//! Passive connection fingerprinting against TrackMe 9d2e865ad663ae114e28c33ddc08a4797b4ecaa8.
#![cfg_attr(not(any(target_os = "linux", test)), allow(dead_code))]
#[path = "tcp/options.rs"]
mod options;
#[path = "tcp/packet.rs"]
mod packet;

use packet::{Ack, Observation, Syn};
use serde_json::{json, Value};
use std::collections::{BTreeSet, HashMap};
use std::net::SocketAddr;
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc, Mutex,
};
use std::time::{Duration, Instant, SystemTime};
use tokio::sync::Notify;

const PENDING_LIMIT: usize = 8192;
const PENDING_TTL: Duration = Duration::from_secs(30);
const CAPTURE_WAIT: Duration = Duration::from_millis(60);

#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
struct Flow {
    peer: SocketAddr,
    local: SocketAddr,
}

impl Flow {
    fn new(peer: SocketAddr, local: SocketAddr) -> Self {
        // pcap provides addresses on one configured interface, without zone IDs.
        let canonical = |addr: SocketAddr| SocketAddr::new(addr.ip().to_canonical(), addr.port());
        Self {
            peer: canonical(peer),
            local: canonical(local),
        }
    }
}

#[derive(Default)]
struct Samples {
    syn: Option<Syn>,
    ack: Option<(SystemTime, Ack)>,
}

impl Samples {
    fn record_ack(&mut self, seen: SystemTime, ack: Ack) -> bool {
        if self.ack.as_ref().is_some_and(|(time, _)| *time > seen) {
            return false;
        }
        self.ack.replace((seen, ack)).is_none()
    }

    fn json(&self, flow: Flow) -> Value {
        let mut result = self
            .ack
            .as_ref()
            .map(|(_, ack)| ack.json(flow))
            .unwrap_or_else(|| json!({"ip": {}, "tcp": {}}));
        if let Some(syn) = &self.syn {
            result["tcp_syn"] = syn.details.clone();
            result["p0f"] = syn.p0f.clone().into();
        }
        result
    }
}

#[derive(Default)]
struct Shared {
    samples: Mutex<Samples>,
    changed: Notify,
}

// A pending generation may precede accept. After close, the bounded cache
// holds only an ISN and a time boundary so late ACKs cannot seed a new socket.
enum Owner {
    Pending(Arc<Shared>),
    Accepted { shared: Arc<Shared>, at: SystemTime },
    Closed,
    // The wire timestamp of a reset separates an aborted handshake from a
    // later handshake even when its SYN is missing.
    Reset,
}

struct Slot {
    owner: Owner,
    isn: Option<u32>,
    since: SystemTime,
    expires: Option<Instant>,
}

#[derive(Default)]
struct Registry {
    slots: HashMap<Flow, Slot>,
    expirations: BTreeSet<(Instant, Flow)>,
}

impl Registry {
    fn purge(&mut self, now: Instant) {
        while self
            .expirations
            .first()
            .is_some_and(|(time, _)| *time <= now)
        {
            self.evict_first();
        }
    }

    fn evict_first(&mut self) {
        if let Some((_, flow)) = self.expirations.pop_first() {
            self.slots.remove(&flow);
        }
    }

    fn replace(&mut self, flow: Flow, slot: Slot) {
        if let Some(previous) = self.slots.remove(&flow) {
            if let Some(time) = previous.expires {
                self.expirations.remove(&(time, flow));
            }
        }
        if let Some(time) = slot.expires {
            if self.expirations.len() >= PENDING_LIMIT {
                self.evict_first();
            }
            self.expirations.insert((time, flow));
        }
        self.slots.insert(flow, slot);
    }

    fn observe(&mut self, flow: Flow, event: Observation, seen: SystemTime, now: Instant) {
        self.purge(now);
        if self.slots.get(&flow).is_some_and(|slot| seen < slot.since) {
            return;
        }
        if let Observation::Reset(ack) = event {
            self.reset(flow, ack, seen, now);
            return;
        }
        let syn_seq = if let Observation::Syn(syn) = &event {
            Some(syn.seq)
        } else {
            None
        };
        let mut start_new = true;
        if let Some(slot) = self.slots.get(&flow) {
            match (&slot.owner, syn_seq) {
                (Owner::Closed, None) => return,
                (_, Some(seq)) if slot.isn == Some(seq) => return,
                (Owner::Reset, _) => {}
                (Owner::Closed | Owner::Pending(_), Some(_)) => {}
                (_, Some(_)) if slot.isn.is_some() => {}
                // A newly captured handshake which happened after accept
                // cannot have established that accepted socket.
                (Owner::Accepted { at, .. }, Some(_)) if seen > *at => {}
                _ => start_new = false,
            }
        }
        if start_new {
            self.replace(
                flow,
                Slot {
                    owner: Owner::Pending(Arc::default()),
                    isn: None,
                    since: seen,
                    expires: Some(now + PENDING_TTL),
                },
            );
        }
        let slot = self.slots.get_mut(&flow).unwrap();
        let shared = match &slot.owner {
            Owner::Pending(shared) | Owner::Accepted { shared, .. } => shared,
            Owner::Closed | Owner::Reset => unreachable!(),
        };
        let mut samples = shared.samples.lock().unwrap();
        let first_sample = match event {
            Observation::Syn(syn) => {
                slot.isn = Some(syn.seq);
                samples.syn = Some(syn);
                true
            }
            Observation::Ack(ack) => samples.record_ack(seen, ack),
            Observation::Reset(_) => unreachable!(),
        };
        drop(samples);
        if first_sample {
            shared.changed.notify_waiters();
        }
    }

    fn reset(&mut self, flow: Flow, ack: Option<Ack>, seen: SystemTime, now: Instant) {
        let mut isn = None;
        if let Some(slot) = self.slots.get(&flow) {
            if matches!(slot.owner, Owner::Closed) {
                return;
            }
            isn = slot.isn;
            // A response still in flight on the old socket keeps its last
            // observed ACK. Future accepts cannot claim that socket's samples.
            if let (Owner::Accepted { shared, .. }, Some(ack)) = (&slot.owner, ack) {
                if shared.samples.lock().unwrap().record_ack(seen, ack) {
                    shared.changed.notify_waiters();
                }
            }
        }
        self.replace(
            flow,
            Slot {
                owner: Owner::Reset,
                isn,
                since: seen,
                expires: Some(now + PENDING_TTL),
            },
        );
    }

    fn accept(&mut self, flow: Flow, at: SystemTime) -> Arc<Shared> {
        self.purge(Instant::now());
        let (shared, since, isn) = match self.slots.get(&flow) {
            Some(Slot {
                owner: Owner::Pending(shared),
                since,
                isn,
                ..
            }) => (shared.clone(), *since, *isn),
            Some(Slot {
                owner: Owner::Accepted { at, .. },
                ..
            }) => (Arc::default(), *at, None),
            Some(slot) => (Arc::default(), slot.since, None),
            None => (Arc::default(), SystemTime::UNIX_EPOCH, None),
        };
        self.replace(
            flow,
            Slot {
                owner: Owner::Accepted {
                    shared: shared.clone(),
                    at,
                },
                since,
                isn,
                expires: None,
            },
        );
        shared
    }

    fn close(&mut self, flow: Flow, shared: &Arc<Shared>) {
        if let Some(Slot {
            owner: Owner::Accepted {
                shared: current, ..
            },
            isn,
            ..
        }) = self.slots.get(&flow)
        {
            if Arc::ptr_eq(current, shared) {
                self.replace(
                    flow,
                    Slot {
                        owner: Owner::Closed,
                        isn: *isn,
                        since: SystemTime::now(),
                        expires: Some(Instant::now() + PENDING_TTL),
                    },
                );
            }
        }
    }
}

#[derive(Clone, Default)]
pub struct Capture {
    registry: Arc<Mutex<Registry>>,
}

impl Capture {
    #[cfg(target_os = "linux")]
    pub fn start(device: &str, port: u16) -> anyhow::Result<Self> {
        use anyhow::{ensure, Context};
        let mut handle = pcap::Capture::from_device(device)?
            .snaplen(1024)
            .promisc(false)
            .timeout(5)
            .immediate_mode(true)
            .open()
            .with_context(|| format!("opening capture device {device}"))?;
        let link = handle.get_datalink().0;
        ensure!(
            packet::supported_link(link),
            "unsupported link type {link} on {device}"
        );
        handle
            .direction(pcap::Direction::In)
            .with_context(|| format!("selecting inbound capture on {device}"))?;
        let tcp = format!("tcp dst port {port}");
        let filter = if link == 1 {
            format!("{tcp} or (vlan and ({tcp} or (vlan and {tcp})))")
        } else {
            tcp
        };
        handle
            .filter(&filter, true)
            .with_context(|| format!("installing '{filter}' on {device}"))?;
        let mut handle = handle
            .setnonblock()
            .context("setting nonblocking pcap mode")?;
        let capture = Self::default();
        let registry = Arc::downgrade(&capture.registry);
        let device = device.to_owned();
        std::thread::Builder::new()
            .name("tcp-capture".into())
            .spawn(move || {
                let worker = std::panic::catch_unwind(std::panic::AssertUnwindSafe(
                    || -> Result<(), pcap::Error> {
                        while let Some(registry) = registry.upgrade() {
                            match handle.next_packet() {
                                Ok(packet) => {
                                    let stamp = packet.header.ts;
                                    let seen = SystemTime::UNIX_EPOCH
                                        + Duration::new(
                                            stamp.tv_sec as u64,
                                            stamp.tv_usec as u32 * 1000,
                                        );
                                    Capture { registry }.packet(link, packet.data, port, seen);
                                }
                                Err(pcap::Error::TimeoutExpired) => {
                                    registry.lock().unwrap().purge(Instant::now());
                                    drop(registry);
                                    std::thread::sleep(Duration::from_millis(3));
                                }
                                Err(error) => return Err(error),
                            }
                        }
                        Ok(())
                    },
                ));
                match worker {
                    Ok(Ok(())) => return,
                    Ok(Err(error)) => eprintln!("capture on {device} failed: {error}"),
                    Err(_) => eprintln!("capture worker on {device} panicked"),
                }
                std::process::exit(1);
            })
            .context("starting pcap worker")?;
        Ok(capture)
    }

    #[cfg(not(target_os = "linux"))]
    pub fn start(_: &str, _: u16) -> anyhow::Result<Self> {
        anyhow::bail!("live packet capture requires Linux")
    }

    fn packet(&self, link: i32, frame: &[u8], port: u16, seen: SystemTime) {
        if let Some((flow, event)) = packet::decode(link, frame, port) {
            self.registry
                .lock()
                .unwrap()
                .observe(flow, event, seen, Instant::now());
        }
    }

    pub fn connection(&self, peer: SocketAddr, local: SocketAddr) -> Connection {
        let flow = Flow::new(peer, local);
        let shared = self
            .registry
            .lock()
            .unwrap()
            .accept(flow, SystemTime::now());
        Connection {
            capture: self.clone(),
            flow,
            shared,
        }
    }
}

pub struct Connection {
    capture: Capture,
    flow: Flow,
    shared: Arc<Shared>,
}

fn count_missing(counter: &AtomicU64, label: &str) {
    let total = counter.fetch_add(1, Ordering::Relaxed) + 1;
    if total.is_power_of_two() {
        eprintln!("capture snapshots missing {label}: {total}");
    }
}

impl Connection {
    pub async fn snapshot(&self) -> Value {
        static MISSING_SYN: AtomicU64 = AtomicU64::new(0);
        static MISSING_ACK: AtomicU64 = AtomicU64::new(0);
        let deadline = tokio::time::Instant::now() + CAPTURE_WAIT;
        loop {
            let changed = self.shared.changed.notified();
            {
                let samples = self.shared.samples.lock().unwrap();
                if samples.syn.is_some() && samples.ack.is_some() {
                    return samples.json(self.flow);
                }
            }
            if tokio::time::timeout_at(deadline, changed).await.is_err() {
                let samples = self.shared.samples.lock().unwrap();
                if samples.syn.is_none() {
                    count_missing(&MISSING_SYN, "SYN");
                }
                if samples.ack.is_none() {
                    count_missing(&MISSING_ACK, "ACK");
                }
                return samples.json(self.flow);
            }
        }
    }
}

impl Drop for Connection {
    fn drop(&mut self) {
        self.capture
            .registry
            .lock()
            .unwrap()
            .close(self.flow, &self.shared);
    }
}

#[cfg(test)]
#[path = "tcp/tests.rs"]
mod tests;
