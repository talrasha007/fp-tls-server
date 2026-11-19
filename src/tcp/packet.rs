use super::{options::Options, Flow};
use serde_json::{json, Value};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

fn word(bytes: &[u8], offset: usize) -> u16 {
    u16::from_be_bytes([bytes[offset], bytes[offset + 1]])
}

fn dword(bytes: &[u8], offset: usize) -> u32 {
    u32::from_be_bytes(bytes[offset..offset + 4].try_into().unwrap())
}

#[cfg(target_os = "linux")]
pub(super) fn supported_link(link: i32) -> bool {
    matches!(link, 1 | 12 | 101 | 113 | 228 | 229 | 276)
}

fn network_packet(link: i32, frame: &[u8]) -> Option<&[u8]> {
    let (mut offset, mut ethertype) = match link {
        1 if frame.len() >= 14 => (14, word(frame, 12)), // Ethernet (includes Linux lo)
        113 if frame.len() >= 16 => (16, word(frame, 14)), // Linux cooked v1
        276 if frame.len() >= 20 => (20, word(frame, 0)), // Linux cooked v2
        12 | 101 | 228 | 229 => return Some(frame),      // raw IP
        _ => return None,
    };
    while matches!(ethertype, 0x8100 | 0x88a8 | 0x9100) {
        let vlan = frame.get(offset..offset + 4)?;
        ethertype = word(vlan, 2);
        offset += 4;
    }
    matches!(ethertype, 0x0800 | 0x86dd).then(|| &frame[offset..])
}

#[derive(Clone, Copy)]
struct Ip {
    src: IpAddr,
    dst: IpAddr,
    version: u8,
    ttl: u8,
    tos: u8,
    id: u16,
    df: bool,
    reserved: bool,
    flow_label: bool,
    option_len: usize,
    total: usize,
}

impl Ip {
    fn read(raw: &[u8]) -> Option<(Self, &[u8])> {
        let version = *raw.first()? >> 4;
        let (ip, offset) = match version {
            4 if raw.len() >= 20 && raw[9] == 6 => {
                let offset = usize::from(raw[0] & 15) * 4;
                let flags = word(raw, 6);
                if flags & 0x3fff != 0 || offset < 20 {
                    return None;
                }
                (
                    Self {
                        src: Ipv4Addr::from(<[u8; 4]>::try_from(&raw[12..16]).ok()?).into(),
                        dst: Ipv4Addr::from(<[u8; 4]>::try_from(&raw[16..20]).ok()?).into(),
                        version,
                        ttl: raw[8],
                        tos: raw[1],
                        id: word(raw, 4),
                        df: flags & 0x4000 != 0,
                        reserved: flags & 0x8000 != 0,
                        flow_label: false,
                        option_len: offset - 20,
                        total: match word(raw, 2) {
                            0 => raw.len(), // segmentation offload
                            length => usize::from(length),
                        },
                    },
                    offset,
                )
            }
            // Match upstream p0f handling: only direct TCP is fingerprinted.
            6 if raw.len() >= 40 && raw[6] == 6 => (
                Self {
                    src: Ipv6Addr::from(<[u8; 16]>::try_from(&raw[8..24]).ok()?).into(),
                    dst: Ipv6Addr::from(<[u8; 16]>::try_from(&raw[24..40]).ok()?).into(),
                    version,
                    ttl: raw[7],
                    tos: (raw[0] << 4) | (raw[1] >> 4),
                    id: 0,
                    df: false,
                    reserved: false,
                    flow_label: dword(raw, 0) & 0x000f_ffff != 0,
                    option_len: 0,
                    total: 40 + usize::from(word(raw, 4)),
                },
                40,
            ),
            _ => return None,
        };
        Some((ip, raw.get(offset..ip.total.min(raw.len()))?))
    }
}

pub(super) struct Syn {
    pub seq: u32,
    pub details: Value,
    pub p0f: String,
}

impl Syn {
    fn read(ip: Ip, flow: Flow, tcp: &[u8], header: usize) -> Self {
        let flags = tcp[13];
        let ecn = ip.tos & 3 != 0 || flags & 0xc0 != 0 || tcp[12] & 1 != 0;
        let seq = dword(tcp, 4);
        let window = word(tcp, 14);
        let raw = &tcp[20..header];
        let opts = Options::parse(raw);
        let quirks: Vec<&str> = [
            (ip.df, "df"),
            (ip.df && ip.id != 0, "id+"),
            (ip.version == 4 && !ip.df && ip.id == 0, "id-"),
            (ecn, "ecn"),
            (ip.reserved, "0+"),
            (ip.flow_label, "flow"),
            (seq == 0, "seq-"),
            (dword(tcp, 8) != 0, "ack+"),
            (flags & 0x20 == 0 && word(tcp, 18) != 0, "uptr+"),
            (flags & 0x20 != 0, "urgf+"),
            (flags & 8 != 0, "pushf+"),
            (opts.ts_zero, "ts1-"),
            (opts.echo_nonzero, "ts2+"),
            (opts.padding_nonzero, "opt+"),
            (opts.scale.is_some_and(|scale| scale > 14), "exws"),
            (opts.bad, "bad"),
        ]
        .into_iter()
        .filter_map(|(set, name)| set.then_some(name))
        .collect();
        let payload_len = tcp.len() - header;
        let p0f = format!(
            "{}:{}+?:{}:{}:{},{}:{}:{}:{}",
            ip.version,
            ip.ttl,
            ip.option_len,
            opts.mss,
            window,
            opts.scale.unwrap_or(0),
            opts.layout.join(","),
            quirks.join(","),
            if payload_len == 0 { "0" } else { "+" }
        );
        let mut details = json!({
            "ip_version":ip.version, "src_ip":flow.peer.ip().to_string(), "dst_ip":flow.local.ip().to_string(),
            "src_port":flow.peer.port(), "dst_port":flow.local.port(), "ttl":ip.ttl, "ecn":ecn,
            "mss":opts.mss, "window":window, "sack_permitted":opts.sack_ok, "timestamps":opts.timestamps,
            "options":(!opts.names.is_empty()).then_some(&opts.names), "options_raw":hex::encode(raw),
            "option_order":opts.names.join(","), "packet_len":ip.total, "payload_len":payload_len,
        });
        if ip.version == 4 {
            details["df"] = ip.df.into();
            details["ip_id"] = ip.id.into();
        }
        if let Some(scale) = opts.scale {
            details["window_scale"] = scale.into();
        }
        Self { seq, details, p0f }
    }
}

pub(super) struct Ack {
    ip: Ip,
    seq: u32,
    ack: u32,
    window: u16,
    checksum: u16,
    cap_length: usize,
}

impl Ack {
    pub fn json(&self, flow: Flow) -> Value {
        let mut ip = json!({"ip_version":self.ip.version, "src_ip":flow.peer.ip().to_string(),
            "dst_ip":flow.local.ip().to_string()});
        if self.ip.ttl != 0 {
            ip["ttl"] = self.ip.ttl.into();
        }
        if self.ip.version == 4 {
            if self.ip.id != 0 {
                ip["id"] = self.ip.id.into();
            }
            if self.ip.tos != 0 {
                ip["tos"] = self.ip.tos.into();
            }
        }
        let mut tcp = json!({});
        for (name, value) in [
            ("seq", self.seq),
            ("ack", self.ack),
            ("window", self.window.into()),
            ("checksum", self.checksum.into()),
        ] {
            if value != 0 {
                tcp[name] = value.into();
            }
        }
        let mut result = json!({"ip": ip, "tcp":tcp, "cap_length":self.cap_length});
        if flow.peer.port() != 0 {
            result["src_port"] = flow.peer.port().into();
        }
        if flow.local.port() != 0 {
            result["dst_port"] = flow.local.port().into();
        }
        result
    }
}

pub(super) enum Observation {
    Syn(Syn),
    Ack(Ack),
    Reset(Option<Ack>),
}

pub(super) fn decode(link: i32, frame: &[u8], port: u16) -> Option<(Flow, Observation)> {
    let (ip, tcp) = Ip::read(network_packet(link, frame)?)?;
    if tcp.len() < 20 || word(tcp, 2) != port {
        return None;
    }
    let header = usize::from(tcp[12] >> 4) * 4;
    if !(20..=tcp.len()).contains(&header) {
        return None;
    }
    let flow = Flow::new(
        SocketAddr::new(ip.src, word(tcp, 0)),
        SocketAddr::new(ip.dst, port),
    );
    let flags = tcp[13];
    let ack = || Ack {
        ip,
        seq: dword(tcp, 4),
        ack: dword(tcp, 8),
        window: word(tcp, 14),
        checksum: word(tcp, 16),
        cap_length: frame.len(),
    };
    let observation = if flags & 0x17 == 0x02 {
        Observation::Syn(Syn::read(ip, flow, tcp, header))
    } else if flags & 0x06 == 0x04 {
        Observation::Reset((flags & 0x10 != 0).then(ack))
    } else if flags & 0x12 == 0x10 {
        Observation::Ack(ack())
    } else {
        return None;
    };
    Some((flow, observation))
}
