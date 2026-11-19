use super::{frame, MAX_HEAD};
use anyhow::{ensure, Context, Result};
use bytes::{Buf, BytesMut};
use loona_hpack::Decoder;
use serde_json::{json, Value};
use std::collections::{HashMap, VecDeque};

pub(super) const PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
pub(super) const MAX_STREAMS: usize = 32;

#[derive(Default)]
struct History {
    frames: Vec<(u64, Value)>,
    size: usize,
    end: Option<u64>,
}

impl History {
    fn record(&mut self, seq: u64, value: Value, cost: usize) -> Result<()> {
        self.size += cost;
        ensure!(
            self.frames.len() < 128 && self.size <= MAX_HEAD * 2,
            "HTTP/2 capture limit reached"
        );
        self.frames.push((seq, value));
        Ok(())
    }
}

// Keep the initial SETTINGS, connection WINDOW_UPDATE and first 32 PRIORITY frames
// for fingerprinting. Other connection controls use a rolling window of up to
// 94 frames / 128 KiB of wire payload, so a busy connection can keep serving.
#[derive(Default)]
struct CommonHistory {
    initial: Vec<(u64, Value)>,
    recent: VecDeque<(u64, Value, usize)>,
    recent_size: usize,
}

impl CommonHistory {
    fn record(&mut self, kind: u8, seq: u64, value: Value, wire_size: usize) {
        let pin = match kind {
            4 | 8 => !self
                .initial
                .iter()
                .any(|(_, f)| f["frame_type"] == value["frame_type"]),
            2 => {
                self.initial
                    .iter()
                    .filter(|(_, f)| f["frame_type"] == "PRIORITY")
                    .count()
                    < 32
            }
            _ => false,
        };
        if pin {
            self.initial.push((seq, value));
            return;
        }
        self.recent.push_back((seq, value, wire_size));
        self.recent_size += wire_size;
        while self.recent.len() > 94 || self.recent_size > MAX_HEAD * 2 {
            let (_, _, cost) = self.recent.pop_front().expect("window exceeds limit");
            self.recent_size -= cost;
        }
    }

    fn append_through(&self, end: u64, frames: &mut Vec<(u64, Value)>) {
        frames.extend(
            self.initial
                .iter()
                .take_while(|(seq, _)| *seq <= end)
                .cloned(),
        );
        frames.extend(
            self.recent
                .iter()
                .take_while(|(seq, _, _)| *seq <= end)
                .map(|(seq, value, _)| (*seq, value.clone())),
        );
    }
}

struct Block {
    stream: u32,
    header_index: usize,
    end_stream: bool,
    bytes: Vec<u8>,
}

pub(super) struct Observer {
    buf: BytesMut,
    preface: bool,
    seq: u64,
    settings: Option<String>,
    common: CommonHistory,
    streams: HashMap<u32, History>,
    decoder: Decoder<'static>,
    block: Option<Block>,
}

impl Default for Observer {
    fn default() -> Self {
        let mut decoder = Decoder::new();
        decoder.set_max_allowed_table_size(4096);
        Self {
            buf: BytesMut::new(),
            preface: false,
            seq: 0,
            settings: None,
            common: CommonHistory::default(),
            streams: HashMap::new(),
            decoder,
            block: None,
        }
    }
}

impl Observer {
    pub(super) fn feed(&mut self, buf: &[u8]) -> Result<()> {
        self.buf.extend_from_slice(buf);
        if !self.preface {
            if self.buf.len() < PREFACE.len() {
                return Ok(());
            }
            ensure!(
                self.buf.starts_with(PREFACE),
                "invalid HTTP/2 connection preface"
            );
            self.buf.advance(PREFACE.len());
            self.preface = true;
        }
        while self.buf.len() >= 9 {
            let len = u32::from_be_bytes([0, self.buf[0], self.buf[1], self.buf[2]]) as usize;
            ensure!(len <= 16384, "HTTP/2 frame exceeds advertised maximum");
            if self.buf.len() < 9 + len {
                break;
            }
            let frame = self.buf.split_to(9 + len);
            let stream = frame::word(&frame[5..9])? & 0x7fff_ffff;
            self.seq += 1;
            self.observe(frame[3], frame[4], stream, &frame[9..])?;
        }
        Ok(())
    }

    fn observe(&mut self, kind: u8, flags: u8, stream: u32, payload: &[u8]) -> Result<()> {
        if let Some(block) = &self.block {
            ensure!(
                kind == 9 && stream == block.stream,
                "interleaved HTTP/2 header block"
            );
        }
        let parsed = frame::parse(kind, flags, stream, payload, &mut self.settings)?;
        if stream == 0 || kind == 2 {
            // PRIORITY frames may describe idle streams in the initial priority tree.
            self.common.record(kind, self.seq, parsed, payload.len());
            return Ok(());
        }
        if kind == 3 {
            self.discard(stream);
            return Ok(());
        }
        if kind == 1 && !self.streams.contains_key(&stream) {
            ensure!(
                self.streams.len() < MAX_STREAMS,
                "too many captured HTTP/2 streams"
            );
            self.streams.insert(stream, History::default());
        }
        let Some(history) = self.streams.get_mut(&stream) else {
            return Ok(());
        };
        if history.end.is_some() {
            return Ok(());
        }
        let index = history.frames.len();
        history.record(self.seq, parsed, payload.len())?;
        match kind {
            1 => {
                let data = frame::unpad(payload, flags)?;
                let start = if flags & 32 != 0 { 5 } else { 0 };
                self.block = Some(Block {
                    stream,
                    header_index: index,
                    end_stream: flags & 1 != 0,
                    bytes: data.get(start..).context("short HEADERS frame")?.to_vec(),
                });
            }
            9 => {
                let block = self.block.as_mut().context("unexpected CONTINUATION")?;
                ensure!(
                    block.bytes.len() + payload.len() <= MAX_HEAD,
                    "compressed headers too large"
                );
                block.bytes.extend_from_slice(payload);
            }
            0 if flags & 1 != 0 => history.end = Some(self.seq),
            _ => {}
        }
        if matches!(kind, 1 | 9) && flags & 4 != 0 {
            let block = self.block.take().context("missing HEADERS frame")?;
            let mut headers = Vec::new();
            let mut size = 0usize;
            self.decoder.decode_with_cb(&block.bytes, |name, value| {
                size += name.len() + value.len() + 32;
                if size <= MAX_HEAD {
                    headers.push(format!(
                        "{}: {}",
                        String::from_utf8_lossy(&name),
                        String::from_utf8_lossy(&value)
                    ));
                }
            })?;
            history.size += size;
            ensure!(
                size <= MAX_HEAD && history.size <= MAX_HEAD * 2,
                "expanded headers too large"
            );
            if !headers.is_empty() {
                history.frames[block.header_index].1["headers"] = json!(headers);
            }
            if block.end_stream {
                history.end = Some(self.seq);
            }
        }
        Ok(())
    }

    pub(super) fn discard(&mut self, stream: u32) {
        self.streams.remove(&stream);
    }

    pub(super) fn take(&mut self, stream: u32) -> Result<Value> {
        let history = self
            .streams
            .remove(&stream)
            .context("no captured request")?;
        let end = history.end.context("incomplete captured request")?;
        let mut frames = history.frames;
        self.common.append_through(end, &mut frames);
        frames.sort_unstable_by_key(|(seq, _)| *seq);
        let frames: Vec<_> = frames.into_iter().map(|(_, f)| f).collect();
        let fingerprint = fingerprint(self.settings.as_deref().unwrap_or(""), &frames);
        Ok(
            json!({"akamai_fingerprint":fingerprint, "akamai_fingerprint_hash":format!("{:x}",md5::compute(&fingerprint)), "sent_frames":frames}),
        )
    }
}

fn fingerprint(settings: &str, frames: &[Value]) -> String {
    let window = frames
        .iter()
        .find(|f| f["frame_type"] == "WINDOW_UPDATE")
        .map(|f| f["increment"].as_u64().unwrap_or(0).to_string())
        .unwrap_or_else(|| "00".into());
    let priorities: Vec<_> = frames
        .iter()
        .filter(|f| f["frame_type"] == "PRIORITY")
        .map(|f| {
            let p = &f["priority"];
            format!(
                "{}:{}:{}:{}",
                f["stream_id"], p["exclusive"], p["depends_on"], p["weight"]
            )
        })
        .collect();
    let priority = if priorities.is_empty() {
        "0".to_owned()
    } else {
        priorities.join(",")
    };
    let mut order = String::new();
    if let Some(headers) = frames
        .iter()
        .find(|f| f["frame_type"] == "HEADERS")
        .and_then(|f| f["headers"].as_array())
    {
        for (index, header) in headers.iter().enumerate() {
            if let Some(initial) = header
                .as_str()
                .and_then(|s| s.strip_prefix(':'))
                .and_then(|s| s.chars().next())
            {
                order.push(initial);
                if index < 3 {
                    order.push(',');
                }
            }
        }
    }
    format!("{settings}|{window}|{priority}|{order}")
}
