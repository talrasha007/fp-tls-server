use anyhow::{ensure, Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use serde_json::{json, Value};

pub(super) fn word(payload: &[u8]) -> Result<u32> {
    Ok(u32::from_be_bytes(
        payload.get(..4).context("short HTTP/2 frame")?.try_into()?,
    ))
}

pub(super) fn unpad(payload: &[u8], flags: u8) -> Result<&[u8]> {
    if flags & 8 == 0 {
        return Ok(payload);
    }
    let (&padding, rest) = payload.split_first().context("missing pad length")?;
    ensure!(padding as usize <= rest.len(), "invalid HTTP/2 padding");
    Ok(&rest[..rest.len() - padding as usize])
}

fn priority(payload: &[u8]) -> Result<Value> {
    let dependency = word(payload)?;
    Ok(json!({
        "depends_on": dependency & 0x7fff_ffff,
        "exclusive": dependency >> 31,
        "weight": u16::from(*payload.get(4).context("missing priority weight")?) + 1
    }))
}

fn flag_names(kind: u8, flags: u8) -> Vec<&'static str> {
    const END: (u8, &str) = (1, "EndStream (0x1)");
    const ACK: (u8, &str) = (1, "Ack (0x1)");
    const HEADERS: (u8, &str) = (4, "EndHeaders (0x4)");
    const PAD: (u8, &str) = (8, "Padded (0x8)");
    const PRIORITY: (u8, &str) = (32, "Priority (0x20)");
    let names: &[(u8, &str)] = match kind {
        0 => &[END, PAD],
        1 => &[END, HEADERS, PAD, PRIORITY],
        4 | 6 => &[ACK],
        5 => &[HEADERS, PAD],
        9 => &[HEADERS],
        _ => &[],
    };
    names
        .iter()
        .filter(|(bit, _)| flags & bit != 0)
        .map(|(_, name)| *name)
        .collect()
}

fn setting_name(id: u16) -> String {
    match id {
        1 => "HEADER_TABLE_SIZE",
        2 => "ENABLE_PUSH",
        3 => "MAX_CONCURRENT_STREAMS",
        4 => "INITIAL_WINDOW_SIZE",
        5 => "MAX_FRAME_SIZE",
        6 => "MAX_HEADER_LIST_SIZE",
        8 => "ENABLE_CONNECT_PROTOCOL",
        9 => "NO_RFC7540_PRIORITIES",
        _ => return format!("UNKNOWN_SETTING_{id}"),
    }
    .into()
}

pub(super) fn parse(
    kind: u8,
    flags: u8,
    stream: u32,
    payload: &[u8],
    first_settings: &mut Option<String>,
) -> Result<Value> {
    let names = [
        "DATA",
        "HEADERS",
        "PRIORITY",
        "RST_STREAM",
        "SETTINGS",
        "PUSH_PROMISE",
        "PING",
        "GOAWAY",
        "WINDOW_UPDATE",
        "CONTINUATION",
    ];
    let name = names
        .get(kind as usize)
        .map(|s| s.to_string())
        .unwrap_or_else(|| format!("UNKNOWN_FRAME_TYPE_{kind}"));
    let mut parsed = json!({"frame_type":name});
    if stream != 0 {
        parsed["stream_id"] = json!(stream);
    }
    if !payload.is_empty() {
        parsed["length"] = json!(payload.len());
    }
    let names = flag_names(kind, flags);
    if !names.is_empty() {
        parsed["flags"] = json!(names);
    }
    match kind {
        0 => {
            let data = unpad(payload, flags)?;
            if !data.is_empty() {
                parsed["payload"] = json!(STANDARD.encode(data));
            }
        }
        1 if flags & 32 != 0 => parsed["priority"] = priority(unpad(payload, flags)?)?,
        2 => parsed["priority"] = priority(payload)?,
        4 => {
            ensure!(
                payload.len().is_multiple_of(6) && payload.len() <= 6 * 128,
                "invalid or oversized SETTINGS"
            );
            let mut names = Vec::new();
            let mut signature = Vec::new();
            for pair in payload.chunks_exact(6) {
                let id = u16::from_be_bytes([pair[0], pair[1]]);
                let value = word(&pair[2..])?;
                names.push(format!("{} = {value}", setting_name(id)));
                signature.push(format!("{id}:{value}"));
            }
            if first_settings.is_none() {
                *first_settings = Some(signature.join(";"));
            }
            if !names.is_empty() {
                parsed["settings"] = json!(names);
            }
        }
        7 => {
            ensure!(payload.len() >= 8, "short GOAWAY");
            parsed["goaway"] = json!({"LastStreamID":word(payload)? & 0x7fff_ffff,"ErrCode":word(&payload[4..])?,"DebugData":STANDARD.encode(&payload[8..])});
        }
        8 => {
            let increment = word(payload)? & 0x7fff_ffff;
            if increment > 0 {
                parsed["increment"] = json!(increment);
            }
        }
        _ => {}
    }
    Ok(parsed)
}
