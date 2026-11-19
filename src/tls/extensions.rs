use super::{grease, names, numbers, plus_grease, Fingerprint, Reader};
use serde_json::{json, Value};

// Go's nil slices marshal as null. Keep the list local to each extension:
// repeated extensions are displayed independently, but all contribute to a hash.
fn list<T: Into<Value>>(items: impl IntoIterator<Item = T>) -> Value {
    let values: Vec<_> = items.into_iter().map(Into::into).collect();
    if values.is_empty() {
        Value::Null
    } else {
        Value::Array(values)
    }
}

fn vector_words(data: &[u8], short_length: bool) -> Vec<u16> {
    let (length, rest) = if short_length {
        let Some((&n, rest)) = data.split_first() else {
            return Vec::new();
        };
        (usize::from(n), rest)
    } else {
        let [hi, lo, rest @ ..] = data else {
            return Vec::new();
        };
        (usize::from(u16::from_be_bytes([*hi, *lo])), rest)
    };
    numbers(&rest[..length.min(rest.len())]).collect()
}

fn protocols(data: &[u8], alps: bool) -> Vec<String> {
    let [hi, lo, bytes @ ..] = data else {
        return vec![];
    };
    let n = usize::from(u16::from_be_bytes([*hi, *lo]));
    if alps && n > bytes.len() {
        return vec![];
    }
    let mut remaining = Reader(bytes);
    let mut names = Vec::new();
    // The reference's ALPS loop requires at least three remaining bytes,
    // whereas its ALPN loop also handles a final one-byte protocol.
    let minimum = if alps { 3 } else { 2 };
    while bytes.len() - remaining.0.len() + minimum <= n {
        let Ok(name) = remaining.vector8() else {
            break;
        };
        names.push(text(name));
    }
    names
}

// encoding/json substitutes U+FFFD for each invalid UTF-8 byte.
fn text(mut bytes: &[u8]) -> String {
    let mut output = String::new();
    while !bytes.is_empty() {
        match std::str::from_utf8(bytes) {
            Ok(s) => {
                output.push_str(s);
                break;
            }
            Err(e) => {
                let valid = e.valid_up_to();
                output.push_str(
                    std::str::from_utf8(&bytes[..valid]).expect("validated UTF-8 prefix"),
                );
                output.push('\u{fffd}');
                bytes = &bytes[valid + 1..];
            }
        }
    }
    output
}

fn shared_keys(data: &[u8]) -> Value {
    let mut reader = Reader(data);
    let Ok(entries) = reader.vector16() else {
        return Value::Null;
    };
    let mut reader = Reader(entries);
    let mut keys = Vec::new();
    while !reader.0.is_empty() {
        let Ok(group) = reader.u16() else {
            break;
        };
        let Ok(key) = reader.vector16() else {
            break;
        };
        let name = plus_grease(group, names::group);
        keys.push(json!({ (name): hex::encode(key) }));
    }
    list(keys)
}

impl Fingerprint {
    pub(super) fn extension(&mut self, id: u16, data: &[u8]) -> Value {
        let name = match id {
            0x0035 => "signature_algorithms_cert (50)".to_owned(),
            0x4469 => "application_settings_old (17513)".to_owned(),
            0x44cd => "application_settings (17613)".to_owned(),
            _ => plus_grease(id, names::extension),
        };
        let mut obj = json!({ "name": name });
        match id {
            0 => obj["server_name"] = json!(text(data.get(5..).unwrap_or_default())),
            5 | 17 => {
                if let [status, responders, extensions, ..] = data {
                    obj["status_request"] = json!({
                        "certificate_status_type": format!("OSCP ({status})"),
                        "responder_id_list_length": responders,
                        "request_extensions_length": extensions,
                    });
                }
            }
            10 => {
                let values = vector_words(data, false);
                obj["supported_groups"] =
                    list(values.iter().map(|&g| plus_grease(g, names::group)));
                self.groups.extend(values);
            }
            11 => {
                let points = data.get(1..).unwrap_or_default();
                self.points.extend_from_slice(points);
                obj["elliptic_curves_point_formats"] =
                    list(points.iter().map(|n| format!("0x{n:02x}")));
            }
            // TrackMe dispatches 0x0035 as a signature list. The registered
            // signature_algorithms_cert ID 0x0032 follows the raw-data branch.
            13 | 0x0035 => {
                let ids = vector_words(data, false);
                obj["signature_algorithms"] = list(ids.iter().copied().map(names::signature));
                self.signatures.extend(ids);
            }
            16 => {
                let names = protocols(data, false);
                obj["protocols"] = list(names.iter().cloned());
                self.protocols.extend(names);
            }
            18 => {}
            21 => obj["padding_data_length"] = json!(data.len() * 2),
            23 => {
                obj["master_secret_data"] = json!(hex::encode(data.get(2..).unwrap_or_default()));
                obj["extended_master_secret_data"] = json!("");
            }
            27 => {
                let ids = vector_words(data, true);
                obj["algorithms"] = list(ids.iter().map(|n| match n {
                    1 => "zlib (1)".into(),
                    2 => "brotli (2)".into(),
                    3 => "zstd (3)".into(),
                    _ => format!("{n:04x}"),
                }));
                self.compression.extend(ids);
            }
            34 => {
                obj["signature_hash_algorithms"] =
                    list(vector_words(data, false).into_iter().map(names::signature))
            }
            43 => {
                let ids = vector_words(data, true);
                obj["versions"] = list(ids.iter().map(|&v| match v {
                    769..=772 => format!("TLS 1.{}", v - 769),
                    _ if grease(v) => format!("TLS_GREASE (0x{v:04x})"),
                    _ => format!("{v:04x}"),
                }));
                self.versions.extend(ids);
            }
            45 => {
                obj["PSK_Key_Exchange_Mode"] = json!(match data.get(1) {
                    Some(0) => "PSK-only key establishment (psk) (0)",
                    Some(1) => "PSK with (EC)DHE key establishment (psk_dhe_ke) (1)",
                    _ => "",
                });
                if let Some(&mode) = data.get(1) {
                    self.psk_mode = mode;
                }
            }
            51 => obj["shared_keys"] = shared_keys(data),
            0x4469 | 0x44cd => obj["protocols"] = list(protocols(data, true)),
            _ if grease(id) => {}
            _ => obj["data"] = json!(hex::encode(data)),
        }
        obj
    }
}
