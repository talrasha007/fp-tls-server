//! Describe a complete TLS ClientHello body using TrackMe's response format.

mod extensions;
mod names;
#[cfg(test)]
mod tests;

use anyhow::{ensure, Context, Result};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, length: usize) -> Result<&'a [u8]> {
        let bytes = self
            .0
            .get(..length)
            .context("truncated ClientHello field")?;
        self.0 = &self.0[length..];
        Ok(bytes)
    }

    fn u16(&mut self) -> Result<u16> {
        let bytes = self.take(2)?;
        Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
    }

    fn vector8(&mut self) -> Result<&'a [u8]> {
        let length = self.take(1)?[0];
        self.take(usize::from(length))
    }

    fn vector16(&mut self) -> Result<&'a [u8]> {
        let length = self.u16()?;
        self.take(usize::from(length))
    }
}

fn numbers(bytes: &[u8]) -> impl Iterator<Item = u16> + '_ {
    bytes
        .chunks_exact(2)
        .map(|b| u16::from_be_bytes([b[0], b[1]]))
}

fn grease(n: u16) -> bool {
    let [a, b] = n.to_be_bytes();
    a == b && a & 15 == 10
}

fn peet_id(n: u16) -> String {
    if grease(n) {
        "GREASE".into()
    } else {
        n.to_string()
    }
}

fn plus_grease(n: u16, name: fn(u16) -> String) -> String {
    if grease(n) {
        format!("TLS_GREASE (0x{n:04x})")
    } else {
        name(n)
    }
}

fn joined<T: ToString>(values: impl IntoIterator<Item = T>, separator: &str) -> String {
    values
        .into_iter()
        .map(|v| v.to_string())
        .collect::<Vec<_>>()
        .join(separator)
}

fn raw_hex(values: impl IntoIterator<Item = u16>) -> String {
    joined(values.into_iter().map(|n| format!("{n:04x}")), ",")
}

fn hash12(input: &str) -> String {
    hex::encode(&Sha256::digest(input.as_bytes())[..6])
}

#[derive(Default)]
struct Fingerprint {
    extension_ids: Vec<u16>,
    versions: Vec<u16>,
    groups: Vec<u16>,
    points: Vec<u8>,
    signatures: Vec<u16>,
    protocols: Vec<String>,
    compression: Vec<u16>,
    psk_mode: u8,
}

impl Fingerprint {
    fn hashes(&self, ciphers: &[u16], legacy: u16, negotiated: u16) -> Value {
        let mut suites: Vec<_> = ciphers.iter().copied().filter(|&n| !grease(n)).collect();
        let mut extensions: Vec<_> = self
            .extension_ids
            .iter()
            .copied()
            .filter(|&n| !grease(n))
            .collect();
        // In the reference parser, 6969 is also the internal placeholder for a GREASE group.
        let groups = self
            .groups
            .iter()
            .copied()
            .filter(|&n| !grease(n) && n != 6969);
        let ja3 = format!(
            "{legacy},{},{},{},{}",
            joined(&suites, "-"),
            joined(&extensions, "-"),
            joined(groups, "-"),
            joined(&self.points, "-")
        );
        let mut extension_labels: Vec<_> =
            self.extension_ids.iter().copied().map(peet_id).collect();
        extension_labels.sort_unstable();
        let http: Vec<_> = self
            .protocols
            .iter()
            .filter_map(|s| match s.to_ascii_lowercase().as_str() {
                "h2" => Some("2"),
                "http/1.1" => Some("1.1"),
                "http/1.0" => Some("1.0"),
                _ => None,
            })
            .collect();
        let group_labels = self.groups.iter().copied().map(|n| {
            if n == 6969 {
                "GREASE".into()
            } else {
                peet_id(n)
            }
        });
        let peet = [
            joined(self.versions.iter().copied().map(peet_id), "-"),
            http.join("-"),
            joined(group_labels, "-"),
            joined(self.signatures.iter().copied().map(peet_id), "-"),
            self.psk_mode.to_string(),
            joined(&self.compression, "-"),
            joined(ciphers.iter().copied().map(peet_id), "-"),
            extension_labels.join("-"),
        ]
        .join("|");

        // TrackMe uses the negotiated version, decimal counts without padding,
        // and the first HTTP protocol recognized by PeetPrint.
        let version = match negotiated {
            769..=772 => (negotiated - 759).to_string(),
            other => other.to_string(),
        };
        let alpn = match http.first() {
            Some(&"2") => "h2",
            Some(_) => "h1",
            None => "",
        };
        let prefix = format!(
            "t{version}d{}{}{alpn}",
            suites.len().max(1),
            extensions.len().max(1)
        );
        // Splitting an empty JA3 field in Go yields one empty token, parsed as zero.
        if suites.is_empty() {
            suites.push(0);
        }
        suites.sort_unstable();
        let cipher_part = raw_hex(suites);
        extensions.retain(|&id| id != 0 && id != 16);
        extensions.sort_unstable();
        let sig_part = if self.signatures.is_empty() {
            "0000".to_string()
        } else {
            raw_hex(self.signatures.iter().copied().filter(|&id| !grease(id)))
        };
        let ext_part = format!("{}_{sig_part}", raw_hex(extensions));
        json!({
            "ja3_hash": format!("{:x}", md5::compute(&ja3)), "ja3": ja3,
            "ja4": format!("{prefix}_{}_{}", hash12(&cipher_part), hash12(&ext_part)),
            "ja4_r": format!("{prefix}_{cipher_part}_{ext_part}"),
            "peetprint_hash": format!("{:x}", md5::compute(&peet)), "peetprint": peet,
        })
    }
}

/// The body starts at legacy_version, immediately after the handshake header.
/// negotiated_version is the wire code taken from the completed connection.
pub fn describe(body: &[u8], negotiated_version: u16) -> Result<Value> {
    let mut hello = Reader(body);
    let legacy = hello.u16()?;
    let random = hello.take(32)?;
    let session_id = hello.vector8()?;
    let suites = hello.vector16()?;
    ensure!(suites.len() % 2 == 0, "odd cipher suite vector length");
    let ciphers: Vec<_> = numbers(suites).collect();
    hello.vector8()?;
    let mut fields = Fingerprint::default();
    let mut extensions = Vec::new();
    if !hello.0.is_empty() {
        let mut records = Reader(hello.vector16()?);
        ensure!(
            hello.0.is_empty(),
            "trailing bytes after ClientHello extensions"
        );
        while !records.0.is_empty() {
            let id = records.u16()?;
            let payload = records.vector16()?;
            fields.extension_ids.push(id);
            extensions.push(fields.extension(id, payload));
        }
    }
    let mut result = fields.hashes(&ciphers, legacy, negotiated_version);
    result["tls_version_record"] = json!(legacy.to_string());
    result["tls_version_negotiated"] = json!(negotiated_version.to_string());
    result["client_random"] = json!(hex::encode(random));
    result["session_id"] = json!(hex::encode(session_id));
    result["ciphers"] = json!(ciphers
        .into_iter()
        .map(|n| {
            if grease(n) {
                format!("TLS_GREASE (0x{n:04X})")
            } else {
                names::cipher(n)
            }
        })
        .collect::<Vec<_>>());
    result["extensions"] = if extensions.is_empty() {
        Value::Null
    } else {
        Value::Array(extensions)
    };
    Ok(result)
}
