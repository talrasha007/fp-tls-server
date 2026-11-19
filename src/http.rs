use crate::Context;
use anyhow::{ensure, Context as _, Result};
use serde_json::{json, Value};
use std::{io::Write, sync::Arc, time::Duration};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    time::timeout,
};

mod frame;
mod h2_server;
mod observe;
#[cfg(test)]
mod tests;

struct RequestHead {
    method: String,
    path: String,
    version: &'static str,
    user_agent: Option<String>,
    details: Value,
}

const MAX_HEAD: usize = 64 * 1024;
const DEADLINE: Duration = Duration::from_secs(15);

async fn read_head(io: &mut (impl AsyncRead + Unpin)) -> Result<RequestHead> {
    let mut bytes = Vec::new();
    let mut chunk = [0u8; 2048];
    let end = loop {
        let start = bytes.len().saturating_sub(3);
        let room = chunk.len().min(MAX_HEAD - bytes.len());
        ensure!(room > 0, "HTTP/1 request head too large");
        let n = io.read(&mut chunk[..room]).await?;
        ensure!(n != 0, "incomplete HTTP/1 request head");
        bytes.extend_from_slice(&chunk[..n]);
        if let Some(i) = bytes[start..].windows(4).position(|s| s == b"\r\n\r\n") {
            break start + i + 4;
        }
    };
    let mut headers = [httparse::EMPTY_HEADER; 256];
    let mut parsed = httparse::Request::new(&mut headers);
    ensure!(
        parsed.parse(&bytes[..end])?.is_complete(),
        "incomplete HTTP/1 request"
    );
    let raw = String::from_utf8_lossy(&bytes[..end - 4]);
    let lines: Vec<_> = raw.split("\r\n").skip(1).collect();
    // TrackMe extracts this optional field from raw lines using a literal ": ".
    let user_agent = lines
        .iter()
        .rev()
        .filter(|line| {
            line.as_bytes()
                .get(..10)
                .is_some_and(|prefix| prefix.eq_ignore_ascii_case(b"user-agent"))
        })
        .filter_map(|line| line.split_once(": ").map(|(_, value)| value))
        .find(|value| !value.is_empty())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned);
    Ok(RequestHead {
        method: parsed.method.context("missing method")?.to_owned(),
        path: parsed.path.context("missing path")?.to_owned(),
        version: if parsed.version == Some(1) {
            "HTTP/1.1"
        } else {
            "HTTP/1.0"
        },
        user_agent,
        details: json!({"headers": if lines.is_empty() { Value::Null } else { json!(lines) }}),
    })
}

async fn route(context: &Context, head: RequestHead) -> Result<(http::StatusCode, String)> {
    use http::StatusCode;
    if head.path.split('?').next() != Some("/api/all") {
        return Ok((
            StatusCode::NOT_FOUND,
            json!({"error":"not found"}).to_string(),
        ));
    }
    let (status, value) = if head.method != "GET" {
        (
            StatusCode::METHOD_NOT_ALLOWED,
            json!({"error":"method not allowed"}),
        )
    } else {
        let value = context
            .response(
                head.version,
                &head.method,
                head.user_agent.as_deref(),
                head.details,
            )
            .await;
        (StatusCode::OK, value)
    };
    // Use the same serialization for the response and its single stdout record.
    // A slow Docker log pipe must not block the async I/O worker.
    let body = tokio::task::spawn_blocking(move || {
        let body = value.to_string();
        if let Err(error) = writeln!(std::io::stdout().lock(), "{body}") {
            eprintln!("Could not log /api/all response: {error}");
        }
        body
    })
    .await?;
    Ok((status, body))
}

pub async fn serve<S>(mut io: S, is_h2: bool, context: Arc<Context>) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    if is_h2 {
        return h2_server::serve(io, context).await;
    }
    let (status, body) = match timeout(DEADLINE, read_head(&mut io)).await? {
        Ok(head) => route(&context, head).await?,
        Err(_) => (
            http::StatusCode::BAD_REQUEST,
            json!({"error":"bad request"}).to_string(),
        ),
    };
    let allow = if status == http::StatusCode::METHOD_NOT_ALLOWED {
        "Allow: GET\r\n"
    } else {
        ""
    };
    let headers = format!("HTTP/1.1 {} {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n{allow}Connection: close\r\n\r\n",
        status.as_u16(), status.canonical_reason().unwrap_or(""), body.len());
    timeout(DEADLINE, async {
        io.write_all(headers.as_bytes()).await?;
        io.write_all(body.as_bytes()).await?;
        io.shutdown().await
    })
    .await??;
    Ok(())
}
