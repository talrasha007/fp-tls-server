use crate::Context;
use anyhow::{ensure, Context as _, Result};
use bytes::Bytes;
use http::StatusCode;
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

struct Reply {
    status: StatusCode,
    content_type: &'static str,
    body: Body,
    allow: Option<&'static str>,
}

enum Body {
    Memory(Bytes),
    File {
        file: tokio::fs::File,
        remaining: u64,
    },
}

impl Body {
    fn len(&self) -> u64 {
        match self {
            Self::Memory(data) => data.len() as u64,
            Self::File { remaining, .. } => *remaining,
        }
    }

    async fn chunk(&mut self, max: usize) -> std::io::Result<Bytes> {
        let size = self.len().min(max as u64) as usize;
        match self {
            Self::Memory(data) => Ok(data.split_to(size)),
            Self::File { file, remaining } => {
                let mut data = vec![0; size];
                file.read_exact(&mut data).await?;
                *remaining -= size as u64;
                Ok(Bytes::from(data))
            }
        }
    }
}

impl Reply {
    fn json(status: StatusCode, body: String) -> Self {
        Self {
            status,
            content_type: "application/json",
            body: Body::Memory(body.into()),
            allow: (status == StatusCode::METHOD_NOT_ALLOWED).then_some("GET"),
        }
    }
}

async fn static_page(context: &Context, path: &str, method: &str) -> Reply {
    let not_found = || {
        Reply::json(
            StatusCode::NOT_FOUND,
            json!({"error":"not found"}).to_string(),
        )
    };
    if context.www.is_none() && path != "/" {
        return not_found();
    }
    if method != "GET" && !(method == "HEAD" && context.www.is_some()) {
        return Reply {
            allow: Some(if context.www.is_some() {
                "GET, HEAD"
            } else {
                "GET"
            }),
            ..Reply::json(
                StatusCode::METHOD_NOT_ALLOWED,
                json!({"error":"method not allowed"}).to_string(),
            )
        };
    }
    let Some(root) = &context.www else {
        return Reply {
            status: StatusCode::OK,
            content_type: "text/html; charset=utf-8",
            body: Body::Memory(Bytes::from_static(include_bytes!(concat!(
                env!("OUT_DIR"),
                "/index.html"
            )))),
            allow: None,
        };
    };
    match crate::www::asset(root.clone(), path).await {
        Ok(asset) => Reply {
            status: StatusCode::OK,
            content_type: asset.mime,
            body: Body::File {
                file: asset.file,
                remaining: asset.size,
            },
            allow: None,
        },
        Err(error) => match error.kind() {
            std::io::ErrorKind::NotFound
            | std::io::ErrorKind::NotADirectory
            | std::io::ErrorKind::PermissionDenied => not_found(),
            _ => {
                eprintln!("Could not open static file: {error}");
                Reply::json(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    json!({"error":"could not read file"}).to_string(),
                )
            }
        },
    }
}

async fn route(context: &Context, head: RequestHead) -> Result<Reply> {
    let path = head.path.split('?').next().unwrap_or("");
    if path != "/api/all" {
        return Ok(static_page(context, path, &head.method).await);
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
    Ok(Reply::json(status, body))
}

pub async fn serve<S>(mut io: S, is_h2: bool, context: Arc<Context>) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    if is_h2 {
        return h2_server::serve(io, context).await;
    }
    let head = timeout(DEADLINE, read_head(&mut io)).await?;
    let headers_only = head.as_ref().is_ok_and(|r| r.method == "HEAD");
    let Reply {
        status,
        content_type,
        mut body,
        allow,
    } = match head {
        Ok(head) => route(&context, head).await?,
        Err(_) => Reply::json(
            http::StatusCode::BAD_REQUEST,
            json!({"error":"bad request"}).to_string(),
        ),
    };
    let allow = allow
        .map(|methods| format!("Allow: {methods}\r\n"))
        .unwrap_or_default();
    let headers = format!("HTTP/1.1 {} {}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\n{allow}Connection: close\r\n\r\n",
        status.as_u16(), status.canonical_reason().unwrap_or(""), body.len());
    timeout(DEADLINE, async {
        io.write_all(headers.as_bytes()).await?;
        while !headers_only && body.len() != 0 {
            io.write_all(&body.chunk(64 * 1024).await?).await?;
        }
        io.shutdown().await
    })
    .await??;
    Ok(())
}
