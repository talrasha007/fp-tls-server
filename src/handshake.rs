use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
};

use anyhow::{ensure, Result};
use bytes::{Buf, Bytes};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf};

// rustls receives the exact records we inspected, including any bytes following
// the first handshake message in the final record.
pub struct Replay<S> {
    prefix: Bytes,
    inner: S,
}

impl<S: AsyncRead + Unpin> AsyncRead for Replay<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.prefix.is_empty() {
            return Pin::new(&mut self.inner).poll_read(cx, buf);
        }
        let n = buf.remaining().min(self.prefix.len());
        buf.put_slice(&self.prefix[..n]);
        self.prefix.advance(n);
        Poll::Ready(Ok(()))
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Replay<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, data)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

pub async fn read_client_hello<S: AsyncRead + Unpin>(mut inner: S) -> Result<(Vec<u8>, Replay<S>)> {
    const MAX_HELLO: usize = 128 * 1024;
    let mut wire = Vec::new();
    let mut message = Vec::new();
    loop {
        let mut header = [0; 5];
        inner.read_exact(&mut header).await?;
        ensure!(
            header[0] == 22 && header[1] == 3,
            "expected TLS handshake record"
        );
        let len = u16::from_be_bytes([header[3], header[4]]) as usize;
        ensure!(
            (1..=16384).contains(&len),
            "invalid plaintext record length"
        );
        ensure!(
            wire.len() + 5 + len <= 2 * MAX_HELLO,
            "ClientHello exceeds capture limit"
        );
        wire.extend_from_slice(&header);
        let start = wire.len();
        wire.resize(start + len, 0);
        inner.read_exact(&mut wire[start..]).await?;
        message.extend_from_slice(&wire[start..]);
        if message.len() >= 4 {
            ensure!(message[0] == 1, "expected ClientHello");
            let size = u32::from_be_bytes([0, message[1], message[2], message[3]]) as usize;
            ensure!((1..=MAX_HELLO).contains(&size), "invalid ClientHello size");
            if message.len() >= size + 4 {
                let body = message[4..4 + size].to_vec();
                return Ok((
                    body,
                    Replay {
                        prefix: wire.into(),
                        inner,
                    },
                ));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{duplex, AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn collects_fragmented_handshake_and_replays_every_byte() {
        let records: &[u8] = &[
            22, 3, 1, 0, 2, 1, 0, 22, 3, 3, 0, 6, 0, 3, 3, 3, 7, 2, 23, 3, 3,
        ];
        let (mut client, server) = duplex(1);
        let writer = tokio::spawn(async move { client.write_all(records).await.unwrap() });
        let (body, mut stream) = read_client_hello(server).await.unwrap();
        assert_eq!(body, [3, 3, 7]);
        let mut replayed = Vec::new();
        stream.read_to_end(&mut replayed).await.unwrap();
        writer.await.unwrap();
        assert_eq!(replayed, records);
    }

    #[tokio::test]
    async fn rejects_truncated_and_oversized_handshakes() {
        for bytes in [
            &[22, 3, 3, 0, 4, 1, 255, 255, 255][..],
            &[22, 3, 3, 0, 6, 1, 0, 0],
            &[23, 3, 3, 0, 1, 0],
        ] {
            assert!(read_client_hello(bytes).await.is_err());
        }
    }
}
