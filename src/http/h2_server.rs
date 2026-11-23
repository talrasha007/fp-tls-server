use super::{
    observe::{Observer, MAX_STREAMS},
    route, RequestHead, DEADLINE, MAX_HEAD,
};
use crate::Context;
use anyhow::{Context as _, Result};
use bytes::Bytes;
use h2::{server::SendResponse, RecvStream};
use http::{Request, Response, StatusCode};
use std::{
    future::poll_fn,
    io,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{ready, Context as TaskContext, Poll},
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    task::JoinSet,
    time::timeout,
};

struct Observed<R> {
    reader: R,
    observer: Arc<Mutex<Observer>>,
}

impl<R: AsyncRead + Unpin> AsyncRead for Observed<R> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let previous = buf.filled().len();
        ready!(Pin::new(&mut self.reader).poll_read(cx, buf))?;
        self.observer
            .lock()
            .unwrap()
            .feed(&buf.filled()[previous..])
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        Poll::Ready(Ok(()))
    }
}

pub(super) async fn serve<S>(io: S, context: Arc<Context>) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let observer = Arc::new(Mutex::new(Observer::default()));
    let (reader, writer) = tokio::io::split(io);
    let io = tokio::io::join(
        Observed {
            reader,
            observer: observer.clone(),
        },
        writer,
    );
    let mut builder = h2::server::Builder::new();
    builder
        .max_concurrent_streams(MAX_STREAMS as u32)
        .max_header_list_size(MAX_HEAD as u32);
    let mut connection = timeout(DEADLINE, builder.handshake(io)).await??;
    let mut tasks = JoinSet::new();
    loop {
        tokio::select! {
            request = timeout(DEADLINE, connection.accept()) => {
                let Some(pair) = request? else { return Ok(()); };
                let (request, response) = pair?;
                let stream = response.stream_id().as_u32();
                let observer = observer.clone();
                let context = context.clone();
                tasks.spawn(async move {
                    // Dropping the handles resets an unfinished stream. Always release its capture.
                    let result = timeout(DEADLINE, respond(request, response, &observer, &context)).await;
                    observer.lock().unwrap().discard(stream);
                    result
                });
            }
            Some(result) = tasks.join_next(), if !tasks.is_empty() => {
                // A client can cancel one stream while other responses are in flight.
                let _stream_outcome = result?;
            }
        }
    }
}

async fn respond(
    request: Request<RecvStream>,
    mut sender: SendResponse<Bytes>,
    observer: &Mutex<Observer>,
    context: &Context,
) -> Result<()> {
    let stream = sender.stream_id().as_u32();
    let (parts, mut body) = request.into_parts();
    while let Some(chunk) = body.data().await {
        let count = chunk?.len();
        body.flow_control().release_capacity(count)?;
    }
    body.trailers().await?;
    let details = observer.lock().unwrap().take(stream)?;
    let head = RequestHead {
        method: parts.method.to_string(),
        path: parts.uri.path().to_owned(),
        version: "h2",
        user_agent: parts
            .headers
            .get_all("user-agent")
            .iter()
            .rev()
            .find(|v| !v.is_empty())
            .map(|v| String::from_utf8_lossy(v.as_bytes()).into_owned()),
        details,
    };
    let reply = route(context, head).await?;
    let mut bytes = reply.body;
    let mut response = Response::builder()
        .status(reply.status)
        .header("content-type", reply.content_type)
        .header("content-length", bytes.len());
    if reply.status == StatusCode::METHOD_NOT_ALLOWED {
        response = response.header("allow", "GET");
    }
    let mut send = sender.send_response(response.body(())?, false)?;
    while !bytes.is_empty() {
        send.reserve_capacity(bytes.len().min(16384));
        let capacity = poll_fn(|cx| send.poll_capacity(cx))
            .await
            .context("closed send stream")??;
        let chunk = bytes.split_to(capacity.min(bytes.len()));
        send.send_data(chunk, bytes.is_empty())?;
    }
    Ok(())
}
