mod handshake;
mod http;
mod tcp;
mod tls;

use std::{env, fs::File, io::BufReader, net::SocketAddr, sync::Arc, time::Duration};

use anyhow::{ensure, Context as _, Result};
use rustls::ServerConfig;
use serde_json::{json, Value};
use socket2::{Domain, Protocol, Socket, Type};
use tokio::{
    net::{TcpListener, TcpStream},
    sync::Semaphore,
    time::timeout,
};
use tokio_rustls::TlsAcceptor;

pub struct Context {
    peer: SocketAddr,
    tls: Value,
    packets: tcp::Connection,
}

impl Context {
    async fn response(
        &self,
        version: &str,
        method: &str,
        user_agent: Option<&str>,
        details: Value,
    ) -> Value {
        let mut response = json!({
            "donate": "",
            "ip": self.peer.to_string(),
            "http_version": version,
            "method": method,
            "tls": &self.tls,
            "tcpip": self.packets.snapshot().await
        });
        if let Some(agent) = user_agent.filter(|agent| !agent.is_empty()) {
            response["user_agent"] = json!(agent);
        }
        response[if version == "h2" { "http2" } else { "http1" }] = details;
        response
    }
}

fn tls_acceptor(cert_path: &str, key_path: &str) -> Result<TlsAcceptor> {
    let cert_file =
        File::open(cert_path).with_context(|| format!("open certificate chain {cert_path}"))?;
    let certs = rustls_pemfile::certs(&mut BufReader::new(cert_file))
        .collect::<std::io::Result<Vec<_>>>()?;
    ensure!(!certs.is_empty(), "empty certificate chain in {cert_path}");
    let key_file = File::open(key_path).with_context(|| format!("open private key {key_path}"))?;
    let key = rustls_pemfile::private_key(&mut BufReader::new(key_file))?
        .context("expected a PEM private key")?;
    let mut config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .context("invalid certificate chain or private key")?;
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(TlsAcceptor::from(Arc::new(config)))
}

fn listen(address: SocketAddr) -> Result<TcpListener> {
    let socket = Socket::new(
        Domain::for_address(address),
        Type::STREAM,
        Some(Protocol::TCP),
    )?;
    if address.is_ipv6() && address.ip().is_unspecified() {
        socket.set_only_v6(false)?;
    }
    socket.set_reuse_address(true)?;
    socket.set_nonblocking(true)?;
    socket.bind(&address.into())?;
    socket.listen(1024)?;
    Ok(TcpListener::from_std(socket.into())?)
}

async fn handle(socket: TcpStream, acceptor: TlsAcceptor, capture: &tcp::Capture) -> Result<()> {
    let peer = socket.peer_addr()?;
    let packets = capture.connection(peer, socket.local_addr()?);
    let (hello, stream) = timeout(Duration::from_secs(10), async {
        let (hello, replay) = handshake::read_client_hello(socket).await?;
        let stream = acceptor.accept(replay).await?;
        anyhow::Ok((hello, stream))
    })
    .await
    .context("TLS handshake timed out")??;
    let session = &stream.get_ref().1;
    let version = session
        .protocol_version()
        .context("missing negotiated TLS version")?;
    let is_h2 = session.alpn_protocol() == Some(&b"h2"[..]);
    let tls = tls::describe(&hello, u16::from(version))?;
    let context = Arc::new(Context {
        peer: canonical_addr(peer),
        tls,
        packets,
    });
    http::serve(stream, is_h2, context).await
}

fn canonical_addr(addr: SocketAddr) -> SocketAddr {
    if let SocketAddr::V6(v6) = addr {
        if let Some(v4) = v6.ip().to_ipv4_mapped() {
            return SocketAddr::new(v4.into(), addr.port());
        }
    }
    addr
}

#[tokio::main]
async fn main() -> Result<()> {
    let address: SocketAddr = env::var("LISTEN_ADDR")
        .unwrap_or_else(|_| "[::]:443".into())
        .parse()
        .context("LISTEN_ADDR must contain an IP address and port")?;
    ensure!(
        address.port() != 0,
        "LISTEN_ADDR must use a fixed capture port"
    );
    let device =
        env::var("CAPTURE_DEVICE").context("set CAPTURE_DEVICE to the ingress interface")?;
    let cert_path = env::var("TLS_CERT").unwrap_or_else(|_| "/certs/fullchain.pem".into());
    let key_path = env::var("TLS_KEY").unwrap_or_else(|_| "/certs/privkey.pem".into());
    let acceptor = tls_acceptor(&cert_path, &key_path)?;
    let capture = tcp::Capture::start(&device, address.port())
        .with_context(|| format!("start capture on {device}"))?;
    let listener = listen(address).with_context(|| format!("listen on {address}"))?;
    let slots = Arc::new(Semaphore::new(512));
    eprintln!("Listening on {address}, capturing on {device}");
    loop {
        let slot = slots.clone().acquire_owned().await?;
        let (socket, _) = match listener.accept().await {
            Ok(connection) => connection,
            Err(error) => {
                // Linux may report a pending network error for just this connection.
                // Back off as well when process or system descriptor limits are reached.
                eprintln!("Could not accept connection: {error}");
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
        };
        let acceptor = acceptor.clone();
        let capture = capture.clone();
        tokio::spawn(async move {
            let _slot = slot;
            if let Err(err) = handle(socket, acceptor, &capture).await {
                eprintln!("Connection closed: {err:#}");
            }
        });
    }
}
