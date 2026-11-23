use super::{
    observe::{Observer, PREFACE},
    read_head,
};
use serde_json::json;

#[tokio::test]
async fn retains_original_h1_lines_and_ignores_following_request() {
    let mut wire = &b"GET /api/all HTTP/1.1\r\nHost: test\r\nx-Foo:\t A  \r\nX-Foo: B\r\nUser-Agent: example\r\n\r\nGET /another HTTP/1.1\r\nHost: other\r\n\r\n"[..];
    let head = read_head(&mut wire).await.unwrap();
    assert_eq!(head.path, "/api/all");
    assert_eq!(head.method, "GET");
    assert_eq!(head.version, "HTTP/1.1");
    assert_eq!(head.user_agent.as_deref(), Some("example"));
    assert_eq!(
        head.details,
        json!({"headers": ["Host: test", "x-Foo:\t A  ", "X-Foo: B", "User-Agent: example"]})
    );
}

fn frame(kind: u8, flags: u8, stream: u32, payload: &[u8]) -> Vec<u8> {
    let mut buf = (payload.len() as u32).to_be_bytes()[1..].to_vec();
    buf.extend([kind, flags]);
    buf.extend(stream.to_be_bytes());
    buf.extend(payload);
    buf
}

#[tokio::test]
async fn optional_http1_user_agent_follows_trackme_raw_delimiters() {
    for (headers, expected) in [
        ("User-Agent:Example", None),
        ("User-Agent: first\r\nUser-Agent:\tsecond", Some("first")),
        ("User-Agent:Ignored: remainder", Some("remainder")),
        (
            "User-Agent: first\r\nUsEr-AgEnT-Extra:  alias: value  ",
            Some("alias: value"),
        ),
        ("User-Agent: first\r\nUser-Agent: ", Some("first")),
        ("User-Agent: first\r\nUser-Agent:  ", None),
    ] {
        let request = format!("GET /api/all HTTP/1.1\r\n{headers}\r\n\r\n");
        let head = read_head(&mut request.as_bytes()).await.unwrap();
        assert_eq!(head.user_agent.as_deref(), expected, "{headers:?}");
        assert_eq!(
            head.details["headers"],
            json!(headers.split("\r\n").collect::<Vec<_>>())
        );
    }
}

#[test]
fn unknown_frame_name_and_known_flags_match_go_framer() {
    use super::frame::parse;
    let mut settings = None;
    let unknown = parse(0x10, 0xff, 0, &[0; 8], &mut settings).unwrap();
    assert_eq!(
        unknown,
        json!({"frame_type":"UNKNOWN_FRAME_TYPE_16","length":8})
    );
    let headers = parse(1, 0x05, 1, &[0x82], &mut settings).unwrap();
    assert_eq!(
        headers["flags"],
        json!(["EndStream (0x1)", "EndHeaders (0x4)"])
    );
    let ping = parse(6, 1, 0, &[0; 8], &mut settings).unwrap();
    assert_eq!(ping["flags"], json!(["Ack (0x1)"]));
}

#[test]
fn long_lived_connections_keep_initial_fingerprint_and_recent_control_frames() {
    let mut observer = Observer::default();
    observer.feed(PREFACE).unwrap();
    observer.feed(&frame(4, 0, 0, &[0, 2, 0, 0, 0, 0])).unwrap();
    observer
        .feed(&frame(8, 0, 0, &4000u32.to_be_bytes()))
        .unwrap();
    observer.feed(&frame(2, 0, 5, &[0, 0, 0, 0, 100])).unwrap();
    let head = [0x82, 0x01, 1, b'a', 0x87, 0x84];
    observer.feed(&frame(1, 5, 1, &head)).unwrap();
    let first = observer.take(1).unwrap();
    assert_eq!(first["akamai_fingerprint"], "2:0|4000|5:0:0:101|m,a,s,p");
    for seq in 1..=150u32 {
        observer.feed(&frame(6, 0, 0, &[0; 8])).unwrap();
        observer.feed(&frame(8, 0, 0, &seq.to_be_bytes())).unwrap();
    }
    observer.feed(&frame(1, 5, 3, &head)).unwrap();
    let second = observer.take(3).unwrap();
    assert_eq!(second["akamai_fingerprint"], first["akamai_fingerprint"]);
    let frames = second["sent_frames"].as_array().unwrap();
    assert!(frames.len() < 150);
    assert_eq!(frames[0], first["sent_frames"][0]);
    assert_eq!(frames[1]["increment"], 4000);
    assert_eq!(frames[2]["frame_type"], "PRIORITY");
    assert_eq!(frames[frames.len() - 2]["increment"], 150);
    assert_eq!(frames.last().unwrap()["stream_id"], 3);
}

#[test]
fn ordered_frames_and_hash_survive_fragmentation_and_stream_reuse_of_hpack() {
    let mut buf = PREFACE.to_vec();
    buf.extend(frame(
        4,
        0,
        0,
        &[
            0, 1, 0, 1, 0, 0, 0xaa, 0xaa, 0, 0, 0, 0, 0, 4, 0, 0x60, 0, 0,
        ],
    ));
    buf.extend(frame(8, 0, 0, &[0, 15, 0, 1]));
    buf.extend(frame(2, 0, 3, &[128, 0, 0, 0, 200]));
    // Padding, priority and two partial HPACK fields. Index :authority = a in the dynamic table.
    buf.extend(frame(
        1,
        0x29,
        1,
        &[1, 0, 0, 0, 3, 15, 0x82, 0x41, 1, b'a', 0x87, 0x04, 8, 0],
    ));
    let mut rest = b"/api/all".to_vec();
    rest.extend([0x00, 8]);
    rest.extend(b"x-secret");
    rest.extend([3, b'o', b'n', b'e']);
    buf.extend(frame(9, 4, 1, &rest));
    buf.extend(frame(4, 1, 0, &[]));
    buf.extend(frame(1, 4, 3, &[0x82, 0xbe, 0x87, 0x84]));
    buf.extend(frame(0, 9, 3, &[1, b'a', 0]));

    let mut observer = Observer::default();
    for bytes in buf.chunks(3) {
        observer.feed(bytes).unwrap();
    }
    let one = observer.take(1).unwrap();
    let two = observer.take(3).unwrap();
    assert_eq!(
        one["akamai_fingerprint"],
        "1:65536;43690:0;4:6291456|983041|3:1:0:201|m,a,s,p"
    );
    assert_eq!(
        one["akamai_fingerprint_hash"],
        "4a576cae23b1f4d228cdb69e15638450"
    );
    assert_eq!(
        one["sent_frames"],
        json!([
            {"frame_type":"SETTINGS","length":18,"settings":["HEADER_TABLE_SIZE = 65536","UNKNOWN_SETTING_43690 = 0","INITIAL_WINDOW_SIZE = 6291456"]},
            {"frame_type":"WINDOW_UPDATE","length":4,"increment":983041},
            {"frame_type":"PRIORITY","length":5,"stream_id":3,"priority":{"weight":201,"depends_on":0,"exclusive":1}},
            {"frame_type":"HEADERS","length":14,"stream_id":1,"flags":["EndStream (0x1)","Padded (0x8)","Priority (0x20)"],"priority":{"weight":16,"depends_on":3,"exclusive":0},"headers":[":method: GET",":authority: a",":scheme: https",":path: /api/all","x-secret: one"]},
            {"frame_type":"CONTINUATION","length":22,"stream_id":1,"flags":["EndHeaders (0x4)"]}
        ])
    );
    let second = two["sent_frames"].as_array().unwrap();
    assert_eq!(second.len(), 6);
    assert_eq!(
        second[3],
        json!({"frame_type":"SETTINGS","flags":["Ack (0x1)"]})
    );
    assert_eq!(
        second[4]["headers"],
        json!([
            ":method: GET",
            ":authority: a",
            ":scheme: https",
            ":path: /"
        ])
    );
    assert_eq!(
        second[5],
        json!({"frame_type":"DATA","stream_id":3,"length":3,"payload":"YQ==","flags":["EndStream (0x1)","Padded (0x8)"]})
    );
    assert!(!two.to_string().contains("x-secret"));
}

fn context() -> std::sync::Arc<crate::Context> {
    let peer = "127.0.0.1:12345".parse().unwrap();
    let local = "127.0.0.1:443".parse().unwrap();
    std::sync::Arc::new(crate::Context {
        peer,
        tls: json!({}),
        packets: Some(crate::tcp::Capture::default().connection(peer, local)),
        www: None,
    })
}

#[tokio::test]
async fn tls_only_response_has_no_request_or_packet_metadata() {
    let tls = json!({"ja3_hash":"fixture", "tls_version_negotiated":"772"});
    let context = crate::Context {
        peer: "127.0.0.1:12345".parse().unwrap(),
        tls: tls.clone(),
        packets: None,
        www: None,
    };
    for version in ["HTTP/1.1", "h2"] {
        let response = context
            .response(version, "GET", Some("example"), json!({}))
            .await;
        assert_eq!(response, json!({"tls": tls}));
    }
}

#[tokio::test]
async fn homepage_serves_rendered_readme_over_http1() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let (mut client, server) = tokio::io::duplex(4096);
    let handle = tokio::spawn(super::serve(server, false, context()));
    client
        .write_all(b"GET /?from=test HTTP/1.1\r\nHost: test\r\n\r\n")
        .await
        .unwrap();
    let mut response = String::new();
    client.read_to_string(&mut response).await.unwrap();
    let (headers, body) = response.split_once("\r\n\r\n").unwrap();
    assert!(headers.starts_with("HTTP/1.1 200 OK"));
    assert!(headers.contains("Content-Type: text/html; charset=utf-8"));
    assert!(body.contains("<h1>fp-tls-server</h1>"));
    assert!(body.contains("<table>"));
    assert!(body.contains("<pre><code"));
    handle.await.unwrap().unwrap();
}

#[tokio::test]
async fn configured_www_serves_binary_assets() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("图.png"), [0, 255, 17]).unwrap();
    let mut ctx = context();
    std::sync::Arc::get_mut(&mut ctx).unwrap().www = Some(crate::www::open(dir.path()).unwrap());
    let (mut client, server) = tokio::io::duplex(4096);
    let handle = tokio::spawn(super::serve(server, false, ctx));
    client
        .write_all(b"GET /%E5%9B%BE.png?v=1 HTTP/1.1\r\nHost: test\r\n\r\n")
        .await
        .unwrap();
    let mut response = Vec::new();
    client.read_to_end(&mut response).await.unwrap();
    let end = response.windows(4).position(|s| s == b"\r\n\r\n").unwrap();
    let headers = std::str::from_utf8(&response[..end]).unwrap();
    assert!(headers.starts_with("HTTP/1.1 200 OK"));
    assert!(headers.contains("Content-Type: image/png"));
    assert_eq!(response[end + 4..], [0, 255, 17]);
    handle.await.unwrap().unwrap();
}

#[tokio::test]
async fn rejects_other_routes_over_http1() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let (mut client, server) = tokio::io::duplex(4096);
    let handle = tokio::spawn(super::serve(server, false, context()));
    client
        .write_all(b"GET /else HTTP/1.1\r\nHost: test\r\n\r\n")
        .await
        .unwrap();
    let mut response = String::new();
    client.read_to_string(&mut response).await.unwrap();
    assert!(response.starts_with("HTTP/1.1 404 Not Found\r\n"));
    handle.await.unwrap().unwrap();
}

#[tokio::test]
async fn concurrent_h2_requests_finish_independently_with_only_their_own_headers() {
    use bytes::Bytes;
    use http::Request;
    use tokio::time::{timeout, Duration};
    async fn body(resp: h2::client::ResponseFuture) -> serde_json::Value {
        let resp = resp.await.unwrap();
        assert_eq!(resp.status(), 200);
        let mut stream = resp.into_body();
        let mut data = Vec::new();
        while let Some(chunk) = stream.data().await {
            let chunk = chunk.unwrap();
            data.extend_from_slice(&chunk);
            stream.flow_control().release_capacity(chunk.len()).unwrap();
        }
        serde_json::from_slice(&data).unwrap()
    }
    let (client, server) = tokio::io::duplex(16 * 1024);
    let server = tokio::spawn(super::serve(server, true, context()));
    let (mut send, connection) = h2::client::handshake(client).await.unwrap();
    let driver = tokio::spawn(connection);
    let req = |agent| {
        Request::get("https://test/api/all")
            .header("user-agent", agent)
            .body(())
            .unwrap()
    };
    let (first, mut pending) = send.send_request(req("first.example"), false).unwrap();
    let (second, _) = send.send_request(req("second.example"), true).unwrap();
    let second = timeout(Duration::from_secs(4), body(second)).await.unwrap();
    assert_eq!(second["user_agent"], "second.example");
    assert!(!second.to_string().contains("first.example"));
    pending.send_data(Bytes::from_static(b"x"), true).unwrap();
    let first = timeout(Duration::from_secs(4), body(first)).await.unwrap();
    assert_eq!(first["user_agent"], "first.example");
    assert!(!first.to_string().contains("second.example"));
    assert_eq!(
        first["http2"]["sent_frames"]
            .as_array()
            .unwrap()
            .last()
            .unwrap()["payload"],
        "eA=="
    );
    drop((pending, send));
    timeout(Duration::from_secs(4), driver)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    timeout(Duration::from_secs(4), server)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
}
