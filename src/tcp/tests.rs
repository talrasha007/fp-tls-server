use super::*;

// IP and TCP headers reconstructed from TrackMe 9d2e865, pkg/tcp/syn_test.go.
const SYN4: &str = concat!(
    "4500003c303940002f060000c000020ac6336414",
    "d43101bb0001e24000000000a002faf000000000",
    "020405b40402080a010203040000000001030308"
);
const SYN6: &str = concat!(
    "6020007b0014063720010db8000000000000000000000010",
    "20010db8000000000000000000000020",
    "d43101bb0001e240000000005002ffff00000000"
);

fn addresses(ipv6: bool) -> (SocketAddr, SocketAddr) {
    if ipv6 {
        (
            "[2001:db8::10]:54321".parse().unwrap(),
            "[2001:db8::20]:443".parse().unwrap(),
        )
    } else {
        (
            "192.0.2.10:54321".parse().unwrap(),
            "198.51.100.20:443".parse().unwrap(),
        )
    }
}

fn ack4(port: u16, sequence: u32, window: u16) -> Vec<u8> {
    let mut packet = hex::decode(concat!(
        "452000280141400030060000c000020ac6336414",
        "d43101bb0001e2410000002a5010006400ff0000"
    ))
    .unwrap();
    packet[20..22].copy_from_slice(&port.to_be_bytes());
    packet[24..28].copy_from_slice(&sequence.to_be_bytes());
    packet[34..36].copy_from_slice(&window.to_be_bytes());
    packet
}

fn raw(capture: &Capture, packet: &[u8]) {
    capture.packet(12, packet, 443, SystemTime::now());
}

#[tokio::test]
async fn v4_reports_original_syn_and_latest_ack_independently() {
    let capture = Capture::default();
    raw(&capture, &hex::decode(SYN4).unwrap());
    raw(&capture, &ack4(54321, 123457, 777));
    let (peer, local) = addresses(false);
    let conn = capture.connection(peer, local);
    let mut ethernet = hex::decode("0000000000000000000000000800").unwrap();
    ethernet.extend(ack4(54321, 123467, 333));
    capture.packet(1, &ethernet, 443, SystemTime::now());
    assert_eq!(
        conn.snapshot().await,
        json!({
            "p0f":"4:47+?:0:1460:64240,8:mss,sok,ts,nop,ws:df,id+:0",
            "tcp_syn":{"ip_version":4,"src_ip":"192.0.2.10","dst_ip":"198.51.100.20",
                "src_port":54321,"dst_port":443,"ttl":47,"ip_id":12345,"df":true,
                "ecn":false,"window":64240,"mss":1460,"window_scale":8,
                "sack_permitted":true,"timestamps":true,
                "options":["mss","sackOK","timestamp","nop","wscale"],
                "options_raw":"020405b40402080a010203040000000001030308",
                "option_order":"mss,sackOK,timestamp,nop,wscale","payload_len":0,"packet_len":60},
            "ip":{"ttl":48,"id":321,"tos":32,"ip_version":4,"src_ip":"192.0.2.10","dst_ip":"198.51.100.20"},
            "tcp":{"seq":123467,"ack":42,"window":333,"checksum":255},
            "src_port":54321,"dst_port":443,"cap_length":54
        })
    );
}

#[tokio::test]
async fn v6_preserves_null_syn_options_and_omits_ipv4_only_and_zero_ack_fields() {
    let capture = Capture::default();
    let mut bytes = hex::decode(SYN6).unwrap();
    raw(&capture, &bytes);
    bytes[53] = 0x10;
    bytes[44..52].fill(0);
    bytes[54..56].fill(0);
    raw(&capture, &bytes);
    let (peer, local) = addresses(true);
    let json = capture.connection(peer, local).snapshot().await;
    assert_eq!(json["p0f"], "6:55+?:0:0:65535,0::ecn,flow:0");
    assert_eq!(
        json["tcp_syn"],
        json!({"ip_version":6,"src_ip":"2001:db8::10","dst_ip":"2001:db8::20",
        "src_port":54321,"dst_port":443,"ttl":55,"ecn":true,"window":65535,"mss":0,
        "sack_permitted":false,"timestamps":false,"options":null,"options_raw":"","option_order":"",
        "payload_len":0,"packet_len":60})
    );
    assert_eq!(
        json["ip"],
        json!({"ip_version":6,"src_ip":"2001:db8::10","dst_ip":"2001:db8::20","ttl":55})
    );
    assert_eq!(json["tcp"], json!({}));
}

#[tokio::test]
async fn malformed_and_unusual_options_keep_observed_layout_and_quirks() {
    let mut syn = hex::decode(SYN4).unwrap();
    syn.truncate(40);
    syn.extend(hex::decode("080a000000000000000103030f000001").unwrap());
    syn[3] = 56;
    syn[32] = 0x90;
    let (peer, local) = addresses(false);
    let capture = Capture::default();
    raw(&capture, &syn);
    assert_eq!(
        capture.connection(peer, local).snapshot().await["p0f"],
        "4:47+?:0:0:64240,15:ts,ws,eol+2:df,id+,ts1-,ts2+,opt+,exws:0"
    );
    syn.truncate(40);
    syn.extend([1, 2, 4, 5]);
    syn[3] = 44;
    syn[32] = 0x60;
    let capture = Capture::default();
    raw(&capture, &syn);
    assert_eq!(
        capture.connection(peer, local).snapshot().await["p0f"],
        "4:47+?:0:0:64240,0:nop,mss:df,id+,bad:0"
    );
}

#[tokio::test]
async fn retransmission_preserves_first_syn_and_reuse_detaches_old_owner() {
    let capture = Capture::default();
    let (peer, local) = addresses(false);
    let mut syn = hex::decode(SYN4).unwrap();
    raw(&capture, &syn);
    let first = capture.connection(peer, local);
    syn[34..36].copy_from_slice(&20_u16.to_be_bytes());
    raw(&capture, &syn); // same initial sequence
    raw(&capture, &ack4(54321, 123457, 40));
    syn[24..28].copy_from_slice(&500000_u32.to_be_bytes());
    raw(&capture, &syn);
    raw(&capture, &ack4(54321, 500001, 80));
    let second = capture.connection(peer, local);
    let old = first.snapshot().await;
    assert_eq!(old["tcp_syn"]["window"], 64240);
    assert_eq!(old["tcp"]["window"], 40);
    drop(first);
    raw(&capture, &ack4(54321, 500002, 81));
    let new = second.snapshot().await;
    assert_eq!(new["tcp_syn"]["window"], 20);
    assert_eq!(new["tcp"]["window"], 81);
    drop(second);
    raw(&capture, &ack4(54321, 500003, 90)); // late packet from closed socket
    assert_eq!(
        capture.connection(peer, local).snapshot().await,
        json!({"ip":{},"tcp":{}})
    );
}

#[tokio::test]
async fn mapped_addresses_and_four_tuple_isolate_missing_syn() {
    let capture = Capture::default();
    let (peer, local) = addresses(false);
    let mut other_peer = peer;
    other_peer.set_port(54322);
    raw(&capture, &hex::decode(SYN4).unwrap());
    raw(&capture, &ack4(54321, 123457, 555));
    raw(&capture, &ack4(54322, 9999, 600));
    let mapped = capture.connection(
        "[::ffff:192.0.2.10]:54321".parse().unwrap(),
        "[::ffff:198.51.100.20]:443".parse().unwrap(),
    );
    assert_eq!(mapped.snapshot().await["tcp"]["window"], 555);
    let other = capture.connection(other_peer, local).snapshot().await;
    assert!(other.get("tcp_syn").is_none());
    assert_eq!(other["tcp"]["window"], 600);
    let different_local = capture.connection(peer, "198.51.100.21:443".parse().unwrap());
    assert_eq!(different_local.snapshot().await, json!({"ip":{},"tcp":{}}));
}

#[tokio::test]
async fn fresh_syn_discards_orphan_ack_from_earlier_connection() {
    let capture = Capture::default();
    let (peer, local) = addresses(false);
    raw(&capture, &ack4(54321, 811, 600));
    raw(&capture, &hex::decode(SYN4).unwrap());
    let result = capture.connection(peer, local).snapshot().await;
    assert_eq!(result["tcp_syn"]["window"], 64240);
    assert_eq!(result["tcp"], json!({}));
}

#[tokio::test]
async fn aborted_pending_handshake_does_not_supply_a_reused_sockets_syn() {
    for flags in [0x04, 0x14] {
        let capture = Capture::default();
        let (peer, local) = addresses(false);
        raw(&capture, &hex::decode(SYN4).unwrap());
        let mut reset = ack4(54321, 123457, 0);
        reset[33] = flags;
        raw(&capture, &reset);
        // The next handshake's SYN is missing, but its ACK is on the wire.
        raw(&capture, &ack4(54321, 800001, 315));
        let report = capture.connection(peer, local).snapshot().await;
        assert!(report.get("tcp_syn").is_none(), "reset flags {flags}");
        assert!(report.get("p0f").is_none());
        assert_eq!(report["tcp"]["seq"], 800001);
        assert_eq!(report["tcp"]["window"], 315);
    }
}

#[tokio::test]
async fn reset_ack_belongs_only_to_the_already_accepted_connection() {
    let capture = Capture::default();
    let (peer, local) = addresses(false);
    raw(&capture, &hex::decode(SYN4).unwrap());
    let old = capture.connection(peer, local);
    let mut reset = ack4(54321, 123458, 12);
    reset[33] = 0x14;
    raw(&capture, &reset);
    raw(&capture, &ack4(54321, 811222, 64));
    assert_eq!(old.snapshot().await["tcp"]["window"], 12);
    let new = capture.connection(peer, local).snapshot().await;
    assert_eq!(new["tcp"]["window"], 64);
    assert!(new.get("tcp_syn").is_none());
}

#[tokio::test]
async fn reordered_ack_does_not_replace_more_recent_wire_sample() {
    let capture = Capture::default();
    let (peer, local) = addresses(false);
    let time = SystemTime::now() - Duration::from_millis(5);
    capture.packet(12, &hex::decode(SYN4).unwrap(), 443, time);
    capture.packet(
        12,
        &ack4(54321, 123467, 808),
        443,
        time + Duration::from_millis(2),
    );
    capture.packet(
        12,
        &ack4(54321, 123457, 144),
        443,
        time + Duration::from_millis(1),
    );
    assert_eq!(
        capture.connection(peer, local).snapshot().await["tcp"]["window"],
        808
    );
}

#[tokio::test]
async fn snapshot_waits_for_packets_already_on_wire_at_accept() {
    let capture = Capture::default();
    let (peer, local) = addresses(false);
    let syn_time = SystemTime::now() - Duration::from_millis(2);
    let ack_time = SystemTime::now() - Duration::from_millis(1);
    let conn = capture.connection(peer, local);
    let report = conn.snapshot();
    let deliver = async {
        tokio::task::yield_now().await;
        capture.packet(12, &hex::decode(SYN4).unwrap(), 443, syn_time);
        capture.packet(12, &ack4(54321, 123457, 133), 443, ack_time);
    };
    let (result, ()) = tokio::join!(report, deliver);
    assert_eq!(result["tcp_syn"]["window"], 64240);
    assert_eq!(result["tcp"]["window"], 133);
}

#[tokio::test]
async fn pending_eviction_and_expiry_keep_active_fingerprints() {
    let capture = Capture::default();
    let (peer, local) = addresses(false);
    raw(&capture, &hex::decode(SYN4).unwrap());
    raw(&capture, &ack4(54321, 123457, 441));
    let active = capture.connection(peer, local);
    for port in 1..=(PENDING_LIMIT + 1) {
        raw(&capture, &ack4(port as u16, 1, 400));
    }
    let mut oldest = peer;
    oldest.set_port(1);
    assert_eq!(
        capture.connection(oldest, local).snapshot().await,
        json!({"ip":{},"tcp":{}})
    );
    capture
        .registry
        .lock()
        .unwrap()
        .purge(Instant::now() + PENDING_TTL);
    let mut newest = peer;
    newest.set_port((PENDING_LIMIT + 1) as u16);
    assert_eq!(
        capture.connection(newest, local).snapshot().await,
        json!({"ip":{},"tcp":{}})
    );
    assert_eq!(active.snapshot().await["tcp"]["window"], 441);
}

#[tokio::test]
async fn truncated_capture_keeps_wire_syn_length_and_ack_caplen() {
    let (peer, local) = addresses(false);
    let capture = Capture::default();
    let mut frame = hex::decode("000000000000000000000000810000010800").unwrap();
    let mut syn = hex::decode(SYN4).unwrap();
    syn[2..4].copy_from_slice(&2000_u16.to_be_bytes());
    frame.extend(syn);
    frame.resize(1024, 0);
    capture.packet(1, &frame, 443, SystemTime::now());
    frame[18 + 13 + 20] = 0x18;
    capture.packet(1, &frame, 443, SystemTime::now());
    let result = capture.connection(peer, local).snapshot().await;
    assert_eq!(result["tcp_syn"]["packet_len"], 2000);
    assert_eq!(result["tcp_syn"]["payload_len"], 946);
    assert_eq!(
        result["p0f"],
        "4:47+?:0:1460:64240,8:mss,sok,ts,nop,ws:df,id+:+"
    );
    assert_eq!(result["cap_length"], 1024);
}

#[tokio::test]
async fn ipv4_zero_total_length_uses_captured_ip_length_like_gopacket() {
    let mut syn = hex::decode(SYN4).unwrap();
    syn[2..4].fill(0);
    let capture = Capture::default();
    raw(&capture, &syn);
    let (peer, local) = addresses(false);
    assert_eq!(
        capture.connection(peer, local).snapshot().await["tcp_syn"]["packet_len"],
        60
    );
}
