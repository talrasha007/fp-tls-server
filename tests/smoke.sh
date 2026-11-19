#!/bin/sh
# Run on a client whose connection reaches the configured capture interface.
set -eu
url=${1:?usage: sh tests/smoke.sh https://your-domain.example/api/all}
tmp=$(mktemp)
trap 'rm -f "$tmp"' EXIT
for protocol in http1.1 http2; do
    curl -fsS --max-time 15 "--$protocol" -A fp-tls-smoke "$url" > "$tmp"
    jq -e --arg protocol "$protocol" '
        .method == "GET" and .user_agent == "fp-tls-smoke" and
        (.tls.ja3_hash | test("^[a-f0-9]{32}$")) and
        (.tls.ja4 | type == "string") and
        (.tls.peetprint_hash | test("^[a-f0-9]{32}$")) and
        (.tcpip.src_port == .tcpip.tcp_syn.src_port) and
        (.tcpip.tcp_syn.window | type == "number") and
        (.tcpip.cap_length > 0) and
        (.tcpip.p0f | test("^[46]:")) and
        (if $protocol == "http2" then
            .http_version == "h2" and (.http2.sent_frames | any(.frame_type == "HEADERS")) and
            (.http2.akamai_fingerprint_hash | test("^[a-f0-9]{32}$"))
         else
            .http_version == "HTTP/1.1" and (.http1.headers | length > 0)
         end)
    ' "$tmp" >/dev/null || { echo "$protocol fingerprint check failed" >&2; exit 1; }
    echo "$protocol OK"
done
