# fp-tls-server

客户端访问 `GET /api/all` 时，服务返回这条连接的 TLS、HTTP 与 TCP/IP 观测值。支持 TLS 1.2/1.3 上的 HTTP/1.1 和 HTTP/2，以及 IPv4、IPv6。JSON 字段与指纹算法对照 [TrackMe 的固定版本](https://github.com/pagpeter/TrackMe/tree/9d2e865ad663ae114e28c33ddc08a4797b4ecaa8)。

## 在 Linux 上用 Docker Compose 运行

域名的 A 或 AAAA 记录指向运行 Docker Engine 的主机，客户端直接连接该机的 TCP 443。先确认端口可用，再用 `ip -br addr` 找到接收客户端流量的网卡名称。

1. 在仓库根目录创建 `certs/`，将域名的 PEM 证书链保存为 `certs/fullchain.pem`，对应的 PEM 私钥保存为 `certs/privkey.pem`。也可以用 `CERT_DIR` 指向包含这两个文件的现有目录。挂载目录中的符号链接需要能在容器内解析。私钥应仅允许服务读取。
2. 在同一目录创建 `.env`，将示例网卡名改为实际的入口网卡。

   ```dotenv
   CAPTURE_DEVICE=eth0
   LISTEN_ADDR=[::]:443
   CERT_DIR=./certs
   ```

3. 构建并启动服务。

   ```sh
   docker compose up -d --build
   docker compose logs server
   ```

4. 从另一台机器访问你的域名。第二条命令需要支持 HTTP/2 的 curl。

   ```sh
   curl --http1.1 https://your-domain.example/api/all
   curl --http2 https://your-domain.example/api/all
   ```

默认监听地址 `[::]:443` 同时接收 IPv4 和 IPv6。仅启用 IPv4 的主机可设置 `LISTEN_ADDR=0.0.0.0:443`。证书更新后运行 `docker compose restart server` 重新载入文件。

容器使用 host 网络，在指定网卡上以非混杂模式过滤目标端口的入站 TCP 报文。Compose 配置只保留 `NET_RAW` 和 `NET_BIND_SERVICE`，根文件系统及证书目录均以只读方式挂载。服务从实际 socket 获取对端地址。如果以后增加会重新建立 TCP 连接的代理，结果将描述代理到服务的连接。

## 如何读取结果

| 字段 | 数据来源 |
| --- | --- |
| `ip`、`http_version`、`method`、`user_agent` | 对端 IP 和端口、实际请求协议、方法以及可选的 User-Agent |
| `tls` | 客户端原始 ClientHello 与协商版本，包含按客户端顺序排列的套件和扩展、JA3、JA4、JA4_r、PeetPrint 和相应哈希 |
| `http1.headers` | HTTP/1 请求头行，保留顺序和大小写 |
| `http2` | 客户端发出的 HTTP/2 帧、SETTINGS 顺序、解码后的首部、Akamai 指纹与哈希 |
| `tcpip.tcp_syn`、`tcpip.p0f` | 连接初始 SYN 的窗口、MSS、原始选项、选项顺序与 p0f 字符串 |
| `tcpip.ip`、`tcpip.tcp`、`tcpip.cap_length` | 生成响应前采集到的最近一个带 ACK 的入站报文，以及实际抓取的字节数 |

`tcp_syn.window` 和 `tcp.window` 来自不同报文，两者可以不同。源端口、序列号、时间戳及 TLS 随机数也会因连接而变化。抓包遗漏时，响应按上游规则省略缺失的可选字段。如果线上请求始终缺少 `tcp_syn`，检查入口网卡、目标端口与实际流量路径。在本机测试回环地址时，抓包网卡需设置为 `lo`。

HTTP/2 长连接会保留首个 SETTINGS、首个连接级 WINDOW_UPDATE 和前 32 个 PRIORITY 帧。其余连接控制帧最多保留最近 94 个，总载荷上限为 128 KiB。`sent_frames` 中的请求首部和数据按当前流隔离。

## 开发验证

在 Linux 上安装 Rust 工具链、C 编译器、pkg-config 和 libpcap 开发包。Debian/Ubuntu 的开发包名称为 `libpcap-dev`。

```sh
cargo test --locked
cargo build --release --locked
```

在装有 curl（支持 HTTP/2）和 jq 的客户端上，可同时检查两种 HTTP 协议、TLS 哈希以及实际采集到的 SYN 和 p0f。

```sh
sh tests/smoke.sh https://your-domain.example/api/all
```
