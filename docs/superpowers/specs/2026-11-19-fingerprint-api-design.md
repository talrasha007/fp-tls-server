# Linux Docker 指纹 API 设计草案

域名直接指向 Linux 宿主机。客户端请求 `GET /api/all` 时，Rust 服务返回该连接上观测到的 TLS 握手、HTTP 请求与 TCP/IP 指纹。首版面向 HTTPS 上的 HTTP/1.1 和 HTTP/2；HTTP/3 使用 QUIC，另属 UDP 部署范围。

## 部署方案

推荐一个 Compose 服务使用 `network_mode: host`。Rust 进程监听可配置的 TCP 端口（默认 443），按配置在指定入口网卡运行 libpcap。这样抓包和 HTTPS 监听使用同一网络命名空间，可以直接关联客户端与服务端的地址和端口。另一种方案是把采集器和 HTTPS 服务拆成两个容器，仅采集器持有抓包权限；这需要额外传递连接事件并处理进程间同步。域名直达同一台主机，首版选择单容器以简化部署。

交付 Rust 源码、多阶段 Dockerfile、Compose 文件与中文运行说明。证书链和私钥由宿主机只读挂载。容器删除默认 capabilities 后按需添加 `NET_RAW` 和 `NET_BIND_SERVICE`。启动时先装载证书，打开网卡，安装入站目标端口过滤器，再接受连接。错误配置或抓包线程意外退出时，进程给出具体错误并退出。域名解析、证书签发由部署者管理。

## API 兼容约定

固定比较基线为 TrackMe 提交 `9d2e865ad663ae114e28c33ddc08a4797b4ecaa8` 中的响应类型、算法与测试，并以原站响应检查字段实例。以 JSON 对象比较，保留字段名、类型、条件省略、空值、数组顺序和哈希格式。顶层包含 `donate` 字符串（自托管默认空串）、带端口的 `ip`、`http_version`、`method`、适用时的 `user_agent`，以及 `tls`、对应协议的 `http1` 或 `http2`、`tcpip`。[上游响应类型](https://github.com/pagpeter/TrackMe/blob/9d2e865ad663ae114e28c33ddc08a4797b4ecaa8/pkg/types/structs.go)

- TLS 层在交给 rustls 的字节流上保留首个完整 ClientHello，支持跨 TCP 读取和多个 TLS record 分片。按上游规则格式化套件、扩展、版本、会话 ID 和随机数，生成 JA3、JA4、JA4_r、PeetPrint 及对应哈希。每种算法分别处理 GREASE 和排序。协商结果取自真实握手。
- HTTP/1.1 保留请求头大小写、顺序和重复项。HTTP/2 在解密后观察帧并按连接维护 HPACK 动态表，保留 SETTINGS 顺序、窗口增量、优先级和伪首部顺序，处理 CONTINUATION，生成帧列表与 Akamai 指纹。连接级设置可复用，请求头和响应快照按流区分，避免在不同并发请求之间暴露首部。
- TCP/IP 层从初始入站 SYN 提取 MSS、窗口、选项原始字节、顺序及异常标记，生成 `tcp_syn` 和原始 `p0f` 字符串。与上游一致，用生成响应前已观察到的最近一份带 ACK 的入站非 SYN 报文填充 `tcpip.ip`、`tcpip.tcp` 和 `cap_length`（抓取长度，snaplen 1024）。支持 IPv4 和 IPv6 的字段差异。[上游抓包逻辑](https://github.com/pagpeter/TrackMe/blob/9d2e865ad663ae114e28c33ddc08a4797b4ecaa8/pkg/tcp/tcp.go)

## 连接关联与资源使用

以客户端和服务端地址、端口关联抓包事件与已接受连接，统一 IPv4 映射地址的表示。区分同一握手的 SYN 重传与相同四元组的新连接，每次连接保留独立的 SYN 和记时数据。抓包可能早于 accept，也可能延迟到请求之后；允许短暂的有界等待。超时后按参考 JSON 的空值与省略规则返回已观测字段，记录缺失计数。关闭连接时释放状态，待关联条目有容量和过期时间。限制协议解析缓冲区、连接级帧记录与等待时间，默认仅在内存中保留生成响应需要的数据。

## 验收

1. 用固定的握手样本和 HTTP 字节序列比对字段、指纹原串和哈希，覆盖 TLS 1.2、1.3、GREASE、分片 ClientHello、重复请求头及多流 HTTP/2。
2. 用固定的 IPv4、IPv6 SYN 样本逐项比对上游的 p0f 断言，加入后续 ACK 窗口变化样本验证两个窗口各自的数据来源。覆盖丢失 SYN、重传、相同客户端 IP 的并发连接以及端口重用。[上游 SYN 测试](https://github.com/pagpeter/TrackMe/blob/9d2e865ad663ae114e28c33ddc08a4797b4ecaa8/pkg/tcp/syn_test.go)
3. 在原生 Linux Docker 启动 Compose，使用另一台主机或独立网络命名空间分别发起 HTTP/1.1 和 HTTP/2 请求。用入口抓包核对源端口、窗口、选项顺序及 p0f，并确认两类响应都能由同一份上游结构解析。证书、网卡或权限配置错误时验证可诊断的启动失败。

具体 crate 版本、缓存容量、超时和模块拆分由实现阶段确定。第一版的接口范围为上述 HTTPS 诊断端点。
