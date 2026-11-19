# Linux 指纹 API 实现计划

按[设计](../specs/2026-11-19-fingerprint-api-design.md)实现单进程 Rust HTTPS 服务。运行目标为 Linux Docker host 网络，抓取长度 1024 字节。

| 模块 | 接口和交付 | 核验 |
| --- | --- | --- |
| src/tls.rs | 从原始 ClientHello body 和协商版本生成 TLS JSON | 固定样本的 JA3、JA4 和 PeetPrint，扩展顺序、GREASE 和分片 |
| src/tcp.rs | 启动 pcap，按本地与远端地址关联 SYN 和 ACK，按连接生成 TCP/IP JSON | IPv4、IPv6、选项异常、SYN 重传、端口复用、丢包 |
| src/http.rs | 在同一 TLS 连接处理 HTTP/1.1 或 h2，把连接观测与请求信息合为 JSON | 原始首部、帧顺序、HPACK 动态表、并发流隔离 |
| src/main.rs | 校验证书和抓包配置，接受连接并重组初始握手，按 ALPN 分发 | 分片读取、提前断开、错误证书和设备、超时 |
| Dockerfile、compose.yaml、README.md | Linux 容器与中文启动说明 | 构建、请求两种协议、对照抓包并检查缺失字段 |

每个模块先建立对应输入和断言，再实现并执行测试。最终从常规服务入口测试，记录实际运行环境以及尚未验证的范围。
