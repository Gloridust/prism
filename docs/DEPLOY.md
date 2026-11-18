# Prism 部署与运维手册

面向负责上线和日常维护的工程师。协议细节见 [PROTOCOL.md](PROTOCOL.md)。

## 1. 拓扑

```
中国办公室 LAN ──► OpenWrt 路由器 (Nikki/Mihomo + prism-client 路由器模式) ──┐
在家办公的 macOS / Windows (prism-client 桌面模式，系统代理或 TUN) ───────────┼──► 新加坡 prism-server ──► 互联网
                                                                              └──► （可选）备用出口
```

## 2. 上线前检查清单

| 项 | 要求 |
|---|---|
| 域名与证书 | 自有域名解析到出口服务器；用 `acme`（推荐）或 `cert_file`/`key_file`。`self_signed` 只用于测试 |
| 回落站点 | `cover_backend` 反代到一个真实网站。内置占位页只用于测试 |
| 时钟 | 两端都开 NTP。握手带时间戳，偏差超过 `window_seconds`（默认 120 秒）的客户端会被当成未认证访客 |
| 握手 | 两端一致。新部署建议 `"handshake": "noise"` |
| 凭据 | 每个办公室 / 每台设备一条，不共用。服务端设 `credentials_file` 才能通过管理 API 持久化增删 |
| 管理 API | 绑 `127.0.0.1`，token 至少 16 字符，经 SSH 隧道访问 |
| 防火墙 | 放行 TCP 443；用 QUIC 时再放行 UDP 443；管理端口不对外 |
| 文件权限 | `server.json` 含服务器私钥，权限 0640、属组为运行用户；`credentials.json` 由程序以 0600 写入 |
| 客户端入站 | `socks_listen` / `http_listen` 没有鉴权。监听非回环地址时务必用防火墙限制到本 LAN |

## 3. 服务端

### 3.1 安装

```bash
# 生成密钥与配置模板
prism-server keygen sg.example.com

useradd --system --no-create-home --shell /usr/sbin/nologin prism
install -d -o root -g prism -m 0750 /etc/prism
install -o root -g prism -m 0640 server.json /etc/prism/server.json
install -m 0755 prism-server /usr/local/bin/prism-server
install -m 0644 scripts/prism-server.service /etc/systemd/system/
systemctl daemon-reload && systemctl enable --now prism-server
```

unit 文件会在启动前执行 `prism-server -check` 校验配置，以最小权限运行（仅 `CAP_NET_BIND_SERVICE`），可写目录只有 `/var/lib/prism`。

### 3.2 生产配置要点

```json
{
  "listen": ":443",
  "acme": { "enabled": true, "domains": ["sg.example.com"], "email": "ops@example.com" },
  "private_key": "…",
  "credentials": [],
  "credentials_file": "/var/lib/prism/credentials.json",
  "ciphers": ["aes-256-gcm", "chacha20-poly1305"],
  "handshake": "noise",
  "cover_backend": "http://127.0.0.1:8080",
  "admin": { "listen": "127.0.0.1:9090", "token": "至少16字符的随机串" }
}
```

- `acme.cache_dir` 留空时，在 systemd 下自动使用 `/var/lib/prism/acme`。
- `credentials_file` 第一次启动时由 `credentials` 列表生成；**此后以该文件为准**，`server.json` 里的列表不再生效。这样通过管理 API 吊销的凭据不会在重启后复活。
- 流量计数与当日配额用量保存在 `stats.json`（与 `credentials_file` 同目录，或用 `stats_file` 指定），每 30 秒落盘一次，重启不丢。
- `max_conns`（默认 4096）限制并发入站连接数；`max_streams`（默认 1024）限制每条载波的并发流数。
- `head_padding` 默认开启，一般不需要改。

### 3.3 三种入口模式

| 模式 | 配置 | 适用 |
|---|---|---|
| 自有域名 + 回落（默认） | `acme` 或证书 + `cover_backend` | 有自己的域名和站点，部署最简单 |
| steal | `"steal": {"dest": "www.example.org:443"}`，客户端 `"steal": true` 且 `sni` 填目标站域名 | 不想暴露自有域名 |
| WebSocket | `"ws_path": "/_prism/ws"`，客户端 `"transport": "ws"` | 需要经过只转发 HTTP 的 CDN |

steal 目标站的选择：启动日志会打印探测结果，例如
`steal target www.example.org:443: TLS 1.3, TLS_AES_128_GCM_SHA256, ALPN "h2", 4321-byte certificate chain (matched)`。
出现 `WARNING`（不是 TLS 1.3）或 `NOTE`（套件不同）时请换一个目标站。目标站应是境外可正常访问、与出口服务器同地区的常见站点。

QUIC（`quic_listen` + 客户端 `"transport": "quic"`）在丢包线路上延迟更稳。该入口是一个真实的 HTTP/3 站点，未认证的请求一律由回落站点应答；两端的 `quic_path`（默认 `/_prism/h3`）需一致。客户端的 QUIC 指纹来自 quic-go 而非 Chrome，对抗性强的线路仍优先用 TCP 入口。

## 4. 凭据生命周期（管理 API）

以下命令在服务器本机执行，或经 `ssh -L 9090:127.0.0.1:9090` 转发后执行。

```bash
T='Authorization: Bearer <token>'
A=http://127.0.0.1:9090

curl -H "$T" $A/api/credentials                                              # 列表（不含 PSK）
curl -H "$T" -d '{"name":"laptop-zhang","max_bytes_per_day":0}' $A/api/credentials/add   # 新增，返回 id 与 psk
curl -H "$T" "$A/api/subscription?id=<id>"                                   # 取回某条凭据的 id/psk/服务器公钥
curl -H "$T" -d '{"id":"<id>"}' $A/api/credentials/rotate                    # 轮换 PSK，旧会话立即断开
curl -H "$T" -d '{"id":"<id>"}' $A/api/credentials/revoke                    # 吊销并踢线
curl -H "$T" -d '{"id":"<id>","max_bytes_per_day":53687091200}' $A/api/quota # 按日配额（字节，0=不限）
curl -H "$T" $A/api/stats                                                    # 每凭据流量、在线会话数、最后活跃时间
```

所有修改先写入 `credentials_file` 再生效。没有配置 `credentials_file` 时，修改类接口返回 409。

也可以直接编辑 `credentials_file`（或未使用该文件时编辑 `server.json`），然后 `systemctl reload prism-server`：新增的凭据立即可用，被删除或更换了 PSK 的凭据对应的在线会话会被断开。reload 只重载凭据与配额，其它配置项需要重启。

设备丢失或员工离职的处理：`revoke` 该设备的凭据即可，不影响其他人。怀疑服务器私钥泄露时，需要重新 `keygen` 并向所有客户端下发新的 `server_public_key`。

## 5. 监控

`GET /metrics`（同样需要 Bearer token）输出 Prometheus 文本格式：

| 指标 | 含义 |
|---|---|
| `prism_sessions` | 当前在线的已认证载波数 |
| `prism_authenticated_total` | 通过握手的载波累计数 |
| `prism_cover_served_total` | 握手失败、被交给回落站点的连接数（扫描与探测量的直接读数） |
| `prism_steal_relayed_total` | steal 模式下被转发到目标站的连接数 |
| `prism_client_bytes_up_total` / `_down_total` | 每凭据累计流量 |
| `prism_client_bytes_today` / `prism_client_quota_bytes` | 当日用量与配额 |
| `prism_client_sessions` / `prism_client_last_seen_seconds` | 每凭据在线会话数与最后活跃时间 |

抓取配置示例：

```yaml
scrape_configs:
  - job_name: prism
    authorization: { credentials: "<token>" }
    static_configs: [{ targets: ["127.0.0.1:9090"] }]
```

建议告警：`prism_sessions == 0` 持续 5 分钟（工作时间）；`prism_cover_served_total` 的增长率突增（被集中探测）；某凭据 `bytes_today` 接近配额。

计数器每 30 秒写入 `stats.json` 并在正常退出时保存，重启后延续；异常掉电最多丢失最后 30 秒。

日志走 journald：`journalctl -u prism-server -f`。每次客户端接入会记录凭据 ID、名称、入口类型和来源地址；被出口策略拦截的私网目标也会记录。

## 6. 客户端

### 6.1 路由器（OpenWrt + Nikki/Mihomo）

1. 按 CPU 架构取对应的 `prism-client-linux-*` 二进制（无 AES 硬件加速的 MIPS / 老 ARM 用 `-chacha` 版本）。
2. `config/client-router.example.json` → `/etc/prism/client.json`，`scripts/openwrt-prism-client.init` → `/etc/init.d/prism-client`。
3. Mihomo 配置参考 `config/nikki-mihomo.example.yaml`。其中 **IPv6 处理** 与 **STUN 规则前置** 两处直接关系到是否泄露办公室真实 IP，不要省略。
4. 路由器没有 RTC 时，确认 NTP 在 prism-client 之前完成同步，否则开机后的头几次握手会因时间偏差失败（之后自动重连）。

### 6.2 桌面（macOS / Windows）

- **系统代理模式**（默认）：自动设置系统代理，控制面板在 `http://127.0.0.1:9797`。`webrtc_guard` 默认开启，为 Chrome / Edge / Brave / Firefox 写入 WebRTC 策略。Safari 和原生应用不受浏览器策略约束。
- **TUN 全局模式**（配置 `tun` 块，需管理员权限）：IPv4 与 IPv6 全部进隧道，覆盖所有应用。**要求不泄露真实 IP 时用这个模式。**
- **Kill-switch**：在 `tun` 块里加 `"kill_switch": true`。启用后只有隧道、Prism 服务器和本地网络可达，客户端崩溃或被强杀时机器断网而不是回到直连。此时发往局域网解析器的 DNS 也会被拒绝，所以需要同时配置 `dns` 块（或把系统 DNS 设为公网解析器，让查询走隧道）。异常退出后恢复上网：重新启动客户端，或以管理员身份执行 `prism-client -killswitch-off`。Linux 需要 nftables，Windows 需要系统防火墙处于启用状态。需要开机即受保护（重启后、隧道建立前也不允许直连）时再加 `"kill_switch_boot": true`，并把客户端设为开机自启；此模式下正常退出也不会解除规则，只能用 `-killswitch-off`。
- `dns` 块开启本地 DNS 代理并把系统 DNS 指向它，防止直连解析泄露访问目标。
- 全公司强制浏览器策略：下发 `config/webrtc-policy.mobileconfig`（macOS MDM）、`config/webrtc-policy.reg`（Windows 组策略 / Intune）、`config/firefox-policies.json`。

异常退出（进程被强杀、断电）后，系统代理、系统 DNS、浏览器策略可能停留在「已连接」状态，表现为上不了网。重新启动 prism-client 再正常退出即可恢复；macOS 也可以在「网络」设置里手动关闭代理并清空 DNS。

### 6.3 多出口

```json
"server": "sg1.example.com:443", "sni": "sg1.example.com", "server_public_key": "…",
"backups": [
  { "server": "sg2.example.com:443", "sni": "sg2.example.com", "server_public_key": "…" }
]
```

各出口需要配置同一组凭据（把同一份 `credentials.json` 同步到每台服务器即可），服务器密钥各自独立。主出口不可达时客户端自动切到备用出口，并每 5 分钟尝试回切，日志里有 `egress switched: A -> B`。

## 7. 升级

- 客户端与服务端的二进制可以分别升级，但**握手类型、steal 标记格式必须两端一致**。本版本修改了 Noise 握手、steal 标记和 QUIC 载波的线格式：使用 `handshake: "noise"`、`steal` 或 `transport: "quic"` 的部署，需要在同一个维护窗口内升级两端。默认握手（`handshake` 留空）且未启用 steal 的部署，线格式不变，可以先升级服务端再逐步升级客户端。
- 升级服务端：替换二进制后 `systemctl restart prism-server`。在线会话会断开，客户端自动重连（退避 0.5–30 秒）。
- 每次升级 Chrome 大版本后，关注 uTLS 是否发布了对应指纹并跟进升级依赖。

## 8. 排障

| 现象 | 排查 |
|---|---|
| 客户端日志 `carrier dial failed: … server authentication failed` | `server_public_key` 与服务器不匹配；或两端 `handshake` 不一致 |
| 客户端连上即断、服务端没有 `connected` 日志 | 时钟偏差；凭据 `id`/`psk` 不匹配；客户端 `cipher` 不在服务端 `ciphers` 里。这三种情况服务端都会按未认证访客处理，不产生错误日志——看 `prism_cover_served_total` 是否在涨 |
| `ws: server returned 200, want 101` | 服务端没配 `ws_path`，或路径不一致，或中间的 CDN 没有开启 WebSocket |
| steal 模式下客户端握手失败 | 两端版本不一致（标记格式不同）；客户端同时开了 `ech` 或 `transport: quic`（启动时会报错） |
| 某个网站打不开，日志有 `blocked egress` | 目标解析到私网 / 保留地址。确需访问出口服务器内网时设 `allow_private: true` |
| 用到一半全部断流 | 该凭据当日配额用尽（`/api/stats` 的 `bytes_today`） |
| TUN 模式启动失败 `tun ipv6 capture failed and this host has global IPv6` | 本机有公网 IPv6 但无法把 IPv6 路由进隧道。程序拒绝在会泄露的状态下运行；检查是否有其它 VPN 占用了 IPv6 路由 |
| 客户端异常退出后整机断网 | 这是 kill-switch 在起作用。重新启动客户端，或执行 `prism-client -killswitch-off` |
| 启用 kill-switch 后域名解析全部失败 | 系统 DNS 指向了局域网解析器。配置 `dns` 块，或改用公网解析器 |
| WebRTC 泄露检测仍显示真实 IP | 浏览器没有重启（策略在启动时读取）；用的是 Safari 或原生应用（改用 TUN 模式）；路由器侧没有按示例处理 IPv6 |

配置自检：`prism-server -c server.json -check`、`prism-client -c client.json -check`。版本：`-version`。
