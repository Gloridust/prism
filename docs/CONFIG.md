# 配置参考

服务端与客户端都使用 JSON 配置文件。完整的带注释样例在 [`config/`](../config/)：

- [`server.example.json`](../config/server.example.json)：出口服务器
- [`client-router.example.json`](../config/client-router.example.json)：路由器模式
- [`client-desktop.example.json`](../config/client-desktop.example.json)：桌面模式

以 `_` 开头的键是注释，程序会忽略。修改后可用 `-check` 校验：

```bash
prism-server -c server.json -check
prism-client -c client.json -check
```

**两端必须一致的项**：`handshake`、`transport` 对应的入口（`ws_path` / `quic_path`）、`steal`；客户端的 `cipher` 必须在服务端 `ciphers` 列表中。

---

## 服务端 `server.json`

### 基础

| 键 | 默认 | 说明 |
|---|---|---|
| `listen` | — | TCP 监听地址，通常 `":443"` |
| `private_key` | — | 服务器 X25519 私钥（base64），由 `keygen` 生成。**只放在服务器上** |
| `credentials` | `[]` | 客户端凭据列表：`{name, id, psk, max_bytes_per_day}` |
| `credentials_file` | 空 | 可写的凭据库。首次启动由 `credentials` 生成，之后以它为准；管理 API 的修改写入这里。不设置则管理 API 只读 |
| `stats_file` | 与 `credentials_file` 同目录的 `stats.json` | 流量与当日配额用量，每 30 秒落盘 |
| `window_seconds` | `120` | 握手时间戳允许的时钟偏差（秒） |

### 证书（三选一）

| 键 | 说明 |
|---|---|
| `acme` | `{enabled, domains, email, cache_dir, directory_url}`。自动签发 Let's Encrypt（TLS-ALPN-01，只用 443）。`cache_dir` 在 systemd 下默认 `/var/lib/prism/acme` |
| `cert_file` / `key_file` | 自备证书的 PEM 路径 |
| `self_signed` | 自签名的域名，**仅测试用** |

### 回落站点

| 键 | 说明 |
|---|---|
| `cover_backend` | 反向代理目标，如 `http://127.0.0.1:8080`。**生产必须配置** |
| `cover_static_dir` | 或者直接提供一个静态目录 |

两者都不设时使用内置占位页，仅适合测试。

### 加密与握手

| 键 | 默认 | 说明 |
|---|---|---|
| `handshake` | `""` | `""` = 默认握手；`"noise"` = Noise_IKpsk1（新部署建议） |
| `ciphers` | `["aes-256-gcm"]` | 接受的算法，可加 `"chacha20-poly1305"`。服务端自动识别每个客户端使用的算法 |

### 入口模式

| 键 | 说明 |
|---|---|
| `steal` | `{"dest": "www.example.org:443", "server_names": [...]}`。不使用自有域名，未认证连接整条转发到目标站。与 `acme`、`quic_listen` 互斥 |
| `ws_path` | 开启 WebSocket 入口，如 `"/_prism/ws"`，用于经过 CDN |
| `quic_listen` | 开启 HTTP/3 入口（UDP），如 `":443"` |
| `quic_path` | HTTP/3 隧道路径，默认 `/_prism/h3` |

### 流量与安全

| 键 | 默认 | 说明 |
|---|---|---|
| `head_padding` | `true` | 随机化每条流前几个帧的长度，隐藏 TLS-in-TLS 特征 |
| `shaping` | `"none"` | 出口方向长度整形：`none` / `pad` |
| `allow_private` | `false` | 是否允许经隧道访问私网、环回、云元数据地址（默认拒绝，防 SSRF） |
| `max_conns` | `4096` | 并发入站连接上限；负数不限 |
| `max_streams` | `1024` | 每条载波的并发流上限；负数不限 |

### 管理 API

| 键 | 说明 |
|---|---|
| `admin` | `{"listen": "127.0.0.1:9090", "token": "至少 16 个字符"}`。凭据增删/轮换、配额、统计、Prometheus `/metrics`。用法见 [DEPLOY.md §4](DEPLOY.md#4-凭据生命周期管理-api) |

---

## 客户端 `client.json`

### 连接

| 键 | 默认 | 说明 |
|---|---|---|
| `server` | — | 出口服务器 `host:port` |
| `sni` | — | TLS 域名（steal 模式下填目标站域名） |
| `server_public_key` | — | 服务器公钥（base64） |
| `id` / `psk` | — | 本设备凭据 |
| `backups` | `[]` | 备用出口 `[{server, sni, server_public_key}]`，主出口不可达时自动切换，每 5 分钟尝试回切 |
| `allow_insecure` | `false` | 跳过证书校验，**仅测试用** |
| `pool_size` | `4` | 载波连接数 |

### 协议

| 键 | 默认 | 说明 |
|---|---|---|
| `handshake` | `""` | 与服务端一致 |
| `cipher` | `aes-256-gcm`（`-chacha` 构建为 `chacha20-poly1305`） | 载波加密算法 |
| `transport` | `""` | `""` = TLS；`"ws"` = WebSocket；`"quic"` = HTTP/3 |
| `ws_path` / `quic_path` | — / `/_prism/h3` | 与服务端一致 |
| `steal` | `false` | 配合服务端 steal 模式。不能与 `ech`、`transport: "quic"` 同用 |
| `ech` | `""` | Encrypted Client Hello：`"auto"` 通过 DoH 获取，或填 base64 配置 |
| `ech_doh` | `https://1.1.1.1/dns-query` | 获取 ECH 配置用的 DoH 服务 |

### 流量特征

| 键 | 默认 | 说明 |
|---|---|---|
| `head_padding` | `true` | 流首填充 |
| `shaping` | `"none"` | `none` / `pad` / `web` / `video` / `download` |
| `iat_max_ms` | `0` | 帧间时序抖动上限（毫秒），建议 20–50；0 关闭 |
| `max_lifetime_sec` | `0` | 载波最长存活时间，到期后平滑轮换；0 不限 |

### 运行模式

| 键 | 默认 | 说明 |
|---|---|---|
| `mode` | `"desktop"` | `desktop` = 系统代理 + 控制面板；`router` = 仅本地 SOCKS5 |
| `socks_listen` | `127.0.0.1:1080` | SOCKS5 入口（无鉴权，监听非回环地址时请用防火墙限制） |
| `http_listen` | `127.0.0.1:1081` | HTTP 代理入口（桌面模式） |
| `panel_listen` | `127.0.0.1:9797` | 控制面板（桌面模式） |
| `auto_connect` | `true` | 桌面模式启动后立即连接并设置系统代理 |

### 防泄露

| 键 | 默认 | 说明 |
|---|---|---|
| `dns` | 关闭 | `{"listen": "127.0.0.1:53", "upstream": "1.1.1.1:53"}`。本地 DNS 代理，查询经隧道发往出口；桌面模式同时把系统 DNS 指向它 |
| `webrtc_guard` | `true` | 连接时为 Chrome / Edge / Brave / Firefox 写入 WebRTC 策略，断开时恢复。Safari、原生应用、Linux 上的 Edge 不受覆盖，请用 TUN 模式 |

### TUN 全局模式 `tun`

需要管理员权限。IPv4 与 IPv6 全部进入隧道，覆盖所有应用；本机有公网 IPv6 却无法接管时拒绝启动。

| 键 | 默认 | 说明 |
|---|---|---|
| `device_name` | `prism0` | 设备名 |
| `address` | — | TUN 地址，如 `10.0.85.1/24` |
| `gateway` | — | 对端地址，如 `10.0.85.2` |
| `orig_gateway` | — | 原默认网关（如 `192.168.1.1`），用于保留到出口服务器的直连路由。`set_routes` 为 true 时必填 |
| `set_routes` | `true` | 自动配置路由 |
| `kill_switch` | `false` | 用系统防火墙拒绝一切不经隧道的流量，客户端异常退出时断网而不是直连。需同时配置 `dns` |
| `kill_switch_boot` | `false` | 开机即装回 kill-switch 规则（始终在线）。只能用 `prism-client -killswitch-off` 解除 |

---

## 命令行

| 命令 | 说明 |
|---|---|
| `prism-server keygen <域名>` | 生成服务器密钥与两端配置模板 |
| `prism-keygen client <名称>` | 生成一条客户端凭据 |
| `prism-server -c <文件>` / `prism-client -c <文件>` | 指定配置文件 |
| `-check` | 只校验配置 |
| `-version` | 打印版本 |
| `prism-client -killswitch-off` | 解除 kill-switch 规则（需管理员权限） |
