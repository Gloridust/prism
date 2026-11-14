# Prism

**一个原创的抗审查隧道协议 + 两端软件**，用于把多地办公室/远程员工的出口统一收敛到新加坡公司。

- 对观察者而言，流量就是**对你自有域名的一次普通 HTTPS 连接**。
- 任何没有有效凭据的访问者（包括主动探测）看到的，是你服务器上**一个真实的网站**。
- 鉴权是 **X25519 + 每客户端 PSK 的双因子互认**，握手首包 80 字节不可区分于随机，带前向保密与抗重放。
- 数据面**不套内层 TLS**（规避 TLS-in-TLS 指纹），自有 AEAD 分帧 + **逐流流控的多路复用** + 整形。
- 载波握手用 **uTLS 模拟 Chrome 的 ClientHello**（规避 Go `crypto/tls` 指纹）；证书支持 **ACME/Let's Encrypt 自动签发**；无 AES-NI 的路由器可切 **ChaCha20-Poly1305**（同线格式，服务端自动识别）。
- 一条命令交叉编译到路由器 / macOS / Windows。生产加固引入了首批第三方依赖（uTLS、x/crypto），这是刻意的取舍，见下方 [依赖与取舍](#依赖与取舍)。

> 设计细节与字节级规范见 [`docs/PROTOCOL.md`](docs/PROTOCOL.md)。
> 与 REALITY/Trojan/VLESS 的区别、安全局限与诚实告警也在那里，**上线前务必读第 9 节**。

---

## 组成

```
pkg/prism/            协议核心（除 ChaCha 外纯标准库，带单元测试）
  kdf.go  aead.go  aead_chacha.go  keys.go  handshake.go  replay.go  session.go  addr.go
cmd/prism-server/     新加坡出口：TLS(ACME/证书/自签) + 鉴权 + 多路复用出口 + 真实网站回落
cmd/prism-client/     跨平台客户端：uTLS 载波 + 路由器旁车 / 桌面(系统代理+控制面板)
config/               配置样例 + Nikki/Mihomo 路由片段
test/                 uTLS 载波 + prism 端到端联调（AES/ChaCha，1MiB + 并发）
scripts/              OpenWrt init / systemd / 桌面启动器
docs/PROTOCOL.md      协议规范
```

---

## 快速开始

### 0. 构建

```bash
make all                     # 本机构建 + 跑测试
make server-linux-amd64      # 新加坡服务器
make client-linux-arm64      # 路由器（按 CPU 选 arm64 / mipsle / mips）
make client-darwin-arm64     # Apple Silicon Mac
make client-windows-amd64    # Windows
```

### 1. 新加坡服务器

```bash
# 生成密钥，直接得到可粘贴的 server.json / client.json
./prism-server keygen sg.example.com

# 把 server.json 放好，然后：
./prism-server -c /etc/prism/server.json
```

**证书（三选一，优先级 ACME > cert_file/key_file > self_signed）**：

- `acme`（**推荐**）：自动向 Let's Encrypt 签发并续期，走 TLS-ALPN-01 挑战，**只用现成的 :443**，不需要 80 端口或额外 Web 服务。要求域名解析到本机且公网可达 :443。

  ```json
  "acme": { "enabled": true, "domains": ["sg.example.com"], "email": "you@example.com",
            "cache_dir": "/etc/prism/acme" }
  ```
  首次测试建议把 `directory_url` 指向 Let's Encrypt staging，避免触发生产额度限制。
- `cert_file` + `key_file`：自己用 certbot 签发并续期（`certbot certonly --standalone -d sg.example.com`，续期时 reload 本服务）。
- `self_signed`：**仅本地测试**，过不了仔细探测；启动会打印 WARNING。

强烈建议把 `cover_backend` 指向一个**真实的网站/应用**（反代），这样主动探测看到的是真站。
用 systemd 托管见 `scripts/prism-server.service`。

**载波算法**：服务端 `ciphers` 列出接受的 AEAD（默认 `["aes-256-gcm"]`）。要同时服务有 AES-NI 的桌面和无 AES-NI 的路由器，列上两者 `["aes-256-gcm","chacha20-poly1305"]`——同线格式、无明文选择符，服务端按配置试解密自动识别每个客户端用的算法。

> 新增一个办公室/员工：`prism-keygen client <名字>` 生成一条 `{id, psk}`，加进服务器 `credentials`、把 `id/psk/server_public_key` 发给对方即可；删掉该条即吊销该客户端。

**验证抗探测**：浏览器直接访问 `https://sg.example.com/` 应当看到你的掩护网站，而不是任何异常。

### 2A. 路由器（OpenWrt + Nikki）

```bash
# 路由器上
cp prism-client /usr/bin/ && chmod +x /usr/bin/prism-client
mkdir -p /etc/prism && cp client-router.json /etc/prism/client.json
cp scripts/openwrt-prism-client.init /etc/init.d/prism-client
chmod +x /etc/init.d/prism-client
/etc/init.d/prism-client enable && /etc/init.d/prism-client start
```

然后在 Nikki/Mihomo 配置里加入 `config/nikki-mihomo.example.yaml` 的片段：定义一个指向
`127.0.0.1:1080` 的 `socks5` 出站 `PRISM-SG`，把出国流量路由进去，并掐掉 QUIC(UDP/443) 强制回落 TCP。

> **无 AES-NI 的路由器（MIPS / 老 ARM）**：在 `client.json` 里设 `"cipher": "chacha20-poly1305"`（服务端 `ciphers` 需包含它），软件实现比 AES-GCM 更快且常数时间。也可直接编译一个默认 ChaCha 的固件客户端：`go build -tags prism_chacha ./cmd/prism-client`，这样免改配置即默认走 ChaCha（显式 `cipher` 仍可覆盖）。

### 2B. 在家办公的 macOS / Windows 员工（无路由器）

把 `prism-client`、`client-desktop.json`（改名 `client.json`）、对应启动器放一个文件夹：

- **macOS**：首次 `chmod +x start-macos.command`，之后双击它。浏览器会打开控制面板，点"连接"。
- **Windows**：双击 `start-windows.bat`。

桌面模式会自动设置系统代理（mac 用 `networksetup`，Windows 用 WinINET），并在
`http://127.0.0.1:9797` 提供一个连接/断开的控制面板。退出时自动还原系统代理。

---

## 它如何抵御审查（概览）

| 审查手段 | Prism 的应对 |
|---|---|
| 被动 DPI / TLS 指纹 | 对自有域名的真实 TLS 1.3；**uTLS 模拟 Chrome ClientHello**；首包无明文特征 |
| 主动探测 | 无凭据 → 同机真实网站回落，探测只见正常站点 |
| SNI / 证书封锁 | 自有域名 + 真实证书，SNI 即正常域名 |
| TLS-in-TLS 检测 | 数据面不套内层 TLS，自有分帧 + 整形 |
| 熵分析 | 高熵只出现在 TLS 记录体内，无裸随机段 |
| 重放 | 一次性临时公钥 + 新鲜度窗口 + 重放集合 |

---

## 安全与合规（请读）

- 握手为**自研未审计**构造，刻意对齐 Noise_IKpsk2 以便替换为成熟库；面对高风险对手上线前请做密码学评审。
- 载波已接 **uTLS 模拟 Chrome 指纹**（`cmd/prism-client/dialer.go`）；仍需跟随 Chrome 版本更新 uTLS，`HelloChrome_Auto` 只对齐到打包时的某个稳定版，且 uTLS 指纹本身也在被研究，需持续迭代。
- 自有域名会被枚举/封锁，注意域名隔离与运维卫生。
- v1 数据面 TCP-only，需在 Nikki 掐 QUIC。
- 这是**坚实的工程基座，不是实网对抗成品**。完整清单见 `docs/PROTOCOL.md` §9。
- 统一出口是正当企业需求，但请自行确认符合各运营地法律法规与公司合规。

---

## 依赖与取舍

Prism 的协议核心 `pkg/prism/`（握手、KDF、分帧、mux、流控、重放）**除 ChaCha 外仍是纯 Go 标准库**。生产加固引入了**首批第三方依赖**，这是刻意的、也是无法在标准库内完成的取舍：

| 依赖 | 用途 | 为什么标准库做不到 |
|---|---|---|
| `github.com/refraction-networking/utls` | 客户端载波握手模拟 Chrome 的 ClientHello | Go `crypto/tls` 的 ClientHello（扩展顺序、GREASE、密码套件等）是一类**可被指纹识别**的特征，标准库不开放自定义 |
| `golang.org/x/crypto` | 路由器用的 **ChaCha20-Poly1305**；证书的 **acme/autocert** 自动签发 | 这两者都不在标准库内 |

因此 `go.mod` 不再是零依赖。影响与应对：

- **离线/受限构建**：先在有网主机 `go mod download` 或 `go mod vendor`（提交 `vendor/`），之后即可离线交叉编译。
- **交叉编译不受影响**：uTLS 与 x/crypto 均为纯 Go（无 CGO），`linux/mipsle`、`darwin/arm64`、`windows/amd64` 等目标照常 `GOOS/GOARCH` 一条命令构建（已验证）。
- **想保留极简核心**：`pkg/prism` 可单独作为库引用；只有当你用到 `NewChaCha20Poly1305AEAD` 时才会真正链接 x/crypto 的 chacha 包，uTLS/autocert 只在 `cmd/` 里用到。

---

## 测试

```bash
go test ./...        # 握手往返 / 重放拒绝 / AEAD(AES+ChaCha) / 算法协商矩阵 / 分帧 / mux / 流控(4MiB) /
                     # 24并发流 / 回落 / uTLS 载波端到端(AES+ChaCha, 1MiB 完整性 + 并发)
go test -race ./...  # 并发/mux 竞态检查
```
