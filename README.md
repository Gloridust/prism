# Prism

**一个原创的抗审查隧道协议 + 两端软件**，用于把多地办公室/远程员工的出口统一收敛到新加坡公司。

- 对观察者而言，流量就是**对你自有域名的一次普通 HTTPS 连接**。
- 任何没有有效凭据的访问者（包括主动探测）看到的，是你服务器上**一个真实的网站**。
- 鉴权是 **X25519 + 每客户端 PSK 的双因子互认**，握手首包 80 字节不可区分于随机，带前向保密与抗重放。
- 数据面**不套内层 TLS**（规避 TLS-in-TLS 指纹），自有 AEAD 分帧 + **逐流流控的多路复用** + 整形。
- 纯 Go 标准库，**零第三方依赖**，一条命令交叉编译到路由器 / macOS / Windows。

> 设计细节与字节级规范见 [`docs/PROTOCOL.md`](docs/PROTOCOL.md)。
> 与 REALITY/Trojan/VLESS 的区别、安全局限与诚实告警也在那里，**上线前务必读第 9 节**。

---

## 组成

```
pkg/prism/            协议核心（纯标准库，带单元测试）
  kdf.go  aead.go  keys.go  handshake.go  replay.go  session.go  addr.go
cmd/prism-server/     新加坡出口：TLS + 鉴权 + 多路复用出口 + 真实网站回落
cmd/prism-client/     跨平台客户端：路由器旁车 / 桌面(系统代理+控制面板)
config/               配置样例 + Nikki/Mihomo 路由片段
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

# 把 server.json 放好（生产用真实证书 cert_file/key_file），然后：
./prism-server -c /etc/prism/server.json
```

强烈建议把 `cover_backend` 指向一个**真实的网站/应用**（反代），这样主动探测看到的是真站。
用 systemd 托管见 `scripts/prism-server.service`。

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
| 被动 DPI / TLS 指纹 | 对自有域名的真实 TLS 1.3；首包无明文特征 |
| 主动探测 | 无凭据 → 同机真实网站回落，探测只见正常站点 |
| SNI / 证书封锁 | 自有域名 + 真实证书，SNI 即正常域名 |
| TLS-in-TLS 检测 | 数据面不套内层 TLS，自有分帧 + 整形 |
| 熵分析 | 高熵只出现在 TLS 记录体内，无裸随机段 |
| 重放 | 一次性临时公钥 + 新鲜度窗口 + 重放集合 |

---

## 安全与合规（请读）

- 握手为**自研未审计**构造，刻意对齐 Noise_IKpsk2 以便替换为成熟库；面对高风险对手上线前请做密码学评审。
- 参考实现用 Go `crypto/tls`，指纹可识别；生产应接 uTLS。
- 自有域名会被枚举/封锁，注意域名隔离与运维卫生。
- v1 数据面 TCP-only，需在 Nikki 掐 QUIC。
- 这是**坚实的工程基座，不是实网对抗成品**。完整清单见 `docs/PROTOCOL.md` §9。
- 统一出口是正当企业需求，但请自行确认符合各运营地法律法规与公司合规。

---

## 测试

```bash
go test ./...        # 握手往返 / 重放拒绝 / AEAD / 分帧 / 多路复用 / 流控(4MiB) / 24并发流 / 回落
```
