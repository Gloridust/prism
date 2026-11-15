# Prism 协议规范 v1

> 一个**原创**的抗审查隧道传输协议。目标：把多地办公室的出口统一收敛到新加坡公司，
> 对抗 GFW 级别的审查方（被动 DPI、主动探测、SNI 封锁、TLS-in-TLS 检测、熵分析、流量分析、重放）。
>
> 本文是权威规范，字节级布局与 `pkg/prism` 的实现一一对应。

---

## 0. 这不是什么（原创性声明）

Prism 不是 REALITY / Trojan / VLESS 的二次开发，三者的核心机制与 Prism 不同：

| 协议 | 伪装模型 | 鉴权 | 抗主动探测方式 |
|---|---|---|---|
| **Trojan** | TLS-over-TCP，密码放在 TLS 之后 | 口令 SHA224 | 鉴权失败回落到真实网站 |
| **VLESS** | 自身无加密，依赖外层 TLS | UUID 明文标识 | 依赖外层传输 |
| **REALITY** | **借用**第三方站点的真实证书（握手期做 MITM 转发） | ClientHello 内嵌 X25519 鉴权 | 未鉴权连接被透明转发到被借用的真站 |
| **Prism** | **在自有域名上做一个真实应用**，把代理藏成该应用的合法负载 | **Noise-IK 风格 X25519 + PSK**，首包不可区分于随机 | 未鉴权连接由同机**真实 Web 回落**接管 |

Prism 的三个独有设计点：

1. **身份即首包随机性**：ClientInit 是「一个 X25519 公钥点 + 一段 AEAD 密文」，整体 80 字节，
   对没有服务器私钥 **且** 没有 PSK 的观察者而言与随机串不可区分——没有任何可供 DPI 匹配的明文结构。
2. **双因子互认 + 前向保密**：鉴权同时需要服务器静态私钥（服务端）和每客户端 PSK（客户端）两个因子；
   会话密钥由双方临时密钥（ephemeral-ephemeral）派生，事后即使泄露服务器静态私钥也无法解密历史会话。
3. **反 TLS-in-TLS 的数据面**：数据阶段**不**在 TLS 里再套一层 TLS，而是自有的 AEAD 分帧 + 多路复用 + 整形，
   记录长度分布服从可配置 profile，而非内层 TLS 握手突发——专门规避已公开的 TLS-in-TLS 指纹攻击
   （Xue et al., USENIX Security 2024 一类）。

---

## 1. 威胁模型

审查方能力假设（取 GFW 级别，向下兼容更弱对手）：

- **T1 被动 DPI**：对每个包做特征匹配、TLS 指纹（JA3/JA4）、明文字段识别。
- **T2 主动探测**：主动连接可疑服务器，发任意探测包，观察响应以判定是否为代理。
- **T3 SNI/证书识别**：按 TLS SNI 或证书封锁；ESNI/ECH 未普及地区尤甚。
- **T4 TLS-in-TLS 检测**：识别"TLS 里套 TLS"的内层握手突发与记录长度特征。
- **T5 熵分析**：全随机载荷（如裸 Shadowsocks）呈现异常高且均匀的熵，本身即特征。
- **T6 流量分析**：按包长分布、时序、方向性做统计/ML 分类。
- **T7 重放**：录制握手首包重放，探测服务器是否有可区分响应。

Prism 对每条威胁的应对见 §7。

---

## 2. 架构

```
   办公室/家庭                             新加坡
┌──────────────────┐                 ┌────────────────────────┐
│ 应用 / 浏览器     │                 │  prism-server :443      │
│   │              │                 │   ├─ 鉴权成功 → 隧道出口 │→ 互联网
│   ▼ (系统代理/TUN)│   Prism/TLS     │   └─ 鉴权失败 → 真实网站 │  (统一出口IP)
│ prism-client ────┼───────TCP:443──▶│      (cover backend)    │
│ (SOCKS5/HTTP)    │   看起来=普通HTTPS │                        │
└──────────────────┘                 └────────────────────────┘
   模式一：OpenWrt + Nikki 路由注入
   模式二：桌面自动系统代理 + 控制面板
```

- **客户端**一份跨平台二进制，两种部署：路由器旁车（SOCKS5，Nikki 注入）/ 桌面（SOCKS5+HTTP+系统代理+面板）。
- **服务端**在新加坡同时是「代理出口」和「真实网站」。任何没拿到有效凭据的访问者（含主动探测）看到的就是一个普通网站。

---

## 3. 术语与密码学参数

| 记号 | 含义 |
|---|---|
| `DH` | X25519（`crypto/ecdh`） |
| `AEAD` | 默认 AES-256-GCM（12B nonce，16B tag）；可换 ChaCha20-Poly1305（路由器推荐） |
| `HASH` | SHA-256 |
| `HKDF` | RFC 5869 的 Extract/Expand（基于 HMAC-SHA256） |
| `ProtocolName` | `"Prism/1 X25519 AESGCM SHA256"`，域分隔标签 |
| `(S_pub,S_priv)` | 服务器长期 X25519 静态密钥对 |
| `PSK` | 每客户端 32 字节预共享密钥（第二鉴权因子） |
| `CID` | 4 字节客户端标识（加密后传输，仅用于记账/吊销） |
| `(E_pub,E_priv)` | 客户端每连接一次性临时密钥 |
| `(F_pub,F_priv)` | 服务器每连接一次性临时密钥 |

**AEAD nonce**：`4 字节 0 || 8 字节大端计数器`。每把密钥各自独立，计数器从 0 起每帧 +1，收发方向分别用不同密钥，故不会 nonce 复用。

---

## 4. 密钥与身份管理

- 服务器生成一次 `(S_pub,S_priv)`；`S_priv` 只存在于新加坡那台机器。`S_pub` 分发给所有客户端。
- 每个办公室/设备配发一条 `Credential = {CID, PSK}`。服务器保存全部凭据集合，**逐条试认证**（见 §6），因此：
  - 吊销某设备 = 从服务器凭据集合删除该条；
  - 不同站点用不同 PSK，一处泄露不影响他处。
- 用 `prism-server keygen <域名>` 一键生成服务器身份 + 一条客户端凭据，并打印可直接粘贴的 server.json / client.json。

---

## 5. 载波层（Carrier）

握手与数据面本身与载波无关；载波只需提供一条可靠有序字节流，以及「升级为 Prism / 回落为掩护」的决策点。

- **v1 参考实现：`tcp-tls`** —— 服务器用**自有域名的真实证书**在 :443 跑 TLS 1.3。
  - ALPN 只宣告 `http/1.1`（与回落的 HTTP/1.1 掩护服务器一致，避免「ALPN 说 h2 却没有 h2 流量」的破绽）。
  - 生产应使用 uTLS 一类库把 ClientHello 指纹对齐到主流浏览器（参考实现用 Go `crypto/tls`，指纹可被识别，见 §8）。
- **规划：`quic-h3`** —— 原生 HTTP/3 站点，鉴权令牌藏在请求里，数据面走 WebTransport/QUIC datagram；
  QUIC 头大部分加密、天然多路复用，可彻底消除 TLS-in-TLS 突发，并在传输层带来按流独立的拥塞控制（mux 层已在 §7.4 消除队头阻塞）。
- **规划：`cdn-ws`** —— 经 CDN 的 WebSocket，便于域前置式部署与抗 IP 封锁。

---

## 6. 握手协议

两条**定长**消息。两条都是「裸 X25519 点（对观察者=均匀随机）+ AEAD 块」，无任何明文结构。

### 6.1 密钥调度

```
# 客户端算 es = DH(E_priv, S_pub)；服务端算 es = DH(S_priv, E_pub)
es   = DH(ephemeral, static)
ck0  = HKDF-Extract(salt = ProtocolName, ikm = es)
ck1  = HKDF-Extract(salt = ck0,          ikm = PSK)          # 混入 PSK：无 PSK 不可解
k_init = HKDF-Expand(ck1, "prism init v1", 32)

# 服务器验证通过后，双方各出一个临时公钥，做 ee 以获得前向保密
# 客户端算 ee = DH(E_priv, F_pub)；服务端算 ee = DH(F_priv, E_pub)
ee   = DH(ephemeral_c, ephemeral_s)
ck2  = HKDF-Extract(salt = ck1, ikm = ee)
k_resp = HKDF-Expand(ck2, "prism resp v1", 32)
k_c2s  = HKDF-Expand(ck2, "prism c2s v1", 32)               # 客户端→服务器 数据密钥
k_s2c  = HKDF-Expand(ck2, "prism s2c v1", 32)               # 服务器→客户端 数据密钥
```

### 6.2 ClientInit（客户端 → 服务器，共 80 字节）

```
偏移  长度  内容
0     32    E_pub                       # X25519 公钥，均匀随机
32    48    AEAD_Seal(k_init, nonce=0,  # 对下面 32 字节明载荷加密 + 16B tag
                       ad = SHA256(ProtocolName || E_pub),
                       plaintext = payload)
```

payload（32 字节明文）：

```
偏移  长度  内容
0     4     CID                         # 客户端标识
4     8     timestamp (int64, 大端, Unix 秒)   # 新鲜度
12    16    client_nonce (随机)
28    1     flags                       # bit0=请求多路复用；低位=profile id
29    3     reserved (置 0)
```

### 6.3 ServerResp（服务器 → 客户端，共 48 字节）

```
偏移  长度  内容
0     32    F_pub                       # 服务器临时公钥
32    16    AEAD_Seal(k_resp, nonce=0,  # 空明文，仅 tag：密钥确认
                       ad = SHA256(ProtocolName || E_pub || ClientInit[32:80] || F_pub),
                       plaintext = "")
```

客户端能成功 Open 这 16 字节 tag ⟺ 服务器确实持有 `S_priv` 且与客户端共享同一 `PSK`——即**服务器被认证**，可防 MITM。

### 6.4 服务端处理与回落判定

1. 增量读取至多 80 字节（带握手超时）。读不满 → 回落；**一旦已读字节里出现完整 HTTP 请求头结束符 `\r\n\r\n` 就立即回落**，不等凑满 80 字节——真实 Web 服务器对短请求是即时响应的，傻等到超时会成为主动探测可测的时序特征。
2. 解析 `E_pub`、`ct`；算 `es = DH(S_priv, E_pub)`、`ck0`、`ad = SHA256(ProtocolName||E_pub)`。
3. **逐条凭据试认证**：对每个 `PSK` 推 `ck1 / k_init`，尝试 `AEAD_Open(ct)`。失败则换下一条。
   （N 很小：几个办公室/一支设备队列；每次仅一个 48 字节 GCM open。）
4. 成功后校验：解出的 `CID` 与该凭据匹配；`timestamp` 在 `±window`（默认 120s）内；`E_pub` 未在重放窗口出现过。
5. 任一步失败 → 返回 `ErrNotPrism` 和**已消费的字节**，调用方把这些字节 + 后续连接透明交给掩护 Web 服务器。
6. 成功 → 生成 `F_pub`、算 `ee / ck2`，发 ServerResp，进入数据阶段。

### 6.5 抗重放

- 每连接一次性 `E_pub`，故重复的 `E_pub` 必是重放。
- 服务器维护窗口内 `E_pub` 集合（`ReplayWindow`，惰性过期），命中即拒。配合 `timestamp` 新鲜度窗口双保险。

---

## 7. 数据阶段：分帧、多路复用、整形

握手完成后，在同一条载波（外层 TLS）上跑 Prism 自有数据面。

### 7.1 线上帧格式

```
[2B 大端 ctLen][ct ...]                 # ctLen 是唯一明文；等价于 TLS 记录长度字段
ct = AEAD_Seal(k_dir, nonce=counter, plaintext=inner, ad=nil); counter 每帧 +1
```

inner（解密后的内层帧）：

```
偏移  长度  内容
0     1     cmd        # 0x00 DATA/0x01 PAD/0x02 SYN/0x03 FIN/0x04 RST/0x05 WND/0x06 SYN-UDP
1     4     streamID
5     2     dataLen
7     dataLen   data
7+dataLen ..  padding  # 其余为填充，加密内不可区分于载荷
```

- `SYN`：开流，`data` = 目标地址（SOCKS 风格 `atyp||addr||port`，**域名不本地解析**，由新加坡出口解析，避免本地 DNS 泄露目的）。
- `DATA`：某流的数据。`FIN`：半关闭（本侧不再发）。`RST`：中止流。`PAD`：纯掩护填充，忽略。
- `WND`：**流量控制信用**，`data` 为 4 字节大端信用值；接收方消费数据后回补发送方可发额度。

### 7.2 多路复用

- 多条逻辑流复用一条载波连接，像浏览器 keep-alive 的长连接，而非大量短连接（短连接本身是特征）。
- 客户端用奇数 ID、服务端用偶数 ID，ID 空间不相交。
- **逐流信用流量控制**：每条流初始接收窗口 512 KiB；接收方每消费约半个窗口即发 `WND` 帧回补发送方信用。单条流在途字节不超过一个窗口，既限制单流缓冲，又让载波读循环只做分发、从不因某条流阻塞——**从机制上消除 §7.4 的队头阻塞**。

### 7.3 整形（profile）

- **长度整形（已实现，`shaping:"pad"`）**：把每个出站帧的明文长度向上取整到固定档位
  {64,256,576,1280,4096,16000}，掩盖内层小记录（隧道内的 TLS ClientHello、DNS 查询、
  ACK 等）的真实长度，削弱 **T4/T6** 的长度相关性。填充字节在 AEAD 之内、收到即忽略，
  故整形是**纯本地、按方向**的选择，无需两端协商；满载帧超过最大档位不填充，不损吞吐。
- **时序整形（IAT）**：发送时序抖动尚未实现（吞吐代价大），列为后续。
- 默认 `shaping:"none"`（直通）。

### 7.4 队头阻塞的消除

mux 层实现了**逐流信用流量控制**（§7.2）：载波读循环只把每一帧分发到对应流的接收队列、**自身从不阻塞**，
单条慢流至多占用它自己一个窗口（512 KiB）的缓冲，不会拖住同一载波上的其他流。客户端仍维持一个小连接池
（默认 4 条载波）以提升并行度与容灾；传输层级的按流拥塞控制可由 `quic-h3` 进一步提供。

### 7.5 保活与死连检测

两端在数据阶段各每 15 秒发一个空 `PAD` 帧；某条载波连续 60 秒收不到任何帧即
判定载波已死并拆除（跨境链路常被有状态中间设备静默掐断，若只靠系统 TCP
keepalive 可能数分钟才感知）。这是 WireGuard/QUIC 的持久保活 + 空闲超时模式，
`PAD` 不携带流数据、收到即忽略，超时值可按部署调整。

### 7.6 UDP 转发（UDP over stream）

`SYN-UDP`(0x06) 开一条 UDP 中继流。该流的可靠字节通道上承载自定界的带址数据报：

```
[uint16 total][uint8 addrLen][addr(atyp||host||port)][payload]   total=1+addrLen+len(payload)
```

一次写入即一个数据报，读方据 total 还原包边界。客户端把 SOCKS5 UDP ASSOCIATE
收到的每个数据报按此封帧上送；出口服务器据址（同样经 §8-T8 出口策略校验）用
一个 UDP 套接字发往目标，并把每个回包按来源地址封帧回送。这是"UDP over 可靠流"
——给原本无连接的 UDP 附加了有序可靠性，是把数据报塞进单条载波的通行取舍；对
DNS、QUIC、实时音视频等足够可用。空闲 60s 的 UDP 关联自动回收。

---

## 8. 各威胁如何被应对

| 威胁 | 机制 |
|---|---|
| T1 被动 DPI | 外层是对自有域名的真实 TLS 1.3；Prism 首包无明文结构 |
| T2 主动探测 | 无有效凭据 → 同机真实 Web 回落，探测者只见一个正常网站 |
| T3 SNI/证书 | 用**自有域名 + 真实证书**，SNI 就是你自己的正常域名；可叠加 ECH |
| T4 TLS-in-TLS | 数据面不套内层 TLS，用自有 AEAD 分帧 + 整形，无内层握手突发 |
| T5 熵分析 | 高熵字节只出现在载波本就期望高熵处（TLS 记录体）；无裸随机段 |
| T6 流量分析 | profile 整形 + 多路复用长连接，贴近真实应用的长度/时序分布 |
| T7 重放 | 一次性 `E_pub` + 新鲜度窗口 + 重放集合 |
| T8 内网 SSRF | 出口默认拒绝私网/环回/链路本地(含云元数据)/CGNAT 目标；解析后只连已放行公网 IP，杜绝 DNS 重绑定 |

---

## 9. 安全局限与诚实告警（务必读）

1. **握手是自研、未经审计的构造**。它刻意对齐 Noise_IKpsk2 的形态，便于生产替换为经过验证的 Noise 库
   （如 flynn/noise）。**面对高风险对手上线前，请做独立密码学评审**，或直接换成成熟 Noise 实现。
2. **TLS 指纹**：已接 uTLS（`cmd/prism-client/dialer.go`，`utls.HelloChrome_Auto`）让客户端载波握手对齐
   Chrome 的 ClientHello，SNI/ALPN 不变（http/1.1）；服务端仍用标准 `crypto/tls` 终止（指纹是客户端侧问题）。
   残留风险：`HelloChrome_Auto` 只对齐到 uTLS 打包时的某个稳定版 Chrome，需随浏览器版本升级 uTLS；uTLS 指纹本身
   也在被研究。ECH 尚未实现。
3. **自有域名会被枚举/封锁**：一旦域名/IP 被发现即可被墙。运维上要做到域名不复用、不公开关联，必要时上 CDN/域前置。
4. **UDP 为 over-stream**：UDP（DNS/QUIC/实时音视频）经 §7.6 的 UDP-over-stream 转发，附带了 TCP 的有序可靠语义，故对 QUIC 这类自带拥塞控制的协议并非最优（相当于在可靠流里再跑一层）。够用但非理想；原生数据报传输见 `quic-h3` 规划。
5. **队头阻塞**：mux 层已用逐流信用流控消除（§7.2/§7.4）；连接池用于并行度与容灾，`quic-h3` 可在传输层再加按流拥塞控制。
6. **这是一个坚实的工程基座，不是经过实网对抗检验的成品**。抗审查协议必须在真实网络里对抗、迭代。
7. **默认 AEAD 是 AES-256-GCM**。无 AES 硬件加速的路由器（MIPS/部分 ARM）可切 ChaCha20-Poly1305
   （`pkg/prism/aead_chacha.go` 的 `NewChaCha20Poly1305AEAD`）：客户端用配置 `cipher` 或构建标签 `prism_chacha`
   选择，服务端用 `ciphers` 列出接受集合并**按序试解密**自动识别每个客户端用的算法。两者**线格式完全一致**
   （12B nonce / 16B tag，首包仍 80 字节），**不在明文里携带算法选择符**（那会引入可识别特征并改变线格式）。
   注意：引入 ChaCha 使 `go.mod` 依赖 `golang.org/x/crypto`（见 README「依赖与取舍」），不再是零第三方依赖。
8. **合规**：统一出口是正当的企业网络需求，但请确认符合你各运营地的法律法规与公司合规要求。

---

## 10. 路线图

- [ ] `quic-h3` 载波（原生 HTTP/3 伪装 + 按流拥塞控制）
- [x] uTLS 指纹对齐（Chrome ClientHello）；ECH 待做
- [x] ChaCha20-Poly1305 可选算法（路由器无 AES-NI）
- [x] ACME/Let's Encrypt 证书自动签发（TLS-ALPN-01）
- [ ] profile 整形库（网页/视频/下载画像）
- [ ] 握手替换为经审计的 Noise_IKpsk2 实现
- [ ] UDP relay（SOCKS UDP ASSOCIATE / QUIC 直穿）
- [ ] 订阅分发与密钥轮换、per-CID 配额与审计
- [ ] 桌面原生 TUN 全局模式
