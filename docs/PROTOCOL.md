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
| **Prism** | **在自有域名上做一个真实应用**，把代理藏成该应用的合法负载；也可切到 steal 模式借用第三方站点 | **X25519 + 每客户端 PSK**（自研握手或 Noise_IKpsk1），首包不可区分于随机 | 未鉴权连接由同机**真实 Web 回落**接管，或（steal）整条 TCP 转发到真实站点 |

Prism 的三个独有设计点：

1. **身份即首包随机性**：ClientInit 是「一个 X25519 公钥点 + 一段 AEAD 密文」，整体 80 字节，
   对没有服务器私钥 **且** 没有 PSK 的观察者而言与随机串不可区分——没有任何可供 DPI 匹配的明文结构。
2. **双因子互认 + 前向保密**：鉴权同时需要服务器静态私钥（服务端）和每客户端 PSK（客户端）两个因子；
   会话密钥由双方临时密钥（ephemeral-ephemeral）派生，事后即使泄露服务器静态私钥也无法解密历史会话。
3. **反 TLS-in-TLS 的数据面**：数据阶段**不**在 TLS 里再套一层 TLS，而是自有的 AEAD 分帧 + 多路复用 + 整形，
   记录长度分布服从可配置 profile，而非内层 TLS 握手突发——专门规避已公开的 TLS-in-TLS 指纹攻击
   （Xue et al., USENIX Security 2024 一类）。

### 0.1 取长补短：与主流协议逐项对照

下表列出各协议公认的强项，以及 Prism 对应的做法。「局限」一栏是如实说明，不是客套。

| 来源 | 它的强项 | Prism 的对应实现 | 局限 |
|---|---|---|---|
| **Trojan** | 真实证书 + 鉴权失败回落真实网站，部署简单 | 默认模式即此模型：ACME 自动证书，未鉴权连接交给 `cover_backend`（HTTP/1.1 与 h2 均支持） | 内置占位页只适合测试，生产必须反代到真实站点 |
| **Trojan-Go / VLESS-WS** | WebSocket 过 CDN | `transport: "ws"`，握手 ALPN 与 Chrome 的 wss 行为一致（仅 http/1.1） | 经 CDN 时 CDN 能看到 Prism 密文帧的长度与时序 |
| **REALITY** | 不需要自有域名与证书；探测者看到真实站点；标记绑定握手、不可重放 | steal 模式：标记覆盖整个 ClientHello、带加密时间戳、单次有效；仅 TLS 1.3；启动时探测目标站并对齐 ALPN 与证书链长度（§7.7） | ServerHello 由 Go `crypto/tls` 生成，套件选择等细节无法逐字节复刻目标站，目标站需按提示挑选；客户端不校验外层证书，服务端身份由内层握手保证 |
| **VLESS XTLS-Vision** | 对隧道内 TLS 握手包做填充，消除 TLS-in-TLS 长度特征 | 流首填充默认开启：每条流前 8 个数据帧与 SYN 随机化长度（§7.12） | 不做 Vision 的「握手后直通（splice）」，全程双层加密，CPU 开销略高 |
| **Shadowsocks 2022** | 首包全随机、时间戳 + 重放保护 | ClientInit 80 字节全随机，新鲜度窗口 + 重放集合；Noise 模式同样处理 | — |
| **Hysteria2 / TUIC** | QUIC 弱网拥塞控制、HTTP/3 伪装、认证失败即表现为普通 H3 站点 | `transport: "quic"`：服务端是真实的 HTTP/3 站点，隧道跑在一个 POST 请求里，握手不通过的任何请求都由回落站点应答（§7.14） | UDP 仍走 over-stream，没有用 QUIC 原生数据报；客户端 QUIC 指纹是 quic-go 的，不是 Chrome 的 |
| **naiveproxy** | 复用 Chrome 网络栈，指纹完全一致 | uTLS 模拟 Chrome ClientHello | 仅 ClientHello 层面对齐，需随 Chrome 版本升级 uTLS |
| **WireGuard** | 极简、经审计的 Noise 握手 | `handshake: "noise"` 使用 flynn/noise 状态机（§6.6） | Prism 用的是 IKpsk1 而非 WireGuard 的 IKpsk2，见 §6.6 的取舍说明 |
| **企业 VPN 网关** | 多出口容灾、按人吊销、配额、监控 | `backups` 自动故障切换与回切；管理 API 持久化增删/轮换凭据并踢线；按日配额；Prometheus `/metrics` | 计量每 30 秒落盘一次，异常掉电最多丢 30 秒的计数 |

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

### 6.6 Noise 模式（`handshake: "noise"`）

握手状态机换成 `flynn/noise`，模式为 **Noise_IKpsk1_25519_AESGCM_SHA256**，prologue 为协议名：

```
<- s
...
-> e, es, s, ss, psk      # 载荷：CID(4) ‖ unix秒(8) ‖ 数据面算法ID(1)，加密
<- e, ee, se
```

线上每条 Noise 消息前有 2 字节大端长度。要点：

- **为什么是 psk1 而不是 WireGuard 的 psk2**：psk2 把 PSK 混入第二条消息，第一条消息不依赖 PSK，于是任何知道服务器公钥的人都能让服务端回复，主动探测即可识别。psk1 让第一条消息的载荷只有持有该客户端 PSK 的服务端才能解开：服务端据此逐凭据试解密来识别客户端，对不持有 PSK 的对端**一个字节都不回**，直接走回落。代价是 psk1 的公开分析少于 psk2。
- **流量密钥**取自 Noise `Split()` 得到的两个 CipherState 的密钥，再与握手哈希一起过 HKDF；不会仅由握手哈希派生（握手哈希可由线上字节算出）。
- **数据面算法**由客户端在加密载荷里声明（1=AES-256-GCM，2=ChaCha20-Poly1305），服务端只接受自己 `ciphers` 列表里的算法。
- 客户端静态密钥每次连接随机生成，客户端身份由 CID + PSK 确定，握手之间不可关联。

两种握手的线格式不兼容，两端必须同时切换。

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
- **时序整形（IAT，已实现，`iat_max_ms`）**：对小于 1280 字节的 DATA 帧，在获取写锁
  之前注入一个 `[0, iat_max_ms)` 毫秒的随机延迟，模糊帧间到达时间的周期性特征，
  削弱 **T6** 的时序相关性。大帧（≥1280B，即批量传输）不受影响，仅对交互式小包
  生效，实际吞吐代价可忽略。建议值 20–50 ms。
- 默认 `shaping:"none"`（直通），IAT 默认关闭（`iat_max_ms:0`）。

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

### 7.7 REALITY 风格主动探测抗性（steal 模式）

启用 steal 后，服务器在完成 TLS 之前先在 TCP 层检查原始 ClientHello。已认证客户端在 32 字节的 `session_id`（TLS 1.3 兼容模式下本就是随机串）里携带标记：

```
stealKey   = HKDF-Expand(HKDF-Extract("Prism/1 …", psk), "prism steal v2")
sid[0:20]  = 随机
sid[20:24] = unix秒(uint32) XOR HMAC(stealKey, "ts" ‖ sid[0:20])[0:4]
sid[24:32] = HMAC(stealKey, "tag" ‖ ClientHello（sid[24:32] 置零）)[0:8]
```

服务端处理：

1. 读入第一条 TLS 记录（必须包含完整 ClientHello），对每个凭据验证 `tag`；
2. 解出时间戳并检查新鲜度窗口；
3. 该 `session_id` 进入重放集合，**每个标记只接受一次**；
4. 全部通过 → 用临时证书完成 **TLS 1.3**，随后进入内层握手；
5. 任一步失败 → 整条 TCP 连接（含已读字节）转发到 `steal.dest`，对方看到的是真实站点的证书与内容。

这样设计的原因：

- `tag` 覆盖整个 ClientHello，标记无法被搬到另一个 ClientHello 上（换密钥交换参数、降级 TLS 版本都会失效）。
- 重放抓到的 ClientHello 只会被转发到真实站点；即使在重放集合过期前抢先重放，由于只走 TLS 1.3，服务端证书在握手密钥下加密，而重放者没有对应的 key share 私钥，读不到证书。
- 时间戳经过掩码，线上不出现可识别的时间字段。

**对齐目标站**：服务端启动时以浏览器方式与 `steal.dest` 握手一次，记录其 TLS 版本、套件、ALPN 和证书链字节数，然后让自己对已认证客户端的应答选择相同的 ALPN，并把临时证书填充到相同长度（加密后的证书飞行长度因此一致）。目标站不是 TLS 1.3、或选择的套件与本机不同，会在日志里给出告警——请据此挑选目标站（要求与 REALITY 相同：TLS 1.3、h2、X25519）。

与 REALITY 的区别：REALITY 把认证信息放进 X25519 密钥交换并让客户端在外层校验服务端；Prism 的外层 TLS 不做证书校验，**服务端身份由内层握手用服务器静态密钥证明**，外层被中间人替换只会导致内层握手失败。steal 与 `transport: "quic"`、`ech` 互斥。

### 7.8 WebSocket 载波传输

配置 `transport:"ws"` + `ws_path` 后，客户端在 TLS 之上先完成 RFC 6455 升级握手
（HTTP/1.1 101 Switching Protocols），然后在 WebSocket 二进制帧内运行 Prism 握手与数据面。

- 实现为最小 RFC 6455（仅二进制帧、ping/pong、close），约 250 行，无外部依赖。
- 客户端帧按规范做掩码（mask），服务端帧不掩码。
- 用途：穿透 Cloudflare 等只代理 HTTP 的 CDN——对 CDN 来说这只是一个普通的 WebSocket 长连接。
- 未启用 WS 时，载波直接在 TLS 流上运行，无额外开销。

### 7.9 HTTP/2 cover

服务端 TLS 配置的 ALPN 列表为 `["h2", "http/1.1"]`。当 TLS 协商到 h2 时：

- **非 Prism 访客（浏览器/探测器）**：使用 `x/net/http2.Server.ServeConn()` 提供完整 HTTP/2 cover 页面，
  与真实网站无异。
- **Prism 客户端**：uTLS 以 `http/1.1` ALPN 连接，不走 h2，直接进入 Prism 握手。
- **WebSocket 客户端**：WS 升级是 HTTP/1.1，同样不走 h2。

效果：主动探测器用浏览器（默认 h2）访问时看到的是一个支持 HTTP/2 的真实网站，
更难与仅支持 HTTP/1.1 的代理区分。

### 7.10 载波会话轮换

配置 `max_lifetime_sec` 后，每条载波会话在存活超过指定时间后进入「排空」状态：

- 新建流（`OpenStream`/`OpenUDP`）返回 `ErrSessionDraining`，客户端的连接池自动在下一个池槽重拨新会话。
- 已有流继续运行直到自然结束，不被强制中断。
- `sessionDead()` 把 draining 的会话视为不可用，触发重拨。

目的：定期轮换 TLS 连接，避免单条连接存活过久成为统计特征；与真实浏览器的连接行为更一致。

### 7.11 WebRTC 与 IP 泄露防护

WebRTC 会用 STUN（UDP）探测本机的公网地址（server-reflexive candidate），还会枚举本机网卡地址（host candidate）。这些行为都不经过 HTTP/SOCKS 代理，所以只设系统代理时，网页能直接拿到中国办公室的真实公网 IP，以及原生 IPv6 地址。各模式的防护方式如下：

| 模式 | 机制 | 保证程度 |
|---|---|---|
| TUN 全局（`tun`） | IPv4 用 `0/1`+`128/1`、IPv6 用 `::/1`+`8000::/1` 全部路由进 TUN；UDP 按 §7.6 封帧经隧道转发，STUN 从新加坡出口发出，探测到的是新加坡地址。服务器地址在启动时固定为一个 IPv4（`pinServerIPv4`），并加主机路由，避免载波自身被 TUN 接管而形成环路。若本机有公网 IPv6 但接管失败，**拒绝启动**（fail-closed）。浏览器侧再加 `default_public_interface_only`，物理网卡的内网地址也不会出现在 candidate 里。 | 对所有应用生效，包括 Safari 和原生会议软件 |
| 桌面系统代理 | `webrtc_guard`（默认开启）：连接时写入 Chrome/Brave 的 `WebRtcIPHandling` 和 Edge 的 `WebRtcLocalhostIpHandling`，值为 `disable_non_proxied_udp`，断开时恢复原值；Firefox 的 `user.js` 写入 `proxy_only_if_behind_proxy` 和 `default_address_only`。WebRTC 不再发直连 UDP，改走代理上的 TURN-over-TCP。 | 只覆盖上述浏览器；Safari 和原生应用仍会直连，需要完全防护请用 TUN |
| 路由器（Nikki/Mihomo） | STUN/TURN 端口（3478/5349/19302）的规则排在 `GEOIP,CN,DIRECT` 之前，强制走出口；IPv6 要么由 Mihomo 接管，要么关闭 LAN 的 IPv6 分发（见 `config/nikki-mihomo.example.yaml`）。最严格的做法是 `NETWORK,udp,PRISM-SG`。 | 覆盖整个 LAN |

全公司强制：`config/webrtc-policy.mobileconfig`（macOS MDM）、`config/webrtc-policy.reg`（Windows HKLM/GPO）、`config/firefox-policies.json` 提供 mandatory 级策略，用户和扩展都无法覆盖。

残留风险：未启用 `tun.kill_switch` 时，进程被强杀后 TUN 设备消失、路由失效，流量会回到直连——要求不泄露真实 IP 的部署请启用 kill-switch（§7.15）。用户级浏览器策略可能在异常退出后残留，下次连接时会被识别为我方设置的值并正确清理。

### 7.12 流首填充（对抗 TLS-in-TLS 识别）

隧道里承载的多数是 HTTPS，其自身的 TLS 握手（ClientHello ≈ 517 字节、ServerHello + 证书的突发）在外层记录长度上留下稳定特征，这是已公开的 TLS-in-TLS 检测的主要依据。Prism 对**每条流的前 8 个 DATA 帧**做长度随机化（`head_padding`，默认开启，两端各自独立）：

- 载荷小于 900 字节的帧，填充到 [900, 1400) 内的随机长度；
- 更长的帧追加 0–255 字节；接近满帧（约 16 KB）的不填充，保证不跨 TLS 记录；
- 打开流的 SYN 帧填充到 64 字节的整数倍，隐藏目标域名长度。

填充位于 AEAD 之内，接收端按帧头的 `dataLen` 丢弃，无需协商。第 9 帧起不再填充，所以大流量传输的吞吐不受影响；代价是每条短连接多出几 KB。它与 §7.3 的整形 profile 可以叠加。

### 7.13 多出口与故障切换

客户端可配置 `backups`（每项含 `server`、`sni`、`server_public_key`，共用同一组 `id`/`psk`）。拨号时从当前出口开始按顺序尝试，当前出口不可达就切到下一个并记录日志；运行在备用出口时每 5 分钟尝试一次回切主出口。拨号失败的连接槽按指数退避（0.5 s 起，上限 30 s，带抖动）快速失败，出口不可达时应用侧不会被逐个 10 秒超时拖住。TUN 模式下每个出口都固定为一个 IPv4 并加主机路由。

### 7.14 QUIC 载波：HTTP/3 请求内的隧道

`quic_listen` 启动的是一个真实的 HTTP/3 服务器（ALPN `h3`，TLS 1.3，与 TCP 入口共用证书）。客户端建立 QUIC 连接后发起一个流式 `POST <quic_path>`（默认 `/_prism/h3`）：请求体是客户端→服务端方向的 Prism 字节流，响应体是反方向。

服务端处理每个 HTTP/3 请求时：

- 路径与方法匹配 → 从请求体读内层握手；**握手成功之前不写任何响应**；
- 握手成功 → 回 200 并在同一个请求上进入会话；
- 路径不匹配、握手失败、普通浏览器访问 → 把已读的请求体放回，交给回落站点处理。

所以即使探测者知道隧道路径，不持有凭据时得到的也是回落站点对这个 POST 的正常应答，与访问其它路径没有区别。

### 7.15 Kill-switch（TUN 模式）

`tun.kill_switch: true` 时，客户端在系统防火墙里安装规则，拒绝一切不经隧道的出站流量。规则属于操作系统而不是客户端进程，进程崩溃或被强杀后依然生效，机器会断网而不是回到直连。

| 放行 | 拒绝 |
|---|---|
| 回环；TUN 接口；Prism 服务器（含备用出口）的 IP；本地网络（RFC1918、链路本地、组播、IPv6 ULA/链路本地） | 其余全部 IPv4 与 IPv6 出站；**发往回环与隧道以外任何地址的 DNS（含局域网解析器）** |

| 平台 | 实现 | 重启后 |
|---|---|---|
| Linux | nftables 表 `inet prism_killswitch`，output 链，原子替换 | 默认不保留；`kill_switch_boot` 时由 systemd 单元在 `network-pre.target` 之前加载 |
| macOS | pf 锚点 `com.apple/250.PrismKillSwitch`（系统默认规则集已引用 `com.apple/*`，不改写 `/etc/pf.conf`），`pfctl -E` 引用计数启用。放行规则一律无状态、匹配任意 TCP 标志位（pf 默认的「只匹配 SYN + 状态」会重置回环连接和启用前已建立的连接） | 默认不保留；`kill_switch_boot` 时由 LaunchDaemon 在开机时加载 |
| Windows | Windows 防火墙出站阻止规则 `PrismKillSwitch`。阻止规则优先于允许规则，所以写成「阻止允许集合的补集」，并限定本地地址为隧道地址与回环以外的地址 | 规则保留 |

`tun.kill_switch_boot: true` 让规则在每次开机时重新装上（开机到隧道建立之间也没有直连），并且正常退出时**不**移除规则，只有 `-killswitch-off` 能解除——这是「始终在线」模式，客户端需要设为开机自启，否则机器开机后没有外网。未设置该项时，正常退出时规则被移除；异常退出后用 `prism-client -killswitch-off` 移除，或重新启动客户端（启动时会原子替换旧规则）。因为异常退出后 DNS 也被封，客户端把上次解析到的服务器 IP 缓存在 `<配置文件>.resolved`，解析失败时使用缓存，保证能自己恢复连接。启用后若规则安装失败，客户端拒绝启动。

---

## 8. 各威胁如何被应对

| 威胁 | 机制 |
|---|---|
| T1 被动 DPI | 外层是对自有域名的真实 TLS 1.3；Prism 首包无明文结构 |
| T2 主动探测 | 无有效凭据 → 同机真实 Web 回落；steal 模式下 TCP 透传到真实目标站，标记绑定 ClientHello 且单次有效（§7.7）；Noise 模式对无 PSK 的对端不回任何字节（§6.6） |
| T3 SNI/证书 | 用**自有域名 + 真实证书**，SNI 就是你自己的正常域名；**ECH 已实现**（`ech: "auto"` 加密 SNI） |
| T4 TLS-in-TLS | Prism 自身不再套一层 TLS 握手；被承载连接自带的 TLS 握手长度由流首填充随机化（§7.12），可再叠加整形 profile |
| T5 熵分析 | 高熵字节只出现在载波本就期望高熵处（TLS 记录体）；无裸随机段 |
| T6 流量分析 | profile 整形 + IAT 时序抖动（§7.3）+ 多路复用长连接 + 载波轮换（§7.10），贴近真实应用的长度/时序/连接分布 |
| T7 重放 | 一次性 `E_pub` + 新鲜度窗口 + 重放集合 |
| T8 内网 SSRF | 出口默认拒绝私网/环回/链路本地(含云元数据)/CGNAT 目标；解析后只连已放行公网 IP，杜绝 DNS 重绑定 |
| T9 WebRTC/IPv6 泄露真实 IP | TUN 接管 IPv4+IPv6 与 UDP（STUN 从出口发出，IPv6 接管失败即拒绝启动）；代理模式写入浏览器 WebRTC IP 策略；路由器侧 STUN 规则前置（§7.11） |
| T10 客户端崩溃后回落直连 | kill-switch：防火墙规则独立于进程，隧道消失后机器断网而不是直连（§7.15） |

---

## 9. 安全局限与诚实告警（务必读）

1. **两种握手都没有经过独立的密码学审计**。默认握手是自研构造；`handshake: "noise"` 使用经审计的
   `flynn/noise` 状态机（§6.6），但 Prism 对它的用法（psk1 模式选择、密钥导出、载荷格式）本身未经第三方评审。
   面对高风险对手，上线前请安排评审；两者之间优先选 `noise`。
2. **TLS 指纹**：已接 uTLS（`cmd/prism-client/dialer.go`，`utls.HelloChrome_Auto`）让客户端载波握手对齐
   Chrome 的 ClientHello，SNI/ALPN 不变（http/1.1）；服务端 ALPN 已启用 h2（§7.9），用标准 `crypto/tls` 终止（指纹是客户端侧问题）。
   残留风险：`HelloChrome_Auto` 只对齐到 uTLS 打包时的某个稳定版 Chrome，需随浏览器版本升级 uTLS；uTLS 指纹本身
   也在被研究。**ECH 已实现**：客户端配置 `ech: "auto"` 通过 DoH 自动获取 DNS HTTPS 记录中的
   ECHConfigList，或手动填写 base64 编码的配置。启用后 TLS 握手的 SNI 字段加密，网络观察者无法
   看到连接的真实域名。
3. **自有域名会被枚举/封锁**：一旦域名/IP 被发现即可被墙。运维上要做到域名不复用、不公开关联，必要时上 CDN/域前置。
4. **UDP 为 over-stream**：UDP（DNS/QUIC/实时音视频）经 §7.6 的 UDP-over-stream 转发，附带了 TCP 的有序可靠语义，故对 QUIC 这类自带拥塞控制的协议并非最优（相当于在可靠流里再跑一层）。够用但非理想；原生数据报传输见 `quic-h3` 规划。
5. **队头阻塞**：mux 层已用逐流信用流控消除（§7.2/§7.4）；连接池用于并行度与容灾，`quic-h3` 可在传输层再加按流拥塞控制。
6. **这是一个坚实的工程基座，不是经过实网对抗检验的成品**。抗审查协议必须在真实网络里对抗、迭代。
7. **默认 AEAD 是 AES-256-GCM**。无 AES 硬件加速的路由器（MIPS/部分 ARM）可切 ChaCha20-Poly1305
   （`pkg/prism/aead_chacha.go` 的 `NewChaCha20Poly1305AEAD`）：客户端用配置 `cipher` 或构建标签 `prism_chacha`
   选择，服务端用 `ciphers` 列出接受集合并**按序试解密**自动识别每个客户端用的算法。两者**线格式完全一致**
   （12B nonce / 16B tag，首包仍 80 字节），**不在明文里携带算法选择符**（那会引入可识别特征并改变线格式）。
   注意：引入 ChaCha 使 `go.mod` 依赖 `golang.org/x/crypto`（见 README「依赖与取舍」），不再是零第三方依赖。
8. **QUIC 载波的指纹**：QUIC 入口有 HTTP/3 回落（§7.14），主动探测看到的是普通 H3 站点；但客户端的 QUIC 握手由 quic-go 生成，传输参数与 Chrome 不同，被动指纹上能区分「Go 写的 H3 客户端」。对抗性强的线路优先用 TCP 载波（uTLS 对齐 Chrome）。
9. **Kill-switch 需显式开启**：默认关闭；未启用时，进程被强杀后流量回到直连。跨重启的保护需要再开 `kill_switch_boot`（Windows 的规则本身就跨重启）。Linux 的开机加载经过真实重启验证（`scripts/test-killswitch-reboot.sh`：以 systemd 为 1 号进程的机器装上钩子后真的重启，规则在网络服务启动前由 systemd 装回；解除后再重启不再出现）。macOS 的 LaunchDaemon 只验证到「文件通过 `plutil` 校验、开机时执行的那条命令能独立把规则装回去」，没有在真的重启的 Mac 上验证过，首次部署请实际重启一次确认。桌面模式写入的系统代理、系统 DNS、浏览器策略在异常退出后可能残留，重新启动并正常退出即可恢复。
10. **计量**：每凭据流量与当日用量每 30 秒落盘（`stats_file`）并在正常退出时保存；异常掉电最多丢失最后 30 秒。未配置 `credentials_file`/`stats_file` 时仍只在内存中。
11. **时钟**：握手带时间戳，两端时钟偏差超过 `window_seconds`（默认 120 秒）会被当作未认证连接。没有 RTC 的路由器需先完成 NTP 同步。
12. **合规**：统一出口是正当的企业网络需求，但请确认符合你各运营地的法律法规与公司合规要求。

---

## 10. 路线图

- [x] `quic-h3` 载波（`transport: "quic"`，quic-go，原生 HTTP/3 伪装 + 按流拥塞控制）
- [x] uTLS 指纹对齐（Chrome ClientHello）+ ECH（`ech: "auto"` 自动获取 / 手动配置）
- [x] ChaCha20-Poly1305 可选算法（路由器无 AES-NI）
- [x] ACME/Let's Encrypt 证书自动签发（TLS-ALPN-01）
- [x] REALITY 风格主动探测抗性（steal 模式：标记绑定整个 ClientHello、加密时间戳、单次有效、对齐目标站 ALPN 与证书长度）
- [x] WebSocket 载波传输（穿透 Cloudflare 等 CDN，`transport: "ws"`）
- [x] HTTP/2 cover（h2 ALPN + `x/net/http2.ServeConn`）
- [x] 载波会话最大存活时间 + 渐次排空（`max_lifetime_sec`）
- [x] 帧间到达时间抖动（`iat_max_ms`，模糊时序指纹）
- [x] 会话级 buffer pool（消除每帧堆分配）
- [x] profile 整形库（web/video/download 画像 + 概率性 cover 注入）
- [x] 可选 Noise 握手（`handshake: "noise"`，flynn/noise，Noise_IKpsk1）
- [x] UDP relay（SOCKS UDP ASSOCIATE + UDP over stream）
- [x] 订阅分发与密钥轮换、per-CID 配额与审计（管理 API `admin.listen`）
- [x] 桌面原生 TUN 全局模式（Linux /dev/net/tun + macOS utun + Windows wintun，gVisor netstack 用户态 TCP/IP 栈，`tun` 配置块）
- [x] WebRTC/IPv6 防泄露（TUN 接管 IPv6 + UDP 封帧、浏览器 WebRTC 策略、路由器 STUN 规则，§7.11）
- [x] 流首填充（对抗 TLS-in-TLS 长度特征，默认开启）
- [x] 多出口故障切换与回切、拨号退避
- [x] 管理 API 持久化（`credentials_file`）、按日配额强制执行、Prometheus `/metrics`
- [x] QUIC 入口改为真实 HTTP/3 站点 + 回落（§7.14）
- [x] 计量落盘（`stats_file`）
- [x] 持久 kill-switch（nftables / pf / Windows 防火墙，§7.15）
- [ ] QUIC 原生数据报承载 UDP
- [ ] 第三方密码学审计
