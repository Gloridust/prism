# Prism 协议规范 v1

> Prism 是一套为企业自建流量出口设计的、认证加密的隧道协议。
> 它是**原创 wire-level 协议**，不是对 VLESS / Trojan / REALITY 等协议的二次开发。
> 密码学原语全部采用成熟标准件（X25519 / AES-256-GCM / HKDF-SHA256），
> 原创性体现在握手编排、认证模型、抗主动探测、分帧、流量整形与多路复用等协议层设计上。

本文件是**权威规范**，参考实现（`pkg/prism`）必须与之一致。

---

## 0. 设计目标与威胁模型

部署形态：公司在**出口服务器（新加坡）**运行 `prism-server`，各办公室/员工端运行 `prism-client`，
所有被选中的流量经 Prism 隧道汇聚到出口服务器后再访问互联网。出口服务器是公司**唯一流量出口**。

威胁模型（Threat Model）：

| 能力 | 攻击者（无公司 PSK） | 说明 |
|---|---|---|
| 被动观测（Passive DPI） | 看到的是**均匀随机字节流**，无明文特征、无 TLS 指纹、无固定字节头 | 握手首包起整条流不可区分于随机 |
| 主动探测（Active Probing） | 向服务器发任意/随机/重放数据，**得不到任何可区分响应** | 认证失败走“诱饵/沉默”策略（见 §7） |
| 流量分析（长度/时序） | 握手为**定长**；数据记录长度被加密隐藏，支持填充与掩护流量 | 见 §5、§8 |
| 重放（Replay） | 重放旧握手被拒 | 时间戳窗口 + 临时公钥去重（见 §4.4） |
| 密钥泄露（前向保密） | 泄露长期私钥**无法解密历史会话** | 每会话 ECDHE（见 §4） |

**非目标**：Prism 不声称能抵抗拥有公司 PSK 的内部攻击者，也不是匿名网络（出口可见真实目的地）。
它解决的是“企业把自有流量安全、抗干扰地汇聚到自有出口”的问题。

---

## 1. 密码学套件（Cipher Suite v1）

| 用途 | 算法 |
|---|---|
| 密钥协商 | X25519（`crypto/ecdh`） |
| AEAD | AES-256-GCM（12 字节 nonce，16 字节 tag） |
| 哈希 / 握手摘要 | SHA-256 |
| KDF | HKDF-SHA256（Extract + Expand，自实现） |
| 混淆键流（Obfuscation） | AES-256-CTR |

套件标识字符串（协议域分隔符）：

```
Prism_IKpsk_25519_AESGCM_SHA256_v1
```

所有 KDF 的 info 都带独立常量标签，避免跨上下文密钥复用。

---

## 2. 密钥与身份

- **PSK（公司预共享密钥，32 字节）**：全公司一把，用于①混淆键流②绑定握手摘要。
  缺少 PSK 的攻击者无法构造合法握手，也无法把流量去混淆。
- **服务器静态密钥对 `(S_priv, S_pub)`**（X25519）：客户端内置 `S_pub`。
- **客户端静态密钥对 `(C_priv, C_pub)`**（X25519）：即“用户身份”。服务器维护**允许的 `C_pub` 列表**，
  按条目即可授权/吊销单个用户，无需改动 PSK。

密钥编码：32 字节原始值的 **Base64URL(no padding)** 文本，便于配置文件书写。

---

## 3. 符号与基础运算

- `X25519(priv, pub)` → 32 字节共享密钥（低阶点/全零结果由标准库判错）。
- `HKDF(salt, ikm, info, L)` → L 字节。
- `AEAD_Seal(key, nonce, plaintext, ad)` / `AEAD_Open(...)`：AES-256-GCM。
- `nonce(counter)`：12 字节，前 4 字节 0，后 8 字节 counter 的大端表示。

### 3.1 握手对称状态机（Symmetric State）

借鉴 Noise 的 `MixKey/MixHash` 构造（标准、可证明安全的组合方式），字段：

- `ck`（链接键，32B）、`h`（摘要，32B）、`k`（当前 AEAD 密钥，32B）、`n`（当前 nonce 计数）。

初始化：`ck = h = SHA256("Prism_IKpsk_25519_AESGCM_SHA256_v1")`。

```
MixHash(data):      h = SHA256(h || data)
MixKey(ikm):        tmp = HKDF(salt=ck, ikm=ikm, info="prism-mix", 64)
                    ck = tmp[0:32]; k = tmp[32:64]; n = 0
EncryptAndHash(pt): ct = AEAD_Seal(k, nonce(n), pt, ad=h); n++; MixHash(ct); -> ct
DecryptAndHash(ct): pt = AEAD_Open(k, nonce(n), ct, ad=h); n++; MixHash(ct); -> pt
Split():            tmp = HKDF(salt=ck, ikm="", info="prism-split", 64)
                    return tmp[0:32], tmp[32:64]
```

---

## 4. 握手（Prism Handshake, PHS）

模式为 **IK + PSK**：发起方（客户端）预先知道响应方（服务器）静态公钥；
双方都用各自静态密钥参与，实现**双向认证 + 发起方身份隐藏 + 前向保密 + 1-RTT**。

预置（两端一致）：
```
InitSymState()
MixHash(PSK)          // 绑定公司密钥
MixHash(S_pub)        // 预消息：已知响应方静态公钥
```

### 4.1 Message 1（Client → Server），token 序列 `e, es, s, ss`

客户端计算：
```
生成临时密钥 (E_priv, E_pub)
MixHash(E_pub)
MixKey( X25519(E_priv, S_pub) )            // es
encStatic  = EncryptAndHash(C_pub)          // s      (48B = 32 明文 + 16 tag)
MixKey( X25519(C_priv, S_pub) )            // ss
encPayload = EncryptAndHash(Payload1)       // 定长 32 明文 -> 48B
body1 = E_pub(32) || encStatic(48) || encPayload(48)     // 共 128B
```

`Payload1`（32 字节明文）：
```
version(1=0x01) | timestamp(8, 大端 Unix 秒) | flags(1) | pad(22, 随机)
```

### 4.2 线路混淆与成帧

body 不以明文/曲线点形态出现在线路上，而是用 **PSK 键流**整体 XOR：
```
salt_c = 随机 16B
okey = HKDF(PSK, salt_c, "prism-obfs-key", 32)
oiv  = HKDF(PSK, salt_c, "prism-obfs-iv",  16)
wire1 = salt_c(16, 明文随机) || AES256-CTR(okey, oiv, body1)      // 共 144B，定长
```
`salt_c` 随机、CTR 输出随机，故 `wire1` 整体不可区分于随机。
**特别地**：X25519 公钥本身并非均匀随机（可被指纹识别），经 CTR XOR 后在线路上变为均匀随机。

### 4.3 Message 2（Server → Client），token 序列 `e, ee, se`

服务器成功校验 Message 1 后：
```
生成临时密钥 (F_priv, F_pub)
MixHash(F_pub)
MixKey( X25519(F_priv, E_pub) )            // ee
MixKey( X25519(F_priv, C_pub) )            // se
encPayload2 = EncryptAndHash(Payload2)      // 定长 32 明文 -> 48B
body2 = F_pub(32) || encPayload2(48)        // 共 80B

salt_s = 随机 16B
okey2 = HKDF(PSK, salt_s, "prism-obfs-key", 32)
oiv2  = HKDF(PSK, salt_s, "prism-obfs-iv",  16)
wire2 = salt_s(16) || AES256-CTR(okey2, oiv2, body2)             // 共 96B，定长
```
`Payload2`（32B）：`version(1) | flags(1) | pad(30, 随机)`。

### 4.4 服务器校验与重放保护

- `encStatic` / `encPayload` 任一 AEAD 校验失败 → 认证失败（§7）。
- `C_pub` 不在允许列表 → 认证失败。
- `|now - timestamp| > HandshakeWindow`（默认 ±90s）→ 拒绝。
- `E_pub` 在时间窗内已出现过（LRU/布隆去重）→ 拒绝（防重放）。

### 4.5 密钥导出（Split）

握手完成后双方执行 `Split()`：
```
k_c2s, k_s2c = Split()
```
`k_c2s` 用于 Client→Server 方向，`k_s2c` 用于 Server→Client 方向。
会话标识 `session_id = h`（最终握手摘要）。

### 4.6 0-RTT（可选，默认关）

`flags` bit0 置位时，Message 1 的 `encPayload` 后可追加一段 `EncryptAndHash(earlyData)`，
并相应延长 `wire1`（此时放弃定长特性）。默认关闭以优先抗流量分析。

---

## 5. 记录层（Record Layer）

握手后每方向用固定 `k`、独立递增 nonce 计数器加密记录。
为**隐藏真实长度**，每条记录由两段 AEAD 组成：

```
rec = AEAD_Seal(k, nonce(ctr),   uint16_be(len), ad=nil)   // 长度段：2 明文 + 16 tag = 18B
   || AEAD_Seal(k, nonce(ctr+1), payload,        ad=nil)   // 载荷段：len + 16 tag
ctr += 2
```
读取方先读 18B 解出 `len`，再读 `len+16` 解出载荷。单条载荷 `len ∈ [1, 16384]`。
观测者只见连续随机字节，无法从流中还原记录边界或真实长度。

nonce 计数器单向递增，远未触及 2^64 上限，无复用风险。

---

## 6. 多路复用层（Mux）

一条 Prism 记录连接承载多条逻辑流（多个目标），以摊薄握手成本并混合流量特征。
Mux 帧封装在记录层载荷之内：

```
帧头: streamID(uint32_be) | cmd(uint8) | length(uint16_be) | payload[length]
```

| cmd | 名称 | 含义 |
|---|---|---|
| 0x01 | SYN | 新建流；payload = 目标地址（§6.1） |
| 0x02 | PSH | 流数据 |
| 0x03 | FIN | 半关闭（对端不再发数据） |
| 0x04 | RST | 强制关闭 |
| 0x05 | WND | 窗口更新；payload = uint32_be 增量信用 |
| 0x06 | NOP | 保活/填充（payload 可为随机填充） |

流 ID 分配：客户端发起用奇数，服务器发起（保留）用偶数，避免冲突。

### 6.1 目标地址格式（SYN 载荷）

```
atyp(1) | addr | port(uint16_be)
atyp=0x01 IPv4(4B) | atyp=0x03 域名(len(1)+bytes) | atyp=0x04 IPv6(16B)
```

### 6.2 流量控制

每条流初始接收窗口 `InitialWindow`（默认 256KiB）。发送方累计发送字节数不得超过已获得的信用；
接收方每消费数据即回发 `WND` 增量。信用防止单流耗尽缓冲、并提供背压。

---

## 7. 抗主动探测（Anti-Probing）

当 Message 1 校验失败（PSK 错误、AEAD 失败、身份不在列表、时间戳越界、重放）时，
服务器**绝不**返回任何与正常握手可区分的字节或时序。两种可配策略：

- **decoy（诱饵，推荐）**：把已读取的字节原样转发给预配置的真实后端（如本机一台 nginx/一个真实站点），
  并双向拼接，探测者看到的是一个正常服务。
- **reset（沉默重置）**：读尽并静默关闭，表现与通用关闭服务无异。

因为整条首包（含曲线点）均为随机外观，缺少 PSK 的探测者既无法构造合法首包，也无法凭响应区分 Prism。

---

## 8. 流量整形（Traffic Shaping，可选）

- **长度分桶填充**：记录载荷填充到桶边界（如 256/576/1280/1500/4096/16384），削弱基于长度的分析。
- **掩护流量**：空闲时按配置周期发送 `NOP` 记录，打断时序相关性。
默认关闭以优先吞吐；高敏感链路可开启。

---

## 9. 传输层（Transport）

v1 为 **TCP**。传输层被抽象为可插拔接口，后续可加 QUIC/UDP、WebSocket/HTTP(S) 外壳（过 CDN）等，
均不改变 §4–§8 的协议语义。

---

## 10. 常量汇总（默认值）

| 名称 | 值 |
|---|---|
| 套件标识 | `Prism_IKpsk_25519_AESGCM_SHA256_v1` |
| Message 1 定长 | 144 B |
| Message 2 定长 | 96 B |
| HandshakeWindow | ±90 s |
| 记录最大载荷 | 16384 B |
| Mux 初始窗口 | 262144 B |
| 密钥/盐长度 | 32 / 16 B |

---

## 11. 版本协商

版本写在 `Payload1/Payload2` 的 `version` 字段。v1 固定 `0x01`。
不兼容变更递增版本号；服务器可拒绝不支持的版本（走 §7 失败路径以不泄露信息）。
