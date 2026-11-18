# 安装与快速上手

本文带你从零跑通一条隧道：一台出口服务器 + 一个客户端（路由器或桌面）。
上线到生产环境前，请再读 [部署与运维手册](DEPLOY.md)。

- [1. 获取程序](#1-获取程序)
- [2. 出口服务器](#2-出口服务器)
- [3. 客户端：办公室路由器](#3-客户端办公室路由器)
- [4. 客户端：macOS / Windows 桌面](#4-客户端macos--windows-桌面)
- [5. 验证](#5-验证)

---

## 1. 获取程序

### 下载预编译版本

在 [Releases](https://github.com/Gloridust/prism/releases) 页面下载对应平台的文件：

| 文件 | 用途 |
|---|---|
| `prism-server-linux-amd64` / `-arm64` | 出口服务器 |
| `prism-client-linux-arm64` / `-mipsle` / `-mips` | OpenWrt 路由器（按 CPU 选） |
| `prism-client-linux-mipsle-chacha` / `-mips-chacha` | 无 AES 硬件加速的路由器，默认使用 ChaCha20 |
| `prism-client-darwin-arm64` / `-amd64` | macOS（Apple Silicon / Intel） |
| `prism-client-windows-amd64.exe` + `wintun.dll` | Windows（`wintun.dll` 仅 TUN 模式需要，放在同一目录） |
| `prism-client-linux-amd64` | Linux 桌面 |
| `prism-keygen-*` | 生成客户端凭据 |
| `prism-configs-scripts.tar.gz` | 配置样例与启动脚本 |

### 从源码构建

需要 Go 1.27+。所有依赖都是纯 Go，交叉编译不需要 CGO。

```bash
make all                     # 本机构建 + 运行测试，产物在 dist/
make server-linux-amd64      # 出口服务器
make client-linux-arm64      # 路由器（也有 mipsle / mips / *-chacha）
make client-darwin-arm64     # Apple Silicon Mac
make client-windows-amd64    # Windows（会一并下载 wintun.dll）
```

离线环境：先在能联网的机器上 `go mod vendor`，再把整个目录带过去构建。

---

## 2. 出口服务器

前提：一台境外 Linux 服务器、一个解析到它的域名、TCP 443 可达。

**第 1 步：生成密钥和配置模板**

```bash
./prism-server keygen sg.example.com
```

会输出可直接使用的 `server.json` 和 `client.json`。服务器私钥只留在这台机器上。

**第 2 步：配置证书**（三选一，优先级 `acme` > `cert_file`/`key_file` > `self_signed`）

- **`acme`（推荐）**：自动签发并续期 Let's Encrypt 证书，只用 443 端口，不需要 80 端口。

  ```json
  "acme": { "enabled": true, "domains": ["sg.example.com"], "email": "ops@example.com" }
  ```
  第一次调试时可把 `directory_url` 设为 `https://acme-staging-v02.api.letsencrypt.org/directory`，避免触发正式环境的签发频率限制。
- **`cert_file` + `key_file`**：使用自己签发的证书（如 certbot），续期后 `systemctl restart prism-server`。
- **`self_signed`**：仅限本地测试，启动时会打印警告。

**第 3 步：配置回落站点**

把 `cover_backend` 指向一个真实的网站（例如本机 8080 端口上的公司官网或任意 Web 应用）。没有凭据的访问者和探测器看到的就是它。

**第 4 步：启动**

```bash
./prism-server -c server.json -check   # 校验配置
./prism-server -c server.json
```

用 systemd 长期运行（推荐）见 [DEPLOY.md §3.1](DEPLOY.md#31-安装)。

**添加更多客户端**：每个办公室、每台设备一条凭据，不要共用。

```bash
./prism-keygen client office-shanghai   # 输出该设备的 id 与 psk
```

把它作为 `{"name": "office-shanghai", "id": "…", "psk": "…"}` 加进服务器的 `credentials`，再把 `id`、`psk` 和服务器公钥发给对应设备。也可以用[管理 API](DEPLOY.md#4-凭据生命周期管理-api) 在线增删，无需重启。

---

## 3. 客户端：办公室路由器

适用于 OpenWrt + Nikki/Mihomo：路由器上的 prism-client 提供一个本地 SOCKS5 入口，Mihomo 按规则把需要出境的流量送进来，整个办公室无需逐台配置。

```bash
# 在路由器上执行
cp prism-client /usr/bin/ && chmod +x /usr/bin/prism-client
mkdir -p /etc/prism && cp client-router.json /etc/prism/client.json
cp scripts/openwrt-prism-client.init /etc/init.d/prism-client
chmod +x /etc/init.d/prism-client
/etc/init.d/prism-client enable && /etc/init.d/prism-client start
```

然后把 [`config/nikki-mihomo.example.yaml`](../config/nikki-mihomo.example.yaml) 的片段并入 Mihomo 配置：它定义了指向 `127.0.0.1:1080` 的出站 `PRISM-SG`。其中 **IPv6 处理** 和 **STUN 规则前置** 两处用于防止泄露办公室真实 IP，不要省略。

> 无 AES 硬件加速的路由器（MIPS、老 ARM）：使用 `-chacha` 版本，或在 `client.json` 里设 `"cipher": "chacha20-poly1305"`。服务器的 `ciphers` 需要包含该算法。

---

## 4. 客户端：macOS / Windows 桌面

适用于在家或出差的员工。把以下文件放在同一个文件夹：

- `prism-client`（Windows 为 `prism-client.exe`）
- `client.json`（由 [`config/client-desktop.example.json`](../config/client-desktop.example.json) 修改而来）
- 启动器：`scripts/start-macos.command` 或 `scripts/start-windows.bat`

然后：

- **macOS**：首次执行 `chmod +x start-macos.command`，之后双击启动。
- **Windows**：双击 `start-windows.bat`。

浏览器会打开控制面板 `http://127.0.0.1:9797`，点“连接”即可。客户端会自动设置系统代理，退出时还原。

**需要全局接管（所有应用，含 Zoom / Teams 等原生应用的 UDP）** 时，使用 TUN 模式：在 `client.json` 里配置 `tun` 块并以管理员权限运行。建议同时打开 `kill_switch`，客户端意外退出时断网而不是回到直连。详见 [DEPLOY.md §6.2](DEPLOY.md#62-桌面macos--windows)。

---

## 5. 验证

| 检查 | 预期 |
|---|---|
| 浏览器直接打开 `https://sg.example.com/` | 看到你的回落网站，没有任何异常 |
| 客户端连接后访问 `https://ifconfig.me` | 显示出口服务器的 IP |
| 在 [browserleaks.com/webrtc](https://browserleaks.com/webrtc) 检查 WebRTC | 只出现出口服务器的 IP（需在客户端连接后重启浏览器） |
| 服务端日志 | 每次客户端接入有一条带凭据名称的 `connected` 记录 |

连不上时，先看 [DEPLOY.md §8 排障](DEPLOY.md#8-排障)。
