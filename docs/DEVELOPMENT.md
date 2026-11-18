# 开发指南

## 目录结构

```
pkg/prism/          协议核心：握手（默认 / Noise）、密钥派生、AEAD 分帧、多路复用与流控、
                    重放保护、steal 标记、HTTP/3 载波、UDP 封帧
cmd/prism-server/   出口服务器：TLS / ACME、鉴权、出口转发、回落站点、steal、
                    WebSocket / HTTP/3 入口、管理 API、计量
cmd/prism-client/   客户端：uTLS 载波、多出口切换、SOCKS5 / HTTP 代理、控制面板、
                    系统代理与 DNS、TUN（gVisor）、WebRTC 防护、kill-switch
cmd/prism-keygen/   凭据生成
config/             配置样例、Mihomo 片段、浏览器策略
scripts/            systemd unit、OpenWrt init、桌面启动器、kill-switch 重启测试
test/               真实二进制端到端测试
docs/               文档
```

## 构建

需要 Go 1.27+。

```bash
make all                 # 测试 + 本机构建，产物在 dist/
make server-linux-amd64  # 交叉编译示例，全部目标见 Makefile
make VERSION=1.0.0 all   # 指定版本号（写入 -version 输出）
```

推送 `v*` 标签会触发 [`release.yml`](../.github/workflows/release.yml)，构建全部平台并创建 GitHub Release。

## 测试

```bash
go test -race ./...      # 单元 + 进程内端到端 + 真实二进制端到端
go test -short ./...     # 跳过需要编译二进制的用例
go test ./pkg/prism/ -run '^$' -fuzz '^FuzzDispatch$' -fuzztime 30s   # 模糊测试，可换任一 Fuzz 目标
```

[`test/binary_e2e_test.go`](../test/binary_e2e_test.go) 会编译 `prism-server` 与 `prism-client`，按实际部署方式验证：

- TLS / WebSocket / QUIC × 两种握手 × 两种加密算法
- steal 模式、回落站点（含探测洪泛）
- 管理 API 全流程：鉴权、统计、新增、配额、吊销踢线、持久化
- 主备出口切换、错误配置在启动时被拒绝

设置 `PRISM_E2E_LOGS=1` 可打印两端日志。

需要 root 或真实环境的测试：

| 测试 | 运行方式 |
|---|---|
| TUN 捕获、kill-switch | CI 中以 root 在独立网络命名空间运行，见 [`test.yml`](../.github/workflows/test.yml) |
| WebRTC 防护（真实 Chrome / Edge / Firefox） | `webrtc_browser_test.go`，本机装有对应浏览器时运行 |
| kill-switch 开机恢复 | `scripts/test-killswitch-reboot.sh`，在 docker 中启动一台 systemd 机器并真实重启 |

CI 在 Linux、macOS、Windows 三个平台上运行全部测试。

## 依赖

协议核心 `pkg/prism` 尽量只用标准库。以下依赖是标准库无法替代的：

| 依赖 | 用途 |
|---|---|
| `github.com/refraction-networking/utls` | 客户端模拟 Chrome 的 TLS ClientHello，避免 Go `crypto/tls` 的指纹 |
| `golang.org/x/crypto` | ChaCha20-Poly1305；ACME 自动证书 |
| `golang.org/x/net` | 回落站点的 HTTP/2 |
| `golang.zx2c4.com/wintun` | Windows 的 TUN 设备 |
| `github.com/flynn/noise` | Noise_IKpsk1 握手 |
| `github.com/quic-go/quic-go` | HTTP/3 载波 |
| `github.com/sagernet/gvisor` | TUN 模式的用户态 TCP/IP 栈 |

全部为纯 Go，交叉编译不需要 CGO。离线构建前先执行 `go mod vendor`。

## 线格式兼容性

修改以下内容会让新旧版本无法互通，必须在 PR 中写明，并在发布说明里提示两端同时升级：

- 两种握手的消息格式与密钥派生
- steal 标记格式
- 帧格式、UDP 封帧
- HTTP/3 与 WebSocket 载波的请求格式

规范以 [PROTOCOL.md](PROTOCOL.md) 为准，修改实现时同步更新。
