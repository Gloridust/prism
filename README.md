# Prism

[![Test](https://github.com/Gloridust/prism/actions/workflows/test.yml/badge.svg)](https://github.com/Gloridust/prism/actions/workflows/test.yml)

简体中文 | [English](README.en.md)

**Prism 是一套面向企业的加密隧道，把分布在各地的办公室和远程员工，统一经由公司自己的境外出口访问互联网。**

在网络上，它看起来就是一次访问你公司网站的普通 HTTPS 连接。

```
办公室路由器 ─┐
在家办公电脑 ─┼──►  Prism 出口服务器（如新加坡） ──►  互联网
出差笔记本   ─┘
```

## 为什么选择 Prism

- **难以识别**：流量与正常 HTTPS 无异，模拟 Chrome 浏览器的连接特征，没有可供识别的固定特征。
- **抗主动探测**：没有凭据的访问者只会看到一个真实的网站，无法判断背后有隧道。
- **不泄露真实 IP**：内置 DNS、WebRTC、IPv6 防泄露；可选 kill-switch，客户端意外退出时断网而不是直连。
- **企业级运维**：每台设备独立凭据，可随时吊销、轮换、限额；Prometheus 监控；多出口自动故障切换。
- **全平台**：OpenWrt 路由器（整个办公室免配置）、macOS、Windows、Linux。
- **多种入口**：TLS、WebSocket（可经 CDN）、HTTP/3，按网络环境选择。
- **部署简单**：单个二进制，证书自动签发，一条命令生成密钥与配置。

Prism 借鉴了 Trojan、REALITY、VLESS-Vision、Hysteria2 等协议各自的长处，详细对照见 [协议规范 §0.1](docs/PROTOCOL.md#01-取长补短与主流协议逐项对照)。

## 安装

从 [Releases](https://github.com/Gloridust/prism/releases) 下载对应平台的程序，或从源码构建（Go 1.27+）：

```bash
make all
```

## 快速开始

**1. 出口服务器**

```bash
./prism-server keygen sg.example.com   # 生成 server.json 和 client.json
./prism-server -c server.json
```

在 `server.json` 中开启 `acme` 自动证书，并把 `cover_backend` 指向一个真实网站。

**2. 客户端**

- **办公室路由器（OpenWrt）**：安装 `prism-client` 后由 Nikki/Mihomo 分流，整个办公室即可使用。
- **macOS / Windows**：把 `prism-client`、`client.json` 和启动脚本放在一起，双击启动，在弹出的控制面板中点“连接”。

完整步骤见 [安装与快速上手](docs/INSTALL.md)。

## 文档

| 文档 | 内容 |
|---|---|
| [安装与快速上手](docs/INSTALL.md) | 从零跑通第一条隧道 |
| [部署与运维](docs/DEPLOY.md) | 生产上线清单、凭据管理、监控、升级、排障 |
| [配置参考](docs/CONFIG.md) | 服务端与客户端全部配置项 |
| [安全说明](docs/SECURITY.md) | 安全模型、已知局限、漏洞报告 |
| [协议规范](docs/PROTOCOL.md) | 握手、分帧、多路复用等字节级设计 |
| [开发指南](docs/DEVELOPMENT.md) | 代码结构、构建、测试 |

## 注意

- Prism 尚未经过独立的第三方密码学审计，也未在真实审查网络中长期验证。用于高风险场景前，请先阅读 [安全说明](docs/SECURITY.md)。
- 请确认你的部署符合各运营地的法律法规与公司合规要求。
