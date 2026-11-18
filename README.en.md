# Prism

[![Test](https://github.com/Gloridust/prism/actions/workflows/test.yml/badge.svg)](https://github.com/Gloridust/prism/actions/workflows/test.yml)

[简体中文](README.md) | English

**Prism is an encrypted tunnel for companies: it routes the traffic of every office and remote employee through the company's own egress server abroad.**

On the wire it looks like an ordinary HTTPS visit to your company's website.

```
Office router    ─┐
Home office PC   ─┼──►  Prism egress server (e.g. Singapore)  ──►  Internet
Travel laptop    ─┘
```

## Why Prism

- **Hard to fingerprint**: traffic is indistinguishable from normal HTTPS and mimics Chrome's TLS handshake; no fixed pattern to match.
- **Resists active probing**: anyone without a credential just sees a real website.
- **No IP leaks**: built-in DNS, WebRTC and IPv6 leak protection, plus an optional kill switch that cuts the network instead of falling back to a direct connection if the client dies.
- **Built for operations**: one credential per device, revocable, rotatable and quota-limited at any time; Prometheus metrics; automatic failover between egress servers.
- **Every platform**: OpenWrt routers (a whole office with zero per-device setup), macOS, Windows, Linux.
- **Several carriers**: TLS, WebSocket (works through CDNs) and HTTP/3, to suit each network.
- **Easy to deploy**: a single binary, automatic certificates, one command to generate keys and configs.

Prism takes the strong points of Trojan, REALITY, VLESS-Vision, Hysteria2 and others; see the comparison in [the protocol spec §0.1](docs/PROTOCOL.md#01-取长补短与主流协议逐项对照).

## Install

Download a build for your platform from [Releases](https://github.com/Gloridust/prism/releases), or build from source (Go 1.27+):

```bash
make all
```

## Quick start

**1. Egress server**

```bash
./prism-server keygen sg.example.com   # writes server.json and client.json
./prism-server -c server.json
```

Enable `acme` in `server.json` for automatic certificates, and point `cover_backend` at a real website.

**2. Clients**

- **Office router (OpenWrt)**: install `prism-client` and let Nikki/Mihomo route traffic into it; the whole office is covered.
- **macOS / Windows**: put `prism-client`, `client.json` and the launcher script in one folder, double-click the launcher and press "Connect" in the control panel.

Step-by-step instructions: [docs/INSTALL.md](docs/INSTALL.md).

## Documentation

The detailed documentation is in Chinese.

| Document | Contents |
|---|---|
| [Install & quick start](docs/INSTALL.md) | Your first tunnel, from scratch |
| [Deployment & operations](docs/DEPLOY.md) | Production checklist, credentials, monitoring, upgrades, troubleshooting |
| [Configuration reference](docs/CONFIG.md) | Every server and client option |
| [Security](docs/SECURITY.md) | Security model, known limitations, reporting vulnerabilities |
| [Protocol specification](docs/PROTOCOL.md) | Byte-level design of the handshake, framing and multiplexing |
| [Development](docs/DEVELOPMENT.md) | Code layout, building, testing |

## Please note

- Prism has not had an independent cryptographic audit and has not been proven over time on a real censoring network. Read [the security notes](docs/SECURITY.md) before relying on it in high-risk settings.
- Make sure your deployment complies with the laws and regulations of every place you operate in.
