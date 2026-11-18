package main

import (
	"encoding/json"
	"fmt"
	"net"
	"os"

	"github.com/gloridust/prism/pkg/prism"
)

// ClientConfig is the client JSON config (see config/client.example.json).
type ClientConfig struct {
	Server          string `json:"server"`            // SG "host:port"
	SNI             string `json:"sni"`               // TLS ServerName (your domain)
	ServerPublicKey string `json:"server_public_key"` // base64 X25519
	ID              string `json:"id"`                // base64 4 bytes
	PSK             string `json:"psk"`               // base64 32 bytes
	AllowInsecure   bool   `json:"allow_insecure"`    // skip cert verify (testing/self-signed)

	// Steal enables REALITY-style active probing resistance. When true, the
	// client embeds an HMAC tag (derived from the PSK) in the TLS session_id
	// so the server can distinguish it from probers before completing TLS.
	// Implies allow_insecure (the outer TLS cert is ephemeral; real auth is
	// the Prism inner handshake).
	Steal bool `json:"steal"`

	// Transport selects the carrier transport layer:
	//   ""    / "tls" : raw TLS (default, current behaviour).
	//   "ws"         : WebSocket over TLS — the Prism handshake runs inside a
	//                  WS binary stream, letting the carrier traverse CDN infra
	//                  (Cloudflare, etc.) that only proxies HTTP.
	//   "quic"       : QUIC/H3 — native HTTP/3 disguise + per-stream congestion
	//                  control at the transport layer.
	Transport string `json:"transport"`

	// WSPath is the HTTP path the server exposes for WebSocket upgrade (must
	// match the server's ws_path). Only used when transport="ws".
	WSPath string `json:"ws_path"`

	// Cipher selects the carrier AEAD: "aes-256-gcm" (default) or
	// "chacha20-poly1305". Routers without AES-NI (MIPS / older ARM) should use
	// chacha. Empty falls back to the build default (see cipher_default*.go: a
	// firmware image can be compiled with -tags prism_chacha to default to
	// ChaCha). Whatever is chosen must be in the server's enabled "ciphers".
	Cipher string `json:"cipher"`

	// Shaping enables egress length-shaping: "pad" rounds small frames up to
	// fixed sizes to mask inner record lengths; "" / "none" disables it (default).
	Shaping string `json:"shaping"`

	// IATMaxMs enables inter-arrival time shaping: each small outgoing frame is
	// preceded by a random delay of 0–IATMaxMs milliseconds. This blurs per-frame
	// timing patterns that could distinguish Prism from ordinary HTTPS. 0 disables.
	IATMaxMs int `json:"iat_max_ms"`

	// Mode selects the deployment shape:
	//   "router"  : SOCKS5 only, for OpenWrt + Nikki to route into.
	//   "desktop" : SOCKS5 + HTTP proxy + auto system proxy + control panel.
	Mode string `json:"mode"`

	SocksListen string `json:"socks_listen"` // default 127.0.0.1:1080
	HTTPListen  string `json:"http_listen"`  // default 127.0.0.1:1081 (desktop)
	PanelListen string `json:"panel_listen"` // default 127.0.0.1:9797 (desktop)
	PoolSize    int    `json:"pool_size"`    // carrier connections, default 4
	AutoConnect *bool  `json:"auto_connect"` // desktop: set system proxy on start (default true)

	// MaxLifetimeSec caps each carrier session's lifetime in seconds. After this
	// duration the session drains: existing streams continue, but new streams use
	// a fresh session. Rotating carriers limits the amount of traffic under one
	// set of session keys and masks long-lived connection patterns. 0 (default)
	// means no limit.
	MaxLifetimeSec int `json:"max_lifetime_sec"`

	// ECH enables Encrypted Client Hello. Set to "auto" to fetch the ECH
	// config list from DNS HTTPS records via DoH at startup, or to a base64
	// ECHConfigList to use a fixed config. Empty (default) disables ECH.
	ECH string `json:"ech"`

	// ECHDoH overrides the DNS-over-HTTPS resolver used when ECH is "auto".
	// Default: "https://1.1.1.1/dns-query".
	ECHDoH string `json:"ech_doh"`

	// Handshake selects the inner handshake protocol: "" / "legacy" uses the
	// hand-rolled Noise-IK-flavoured handshake; "noise" uses the audited
	// flynn/noise Noise_IKpsk2 implementation.
	Handshake string `json:"handshake"`

	// WebRTCGuard (desktop mode, default true) sets browser WebRTC IP-handling
	// policy while connected so WebRTC can't reveal the real public/LAN address:
	// Chrome/Edge/Brave get disable_non_proxied_udp in system-proxy mode and
	// default_public_interface_only in TUN mode; Firefox gets equivalent prefs.
	WebRTCGuard *bool `json:"webrtc_guard"`

	// DNS configures DNS leak prevention. When enabled, a local DNS proxy
	// intercepts queries and forwards them through the Prism tunnel.
	DNS *DNSConfig `json:"dns"`

	// TUN enables global (TUN device) mode. When set, a TUN device is created
	// and all system traffic is routed through Prism. Requires root/admin.
	TUN *TUNConfig `json:"tun"`
}

// DNSConfig configures the DNS leak prevention proxy.
type DNSConfig struct {
	// Listen is the local address for the DNS proxy (default "127.0.0.1:53").
	Listen string `json:"listen"`
	// Upstream is the DNS server on the exit node (default "1.1.1.1:53").
	Upstream string `json:"upstream"`
}

// TUNConfig configures the TUN global mode.
type TUNConfig struct {
	DeviceName  string `json:"device_name"`  // e.g. "prism0" (default)
	Address     string `json:"address"`      // TUN IP, e.g. "10.0.85.1/24"
	Gateway     string `json:"gateway"`      // peer IP for point-to-point, e.g. "10.0.85.2"
	OrigGateway string `json:"orig_gateway"` // original default gateway for server route
	SetRoutes   *bool  `json:"set_routes"`   // auto-configure default route (default true)
}

func (c *ClientConfig) defaults() {
	if c.Mode == "" {
		c.Mode = "desktop"
	}
	if c.SocksListen == "" {
		c.SocksListen = "127.0.0.1:1080"
	}
	if c.HTTPListen == "" {
		c.HTTPListen = "127.0.0.1:1081"
	}
	if c.PanelListen == "" {
		c.PanelListen = "127.0.0.1:9797"
	}
	if c.PoolSize <= 0 {
		c.PoolSize = 4
	}
}

func (c *ClientConfig) autoConnect() bool {
	return c.AutoConnect == nil || *c.AutoConnect
}

func (c *ClientConfig) webrtcGuard() bool {
	return c.WebRTCGuard == nil || *c.WebRTCGuard
}

func (c *ClientConfig) tunSetRoutes() bool {
	return c.TUN != nil && (c.TUN.SetRoutes == nil || *c.TUN.SetRoutes)
}

// pinServerIPv4 resolves server "host:port" to a single IPv4 "ip:port".
func pinServerIPv4(server string) (string, error) {
	host, port, err := net.SplitHostPort(server)
	if err != nil {
		return "", fmt.Errorf("server %q: %w", server, err)
	}
	if ip := net.ParseIP(host); ip != nil {
		if ip.To4() == nil {
			return "", fmt.Errorf("TUN mode needs an IPv4 server address, got %s", host)
		}
		return server, nil
	}
	ips, err := net.LookupIP(host)
	if err != nil {
		return "", fmt.Errorf("resolve %s: %w", host, err)
	}
	for _, ip := range ips {
		if v4 := ip.To4(); v4 != nil {
			return net.JoinHostPort(v4.String(), port), nil
		}
	}
	return "", fmt.Errorf("%s has no IPv4 address (TUN mode routes the carrier over IPv4)", host)
}

// cipher resolves the configured cipher name, falling back to the build default
// (defaultCipher) when the config leaves it unset.
func (c *ClientConfig) cipher() string {
	if c.Cipher == "" {
		return defaultCipher
	}
	return c.Cipher
}

func loadClientConfig(path string) (*ClientConfig, *prism.Credential, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}
	var c ClientConfig
	if err := json.Unmarshal(raw, &c); err != nil {
		return nil, nil, fmt.Errorf("parsing %s: %w", path, err)
	}
	c.defaults()
	id, err := prism.ParseClientID(c.ID)
	if err != nil {
		return nil, nil, fmt.Errorf("id: %w", err)
	}
	psk, err := prism.DecodeKey(c.PSK)
	if err != nil {
		return nil, nil, fmt.Errorf("psk: %w", err)
	}
	return &c, &prism.Credential{ID: id, PSK: psk}, nil
}
