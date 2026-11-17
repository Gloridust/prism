package main

import (
	"crypto/ecdh"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/gloridust/prism/pkg/prism"
)

// Config is the server JSON config (see config/server.example.json).
type Config struct {
	Listen string `json:"listen"` // e.g. ":443"

	// TLS for the outer carrier. Precedence: ACME (automatic Let's Encrypt) >
	// cert_file+key_file (e.g. a certbot-issued cert) > self_signed (TESTING
	// ONLY — it will not survive a careful probe).
	ACME       *ACMEConfig `json:"acme"`
	CertFile   string      `json:"cert_file"`
	KeyFile    string      `json:"key_file"`
	SelfSigned string      `json:"self_signed"` // domain to self-sign for LOCAL TESTING only

	// Prism identity.
	PrivateKey  string       `json:"private_key"` // base64 X25519 server private
	Credentials []CredConfig `json:"credentials"`

	// Ciphers lists the carrier AEADs this server accepts, in trial-decrypt
	// order: "aes-256-gcm" and/or "chacha20-poly1305". Empty defaults to
	// ["aes-256-gcm"]. List both to serve a mixed fleet (AES-NI desktops +
	// ChaCha routers) from one endpoint; a client's chosen cipher must appear
	// here. The on-wire format is identical for both, so this is a pure
	// server-side policy with no handshake tell.
	Ciphers []string `json:"ciphers"`

	// AllowPrivate permits egress to private/loopback/link-local targets. Default
	// false blocks them (anti-SSRF): a credentialed client otherwise could reach
	// the egress box's own localhost, the internal network, or cloud metadata
	// (169.254.169.254). Enable only if clients legitimately need the egress
	// box's own network (e.g. an internal service behind it).
	AllowPrivate bool `json:"allow_private"`

	// Shaping enables egress length-shaping ("pad" or "none", default none).
	Shaping string `json:"shaping"`

	// MaxStreams caps concurrent streams per carrier (memory safety). 0 uses the
	// built-in default (1024); a negative value means unlimited.
	MaxStreams int `json:"max_streams"`

	// Steal enables REALITY-style active probing resistance. When set, the
	// server inspects raw ClientHellos: authenticated clients (HMAC tag in
	// session_id derived from PSK) are handled as Prism carriers; everyone
	// else has their TCP connection relayed transparently to Dest, so a prober
	// sees the real site's certificate. Mutually exclusive with ACME/cert_file
	// (steal generates an ephemeral cert for authenticated clients; the real
	// target's cert is what probers see).
	Steal *StealConfig `json:"steal"`

	// Anti-replay / freshness.
	WindowSeconds int `json:"window_seconds"` // default 120

	// WSPath enables WebSocket transport at the given path (e.g. "/_prism/ws").
	// When set, clients that upgrade to WebSocket on this path run the Prism
	// handshake inside the WS stream, letting the carrier traverse CDN infra
	// (Cloudflare, etc.) that only proxies HTTP. Regular TLS carriers and cover
	// traffic coexist on the same port — only the exact path triggers the
	// upgrade. Leave empty to disable.
	WSPath string `json:"ws_path"`

	// Handshake selects the inner handshake protocol: "" / "legacy" uses the
	// hand-rolled handshake; "noise" uses the audited flynn/noise Noise_IKpsk2.
	// Both ends must use the same handshake.
	Handshake string `json:"handshake"`

	// Admin enables the management API for credential CRUD, key rotation,
	// per-CID quota and traffic stats.
	Admin *AdminConfig `json:"admin"`

	// QUICListen enables a QUIC/H3 listener on this address (e.g. ":443").
	// QUIC runs over UDP on the same port as TLS/TCP, giving clients an HTTP/3
	// carrier with per-stream congestion control. Leave empty to disable.
	QUICListen string `json:"quic_listen"`

	// Cover: what an unauthenticated visitor (or active prober) sees.
	// Exactly one is used, in this order: Backend, then StaticDir, then a
	// built-in placeholder page.
	CoverBackend   string `json:"cover_backend"`    // reverse-proxy target, e.g. http://127.0.0.1:8080
	CoverStaticDir string `json:"cover_static_dir"` // serve files from a directory
}

// CredConfig is one provisioned client.
type CredConfig struct {
	ID   string `json:"id"`  // base64 4 bytes
	PSK  string `json:"psk"` // base64 32 bytes
	Name string `json:"name"`
}

// ACMEConfig enables automatic certificate issuance and renewal from Let's
// Encrypt (or any ACME CA) via the TLS-ALPN-01 challenge, which needs nothing
// but this server's existing :443 listener — no port 80, no separate web
// server. The box must be reachable from the internet on 443 at each domain.
type ACMEConfig struct {
	Enabled bool     `json:"enabled"`
	Domains []string `json:"domains"` // every SNI this server answers to
	Email   string   `json:"email"`   // optional, for CA expiry notices

	// CacheDir persists issued certs/keys across restarts (default
	// /etc/prism/acme). Back it up or at least keep it on stable storage so you
	// don't re-hit Let's Encrypt rate limits on every redeploy.
	CacheDir string `json:"cache_dir"`

	// DirectoryURL overrides the ACME directory. Leave empty for Let's Encrypt
	// production; point it at the staging directory
	// (https://acme-staging-v02.api.letsencrypt.org/directory) while testing to
	// avoid burning production rate limits.
	DirectoryURL string `json:"directory_url"`
}

func (c *Config) window() time.Duration {
	if c.WindowSeconds <= 0 {
		return 120 * time.Second
	}
	return time.Duration(c.WindowSeconds) * time.Second
}

func loadConfig(path string) (*Config, *ecdh.PrivateKey, []prism.Credential, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, nil, err
	}
	var c Config
	if err := json.Unmarshal(raw, &c); err != nil {
		return nil, nil, nil, fmt.Errorf("parsing %s: %w", path, err)
	}
	if c.Listen == "" {
		c.Listen = ":443"
	}
	priv, err := prism.ParseServerPrivate(c.PrivateKey)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("private_key: %w", err)
	}
	var creds []prism.Credential
	for i, cc := range c.Credentials {
		id, err := prism.ParseClientID(cc.ID)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("credentials[%d].id: %w", i, err)
		}
		psk, err := prism.DecodeKey(cc.PSK)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("credentials[%d].psk: %w", i, err)
		}
		creds = append(creds, prism.Credential{ID: id, PSK: psk, Name: cc.Name})
	}
	if len(creds) == 0 {
		return nil, nil, nil, fmt.Errorf("no credentials configured")
	}
	return &c, priv, creds, nil
}
