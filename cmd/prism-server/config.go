package main

import (
	"crypto/ecdh"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
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

	// CredentialsFile, when set, is the writable source of truth for
	// credentials: it is seeded from Credentials on first start, re-read on
	// SIGHUP, and rewritten by the admin API so that added, revoked and rotated
	// credentials survive a restart. It must live somewhere the service can
	// write (e.g. /var/lib/prism/credentials.json).
	CredentialsFile string `json:"credentials_file"`

	// MaxConns caps concurrent inbound TCP connections (authenticated or not),
	// bounding memory and file descriptors under a connection flood. 0 uses the
	// default (4096); negative means unlimited.
	MaxConns int `json:"max_conns"`

	creds []CredConfig // resolved credential list (file or inline)

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
	// MaxBytesPerDay is this client's daily traffic quota (up + down), reset at
	// 00:00 UTC. 0 means unlimited.
	MaxBytesPerDay int64 `json:"max_bytes_per_day,omitempty"`
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
	switch c.Handshake {
	case "", "legacy", "noise":
	default:
		return nil, nil, nil, fmt.Errorf("handshake: unknown value %q (want \"\", \"legacy\" or \"noise\")", c.Handshake)
	}
	if c.Steal != nil && c.Steal.Dest != "" {
		if _, _, err := net.SplitHostPort(c.Steal.Dest); err != nil {
			return nil, nil, nil, fmt.Errorf("steal.dest must be host:port: %w", err)
		}
		if c.ACME != nil && c.ACME.Enabled {
			return nil, nil, nil, fmt.Errorf("steal and acme are mutually exclusive")
		}
	}
	if c.Admin != nil && c.Admin.Listen != "" && len(c.Admin.Token) < 16 {
		return nil, nil, nil, fmt.Errorf("admin.token must be at least 16 characters (an empty token would leave the admin API open)")
	}
	priv, err := prism.ParseServerPrivate(c.PrivateKey)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("private_key: %w", err)
	}
	c.creds, err = loadCredConfigs(&c)
	if err != nil {
		return nil, nil, nil, err
	}
	creds, err := parseCreds(c.creds)
	if err != nil {
		return nil, nil, nil, err
	}
	if len(creds) == 0 && c.CredentialsFile == "" {
		return nil, nil, nil, fmt.Errorf("no credentials configured")
	}
	return &c, priv, creds, nil
}

// loadCredConfigs returns the credential list: the credentials file when one
// is configured (seeding it from the inline list on first start), otherwise
// the inline list.
func loadCredConfigs(c *Config) ([]CredConfig, error) {
	if c.CredentialsFile == "" {
		return c.Credentials, nil
	}
	raw, err := os.ReadFile(c.CredentialsFile)
	if os.IsNotExist(err) {
		if err := saveCredConfigs(c.CredentialsFile, c.Credentials); err != nil {
			return nil, fmt.Errorf("seeding credentials_file: %w", err)
		}
		return c.Credentials, nil
	}
	if err != nil {
		return nil, fmt.Errorf("credentials_file: %w", err)
	}
	var out []CredConfig
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", c.CredentialsFile, err)
	}
	return out, nil
}

// saveCredConfigs atomically replaces the credentials file (0600: it holds PSKs).
func saveCredConfigs(path string, creds []CredConfig) error {
	if creds == nil {
		creds = []CredConfig{}
	}
	raw, err := json.MarshalIndent(creds, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".credentials-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(append(raw, '\n')); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

func parseCreds(ccs []CredConfig) ([]prism.Credential, error) {
	seen := make(map[prism.ClientID]bool, len(ccs))
	creds := make([]prism.Credential, 0, len(ccs))
	for i, cc := range ccs {
		id, err := prism.ParseClientID(cc.ID)
		if err != nil {
			return nil, fmt.Errorf("credentials[%d].id: %w", i, err)
		}
		if seen[id] {
			return nil, fmt.Errorf("credentials[%d]: duplicate id %s", i, cc.ID)
		}
		seen[id] = true
		psk, err := prism.DecodeKey(cc.PSK)
		if err != nil {
			return nil, fmt.Errorf("credentials[%d].psk: %w", i, err)
		}
		creds = append(creds, prism.Credential{ID: id, PSK: psk, Name: cc.Name})
	}
	return creds, nil
}
