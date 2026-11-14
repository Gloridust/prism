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

	// TLS for the outer carrier. Use a REAL certificate for your own domain
	// (certbot/Let's Encrypt). SelfSigned is for local testing only and will
	// not survive a careful probe.
	CertFile   string `json:"cert_file"`
	KeyFile    string `json:"key_file"`
	SelfSigned string `json:"self_signed"` // domain to self-sign for testing

	// Prism identity.
	PrivateKey  string       `json:"private_key"` // base64 X25519 server private
	Credentials []CredConfig `json:"credentials"`

	// Anti-replay / freshness.
	WindowSeconds int `json:"window_seconds"` // default 120

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
		creds = append(creds, prism.Credential{ID: id, PSK: psk})
	}
	if len(creds) == 0 {
		return nil, nil, nil, fmt.Errorf("no credentials configured")
	}
	return &c, priv, creds, nil
}
