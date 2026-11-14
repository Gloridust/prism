package main

import (
	"encoding/json"
	"fmt"
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

	// Mode selects the deployment shape:
	//   "router"  : SOCKS5 only, for OpenWrt + Nikki to route into.
	//   "desktop" : SOCKS5 + HTTP proxy + auto system proxy + control panel.
	Mode string `json:"mode"`

	SocksListen string `json:"socks_listen"` // default 127.0.0.1:1080
	HTTPListen  string `json:"http_listen"`  // default 127.0.0.1:1081 (desktop)
	PanelListen string `json:"panel_listen"` // default 127.0.0.1:9797 (desktop)
	PoolSize    int    `json:"pool_size"`    // carrier connections, default 4
	AutoConnect *bool  `json:"auto_connect"` // desktop: set system proxy on start (default true)
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
