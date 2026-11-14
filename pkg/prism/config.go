package prism

import (
	"crypto/ecdh"
	"encoding/json"
	"errors"
	"os"
)

// ServerConfig 出口服务器配置。
type ServerConfig struct {
	Listen         string   `json:"listen"`           // 监听地址，如 0.0.0.0:8443
	PrivateKey     string   `json:"private_key"`      // 服务器静态私钥 (base64url)
	PSK            string   `json:"psk"`              // 公司预共享密钥 (base64url)
	AllowedClients []string `json:"allowed_clients"`  // 允许的客户端静态公钥列表 (base64url)
	Fallback       string   `json:"fallback"`         // 诱饵后端 host:port（认证失败转发），可空
}

// ClientConfig 客户端配置。
type ClientConfig struct {
	Server          string `json:"server"`            // prism-server 地址 host:port
	ServerPublicKey string `json:"server_public_key"` // 服务器静态公钥 (base64url)
	PSK             string `json:"psk"`               // 公司预共享密钥 (base64url)
	PrivateKey      string `json:"private_key"`       // 本客户端静态私钥 (base64url)
	SocksListen     string `json:"socks_listen"`      // 本地 SOCKS5 监听，如 127.0.0.1:1080
	HTTPListen      string `json:"http_listen"`       // 本地 HTTP 代理监听（可空）
	MuxConns        int    `json:"mux_conns"`         // 复用连接池大小（默认 2）
}

// LoadServerConfig / LoadClientConfig 从 JSON 文件读取配置。
func LoadServerConfig(path string) (*ServerConfig, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var c ServerConfig
	if err := json.Unmarshal(b, &c); err != nil {
		return nil, err
	}
	return &c, nil
}

func LoadClientConfig(path string) (*ClientConfig, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var c ClientConfig
	if err := json.Unmarshal(b, &c); err != nil {
		return nil, err
	}
	return &c, nil
}

// --- 解析后的运行期材料 ---

var errBadConfig = errors.New("prism: invalid config key material")

// ServerKeys 解析服务器密钥材料。
type ServerKeys struct {
	Priv    *ecdh.PrivateKey
	PSK     []byte
	Allowed map[string]bool // key = string(pubBytes)
}

func (c *ServerConfig) Parse() (*ServerKeys, error) {
	privB, err := DecodeKey(c.PrivateKey)
	if err != nil || len(privB) != KeySize {
		return nil, errBadConfig
	}
	priv, err := ParsePrivateKey(privB)
	if err != nil {
		return nil, err
	}
	psk, err := DecodeKey(c.PSK)
	if err != nil || len(psk) != KeySize {
		return nil, errBadConfig
	}
	allowed := make(map[string]bool)
	for _, a := range c.AllowedClients {
		pb, err := DecodeKey(a)
		if err != nil || len(pb) != KeySize {
			return nil, errBadConfig
		}
		allowed[string(pb)] = true
	}
	return &ServerKeys{Priv: priv, PSK: psk, Allowed: allowed}, nil
}

// Allow 返回供握手使用的校验闭包。
func (k *ServerKeys) Allow(pub []byte) bool { return k.Allowed[string(pub)] }

// ClientKeys 解析客户端密钥材料。
type ClientKeys struct {
	Priv      *ecdh.PrivateKey
	ServerPub *ecdh.PublicKey
	PSK       []byte
}

func (c *ClientConfig) Parse() (*ClientKeys, error) {
	privB, err := DecodeKey(c.PrivateKey)
	if err != nil || len(privB) != KeySize {
		return nil, errBadConfig
	}
	priv, err := ParsePrivateKey(privB)
	if err != nil {
		return nil, err
	}
	spubB, err := DecodeKey(c.ServerPublicKey)
	if err != nil || len(spubB) != KeySize {
		return nil, errBadConfig
	}
	spub, err := ParsePublicKey(spubB)
	if err != nil {
		return nil, err
	}
	psk, err := DecodeKey(c.PSK)
	if err != nil || len(psk) != KeySize {
		return nil, errBadConfig
	}
	return &ClientKeys{Priv: priv, ServerPub: spub, PSK: psk}, nil
}
