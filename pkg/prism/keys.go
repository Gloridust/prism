package prism

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"fmt"
)

// ClientID is a 4-byte opaque label for a provisioned client (e.g. one per
// office or per device). It travels encrypted inside ClientInit and is used
// server-side only for accounting and revocation, never for routing in clear.
type ClientID [4]byte

// ServerKeypair is the server's long-term X25519 static identity.
type ServerKeypair struct {
	Private *ecdh.PrivateKey
	Public  *ecdh.PublicKey
}

// GenerateServerKeypair creates a fresh server static identity.
func GenerateServerKeypair() (*ServerKeypair, error) {
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return &ServerKeypair{Private: priv, Public: priv.PublicKey()}, nil
}

// NewPSK returns a cryptographically random 32-byte pre-shared key. Each client
// (or the whole org) is provisioned one out of band; it is a second,
// independent auth factor and the reason ClientInit is unforgeable/unreadable
// without possessing it.
func NewPSK() ([]byte, error) {
	k := make([]byte, keySize)
	if _, err := rand.Read(k); err != nil {
		return nil, err
	}
	return k, nil
}

// Credential is what a single client is provisioned with server-side: its ID
// and PSK. The server keeps a small set of these and trial-authenticates an
// incoming ClientInit against each, which gives per-client revocation.
type Credential struct {
	ID  ClientID
	PSK []byte
}

// --- base64 helpers for config files ---

var b64 = base64.StdEncoding

// EncodeKey renders a raw key/point as base64 for a config file.
func EncodeKey(b []byte) string { return b64.EncodeToString(b) }

// DecodeKey parses a base64 key and checks it is exactly 32 bytes.
func DecodeKey(s string) ([]byte, error) {
	b, err := b64.DecodeString(s)
	if err != nil {
		return nil, err
	}
	if len(b) != keySize {
		return nil, fmt.Errorf("prism: key must decode to %d bytes, got %d", keySize, len(b))
	}
	return b, nil
}

// ParseServerPrivate loads a base64 X25519 private scalar.
func ParseServerPrivate(s string) (*ecdh.PrivateKey, error) {
	b, err := DecodeKey(s)
	if err != nil {
		return nil, err
	}
	return ecdh.X25519().NewPrivateKey(b)
}

// ParseServerPublic loads a base64 X25519 public point.
func ParseServerPublic(s string) (*ecdh.PublicKey, error) {
	b, err := DecodeKey(s)
	if err != nil {
		return nil, err
	}
	return ecdh.X25519().NewPublicKey(b)
}

// ParseClientID parses a base64 4-byte client id.
func ParseClientID(s string) (ClientID, error) {
	var id ClientID
	b, err := b64.DecodeString(s)
	if err != nil {
		return id, err
	}
	if len(b) != 4 {
		return id, fmt.Errorf("prism: client id must be 4 bytes, got %d", len(b))
	}
	copy(id[:], b)
	return id, nil
}
