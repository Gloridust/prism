package prism

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"fmt"
)

// AEAD is the pluggable authenticated-cipher used for both the handshake and
// the data phase. The reference build wires AES-256-GCM (stdlib). On routers
// without AES hardware (MIPS, some ARM) ChaCha20-Poly1305 is faster and
// constant-time in software (see NewChaCha20Poly1305AEAD in aead_chacha.go).
// Both ciphers share the exact same wire format — a 12-byte counter nonce and a
// 16-byte tag — so a connection only needs both ends to pick the same one; see
// AEADFactory / AEADByName for how that choice is wired through the handshake.
type AEAD interface {
	// Seal encrypts plaintext with a 96-bit counter nonce and associated data.
	Seal(counter uint64, plaintext, ad []byte) []byte
	// Open reverses Seal; it returns an error if authentication fails.
	Open(counter uint64, ciphertext, ad []byte) ([]byte, error)
	Overhead() int
}

// AEADFactory builds an AEAD from a 32-byte key. The handshake and the data
// phase are both parameterised over it so the cipher is a per-connection
// choice: the client dials with one factory, the server trial-authenticates
// against the factories it enables, and the matched factory is remembered on
// the resulting Keys so the data phase uses the identical cipher. NewAEAD is
// the default (AES-256-GCM); NewChaCha20Poly1305AEAD is the router variant.
type AEADFactory = func(key []byte) (AEAD, error)

// NewAEAD builds the default AEAD (AES-256-GCM) from a 32-byte key.
func NewAEAD(key []byte) (AEAD, error) {
	if len(key) != keySize {
		return nil, fmt.Errorf("prism: aead key must be %d bytes, got %d", keySize, len(key))
	}
	blk, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	g, err := cipher.NewGCM(blk)
	if err != nil {
		return nil, err
	}
	return &aeadCipher{g: g}, nil
}

// aeadCipher adapts any stdlib-style cipher.AEAD (AES-GCM or ChaCha20-Poly1305,
// both 12-byte nonce / 16-byte tag) to prism's counter-nonce AEAD interface.
type aeadCipher struct{ g cipher.AEAD }

func nonceOf(counter uint64) []byte {
	var n [nonceSize]byte
	// 4 leading zero bytes + 64-bit big-endian counter. Each direction uses a
	// unique key, so starting every stream's counter at 0 is safe.
	binary.BigEndian.PutUint64(n[4:], counter)
	return n[:]
}

func (a *aeadCipher) Seal(counter uint64, plaintext, ad []byte) []byte {
	return a.g.Seal(nil, nonceOf(counter), plaintext, ad)
}

func (a *aeadCipher) Open(counter uint64, ciphertext, ad []byte) ([]byte, error) {
	return a.g.Open(nil, nonceOf(counter), ciphertext, ad)
}

func (a *aeadCipher) Overhead() int { return a.g.Overhead() }
