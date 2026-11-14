package prism

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"fmt"
)

// AEAD is the pluggable authenticated-cipher used for both the handshake and
// the data phase. The reference build wires AES-256-GCM (stdlib, zero deps, so
// the whole project cross-compiles offline). On routers without AES hardware
// (MIPS, some ARM) ChaCha20-Poly1305 is faster and constant-time in software;
// swap NewAEAD for a golang.org/x/crypto/chacha20poly1305 constructor on a
// build host that has module access. The wire format is identical (12-byte
// nonce, 16-byte tag), so client and server only need to agree on the choice.
type AEAD interface {
	// Seal encrypts plaintext with a 96-bit counter nonce and associated data.
	Seal(counter uint64, plaintext, ad []byte) []byte
	// Open reverses Seal; it returns an error if authentication fails.
	Open(counter uint64, ciphertext, ad []byte) ([]byte, error)
	Overhead() int
}

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
	return &gcmAEAD{g: g}, nil
}

type gcmAEAD struct{ g cipher.AEAD }

func nonceOf(counter uint64) []byte {
	var n [nonceSize]byte
	// 4 leading zero bytes + 64-bit big-endian counter. Each direction uses a
	// unique key, so starting every stream's counter at 0 is safe.
	binary.BigEndian.PutUint64(n[4:], counter)
	return n[:]
}

func (a *gcmAEAD) Seal(counter uint64, plaintext, ad []byte) []byte {
	return a.g.Seal(nil, nonceOf(counter), plaintext, ad)
}

func (a *gcmAEAD) Open(counter uint64, ciphertext, ad []byte) ([]byte, error) {
	return a.g.Open(nil, nonceOf(counter), ciphertext, ad)
}

func (a *gcmAEAD) Overhead() int { return a.g.Overhead() }
