package prism

import (
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"
)

// Cipher names as they appear in config files (server "ciphers", client
// "cipher"). The wire format is byte-for-byte identical across both, so the
// name is purely an out-of-band agreement: the first handshake message carries
// no cipher selector (that would add a cleartext tell and change the wire
// format), so the server simply trial-decrypts against each cipher it enables.
const (
	CipherAES256GCM        = "aes-256-gcm"
	CipherChaCha20Poly1305 = "chacha20-poly1305"
)

// DefaultCipher is used when a config leaves the cipher unset.
const DefaultCipher = CipherAES256GCM

// NewChaCha20Poly1305AEAD builds a ChaCha20-Poly1305 AEAD (RFC 8439, 12-byte
// nonce, 16-byte tag) from a 32-byte key. It is the recommended cipher for
// routers without AES-NI (MIPS / older ARM), where AES-GCM in software is both
// slower and more prone to cache-timing leakage. The wire format matches
// NewAEAD exactly, so only the two endpoints need to agree on the choice.
func NewChaCha20Poly1305AEAD(key []byte) (AEAD, error) {
	if len(key) != keySize {
		return nil, fmt.Errorf("prism: aead key must be %d bytes, got %d", keySize, len(key))
	}
	g, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}
	return &aeadCipher{g: g}, nil
}

// AEADByName maps a cipher name to its factory. An empty name selects the
// default (AES-256-GCM). Unknown names are an error so a typo in a config file
// fails loudly rather than silently falling back.
func AEADByName(name string) (AEADFactory, error) {
	switch name {
	case "", CipherAES256GCM:
		return NewAEAD, nil
	case CipherChaCha20Poly1305:
		return NewChaCha20Poly1305AEAD, nil
	default:
		return nil, fmt.Errorf("prism: unknown cipher %q (want %q or %q)",
			name, CipherAES256GCM, CipherChaCha20Poly1305)
	}
}

// AEADFactoriesByName resolves a list of cipher names (e.g. the server's
// enabled set) to factories, de-duplicating and defaulting an empty list to
// just AES-256-GCM. The returned order is the trial-decrypt order on the
// server, so list the ciphers your fleet actually uses most first.
func AEADFactoriesByName(names []string) ([]AEADFactory, error) {
	if len(names) == 0 {
		return []AEADFactory{NewAEAD}, nil
	}
	seen := make(map[string]bool, len(names))
	out := make([]AEADFactory, 0, len(names))
	for _, n := range names {
		key := n
		if key == "" {
			key = DefaultCipher
		}
		if seen[key] {
			continue
		}
		seen[key] = true
		f, err := AEADByName(n)
		if err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, nil
}
