// Package prism implements the core of the Prism obfuscated transport:
// a Noise-IK-flavoured mutual handshake (X25519 + PSK) whose first message
// is indistinguishable from random bytes, plus an AEAD-framed, multiplexed
// data phase with traffic shaping. See docs/PROTOCOL.md for the wire spec.
//
// SECURITY NOTE: the handshake here is a hand-rolled, UNAUDITED construction.
// It is structured to mirror Noise_IKpsk2 so that a production build can drop
// in a vetted Noise library. Do not ship this to a high-risk adversary without
// an independent cryptographic review. See docs/PROTOCOL.md §"安全局限".
package prism

import (
	"crypto/hmac"
	"crypto/sha256"
)

// ProtocolName is the domain-separation label mixed into every key schedule.
// Changing it makes a build wire-incompatible with another — intentional, so
// each deployment can fork its own namespace.
const ProtocolName = "Prism/1 X25519 AESGCM SHA256"

const (
	keySize   = 32 // AEAD key + X25519 scalar/point size
	hashSize  = 32 // SHA-256
	tagSize   = 16 // AEAD tag
	nonceSize = 12 // AEAD nonce
)

// hkdfExtract is RFC 5869 HKDF-Extract with SHA-256.
func hkdfExtract(salt, ikm []byte) []byte {
	m := hmac.New(sha256.New, salt)
	m.Write(ikm)
	return m.Sum(nil)
}

// hkdfExpand is RFC 5869 HKDF-Expand with SHA-256, truncated to n bytes.
func hkdfExpand(prk, info []byte, n int) []byte {
	out := make([]byte, 0, n)
	var t []byte
	var ctr byte = 1
	for len(out) < n {
		m := hmac.New(sha256.New, prk)
		m.Write(t)
		m.Write(info)
		m.Write([]byte{ctr})
		t = m.Sum(nil)
		out = append(out, t...)
		ctr++
	}
	return out[:n]
}

// mixHash returns SHA-256(parts[0] || parts[1] || ...), the running transcript
// hash used as AEAD associated data to bind each message to all prior ones.
func mixHash(parts ...[]byte) []byte {
	h := sha256.New()
	for _, p := range parts {
		h.Write(p)
	}
	return h.Sum(nil)
}
