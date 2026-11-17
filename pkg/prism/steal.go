package prism

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"errors"
)

// Steal mode: REALITY-style active probing resistance. The server peeks at the
// raw TLS ClientHello before completing TLS. An authenticated client embeds an
// 8-byte HMAC tag in the session_id field (bytes [24:32]); the server
// trial-verifies it against each credential. Matching → complete TLS with an
// ephemeral cert, then Prism handshake. Non-matching → relay the entire TCP
// connection to a real website (the "steal target"), so an active prober sees
// the real site's certificate and behaviour. The tag is HMAC-SHA256 of the
// session_id's first 24 random bytes under a key derived from the client's PSK,
// so it changes every connection and is unforgeable without the PSK.

var labelSteal = []byte("prism steal v1")

// StealKey derives a 32-byte steal authentication key from a client PSK.
func StealKey(psk []byte) []byte {
	return hkdfExpand(hkdfExtract([]byte(ProtocolName), psk), labelSteal, keySize)
}

// StealMarker computes the 8-byte authentication tag for a 24-byte seed
// (session_id[:24]) under the given steal key.
func StealMarker(stealKey, seed []byte) [8]byte {
	mac := hmac.New(sha256.New, stealKey)
	mac.Write(seed)
	var tag [8]byte
	copy(tag[:], mac.Sum(nil))
	return tag
}

// EmbedStealMarker overwrites sessionID[24:32] with the HMAC tag over
// sessionID[:24]. The session_id must be at least 32 bytes (TLS 1.3
// compatibility mode guarantees this for Chrome).
func EmbedStealMarker(sessionID []byte, stealKey []byte) {
	if len(sessionID) < 32 {
		return
	}
	tag := StealMarker(stealKey, sessionID[:24])
	copy(sessionID[24:], tag[:])
}

// VerifyStealMarker checks whether sessionID[24:32] matches any credential's
// steal tag. Returns the matched credential or nil.
func VerifyStealMarker(sessionID []byte, creds []Credential) *Credential {
	if len(sessionID) < 32 {
		return nil
	}
	seed := sessionID[:24]
	for i := range creds {
		if len(creds[i].PSK) != keySize {
			continue
		}
		sk := StealKey(creds[i].PSK)
		tag := StealMarker(sk, seed)
		if subtle.ConstantTimeCompare(sessionID[24:32], tag[:]) == 1 {
			return &creds[i]
		}
	}
	return nil
}

// --- ClientHello parsing (minimal, for session_id extraction only) ---

var (
	ErrNotTLS         = errors.New("prism: not a TLS handshake")
	ErrNotClientHello = errors.New("prism: not a ClientHello")
)

// ParseClientHelloSessionID extracts the session_id from a raw TLS record
// containing a ClientHello. It parses only enough to reach the session_id
// field and returns a slice into the original buffer (not a copy).
func ParseClientHelloSessionID(record []byte) ([]byte, error) {
	// TLS record header: type(1) version(2) length(2) = 5 bytes
	// Handshake header: type(1) length(3) = 4 bytes
	// ClientHello: version(2) random(32) session_id_len(1) session_id(var)
	// Offset to session_id_len: 5 + 4 + 2 + 32 = 43
	if len(record) < 44 {
		return nil, ErrNotTLS
	}
	if record[0] != 0x16 { // ContentType: Handshake
		return nil, ErrNotTLS
	}
	if record[5] != 0x01 { // HandshakeType: ClientHello
		return nil, ErrNotClientHello
	}
	sidLen := int(record[43])
	if 44+sidLen > len(record) {
		return nil, ErrNotClientHello
	}
	return record[44 : 44+sidLen], nil
}

// ReadClientHelloRecord reads one complete TLS record from buf, returning the
// full record bytes and total bytes consumed. The caller must have read at
// least 5 bytes (the TLS record header).
func ClientHelloRecordLen(hdr []byte) int {
	if len(hdr) < 5 || hdr[0] != 0x16 {
		return -1
	}
	return 5 + int(binary.BigEndian.Uint16(hdr[3:5]))
}
