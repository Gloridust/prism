package prism

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"time"
)

// Steal mode: REALITY-style active probing resistance. The server peeks at the
// raw TLS ClientHello before completing TLS. An authenticated client carries a
// marker in the 32-byte legacy session_id (random-looking in every real
// TLS 1.3 hello):
//
//	sid[0:20]   random
//	sid[20:24]  unix seconds, XOR-masked with HMAC(key, "ts" || sid[0:20])
//	sid[24:32]  HMAC(key, "tag" || ClientHello with sid[24:32] zeroed)[:8]
//
// The tag covers the whole ClientHello, so it cannot be lifted into another
// hello (different key share, downgraded version); the masked timestamp bounds
// its lifetime and a replay cache makes each hello single-use. A replayed or
// forged hello is relayed to the real site like any other visitor's. Because
// the server only ever speaks TLS 1.3 to marked clients, its ephemeral
// certificate is encrypted under the client's key share and is unreadable to
// anyone who merely replays a captured hello.

var (
	labelSteal    = []byte("prism steal v2")
	stealTSLabel  = []byte("ts")
	stealTagLabel = []byte("tag")
)

const (
	// Offset of session_id_len inside a ClientHello handshake message:
	// type(1) len(3) version(2) random(32).
	helloSIDLenOff = 38
	helloSIDOff    = 39
	stealSIDLen    = 32
)

// StealKey derives a 32-byte steal authentication key from a client PSK.
func StealKey(psk []byte) []byte {
	return hkdfExpand(hkdfExtract([]byte(ProtocolName), psk), labelSteal, keySize)
}

// HelloSessionID returns the 32-byte session_id inside a complete ClientHello
// handshake message, or nil if hello is not one.
func HelloSessionID(hello []byte) []byte { return stealSID(hello) }

func stealSID(hello []byte) []byte {
	if len(hello) < helloSIDOff+stealSIDLen || hello[0] != 0x01 || hello[helloSIDLenOff] != stealSIDLen {
		return nil
	}
	// The hello must be complete (not fragmented across records), or the tag
	// would not cover all of it.
	if int(hello[1])<<16|int(hello[2])<<8|int(hello[3]) != len(hello)-4 {
		return nil
	}
	return hello[helloSIDOff : helloSIDOff+stealSIDLen]
}

func stealTSMask(key, seed []byte) uint32 {
	m := hmac.New(sha256.New, key)
	m.Write(stealTSLabel)
	m.Write(seed)
	return binary.BigEndian.Uint32(m.Sum(nil))
}

func stealTag(key, hello []byte) []byte {
	m := hmac.New(sha256.New, key)
	m.Write(stealTagLabel)
	m.Write(hello[:helloSIDOff+24])
	m.Write(make([]byte, 8))
	m.Write(hello[helloSIDOff+stealSIDLen:])
	return m.Sum(nil)[:8]
}

// EmbedStealMarker writes the marker into the session_id of hello, a marshaled
// ClientHello handshake message (no record header), in place.
func EmbedStealMarker(hello, stealKey []byte, now time.Time) error {
	sid := stealSID(hello)
	if sid == nil {
		return errors.New("prism: steal needs a ClientHello with a 32-byte session_id")
	}
	binary.BigEndian.PutUint32(sid[20:24], uint32(now.Unix())^stealTSMask(stealKey, sid[:20]))
	copy(sid[24:], stealTag(stealKey, hello))
	return nil
}

// VerifyStealMarker checks hello (a ClientHello handshake message) against each
// credential and the freshness window. It returns the matched credential, or
// nil. The caller must also reject a session_id it has already seen.
func VerifyStealMarker(hello []byte, creds []Credential, window time.Duration, now time.Time) *Credential {
	sid := stealSID(hello)
	if sid == nil {
		return nil
	}
	for i := range creds {
		if len(creds[i].PSK) != keySize {
			continue
		}
		key := StealKey(creds[i].PSK)
		if subtle.ConstantTimeCompare(sid[24:], stealTag(key, hello)) != 1 {
			continue
		}
		ts := binary.BigEndian.Uint32(sid[20:24]) ^ stealTSMask(key, sid[:20])
		skew := now.Sub(time.Unix(int64(ts), 0))
		if skew < -window || skew > window {
			return nil
		}
		return &creds[i]
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
