package prism

import (
	"crypto/ecdh"
	"crypto/rand"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"time"
)

// Wire sizes of the two fixed-length handshake messages. Both are a bare
// X25519 point (uniform random to an observer) followed by an AEAD blob, so
// neither contains any plaintext structure a DPI box can match on.
const (
	payloadSize    = 32                              // CID4 + ts8 + nonce16 + flags1 + rsvd3
	clientInitSize = keySize + payloadSize + tagSize // 32 + 32 + 16 = 80
	serverRespSize = keySize + tagSize               // 32 + 16 = 48
)

// KDF labels (domain separation inside one handshake).
var (
	labelInit = []byte("prism init v1")
	labelResp = []byte("prism resp v1")
	labelC2S  = []byte("prism c2s v1")
	labelS2C  = []byte("prism s2c v1")
)

// ErrNotPrism is returned by ServerHandshake when the peer is not an
// authenticated Prism client. The caller MUST then fall back to serving cover
// traffic using the returned Consumed bytes followed by the live connection —
// this is what makes the server survive active probing.
var ErrNotPrism = errors.New("prism: not an authenticated client (fall back to cover)")

// Flags carried in ClientInit (bit 0 reserved = mux requested). The profile id
// occupies the low nibble so a client can request a shaping profile.
const flagMux = 0x01

// Keys is the output of a completed handshake: direction-separated traffic
// keys. Send/Recv are relative to the local role.
type Keys struct {
	Send []byte // key for frames we send
	Recv []byte // key for frames we receive
}

// clientInitPayload is the 32-byte plaintext sealed inside ClientInit.
type clientInitPayload struct {
	ID    ClientID
	Time  int64
	Nonce [16]byte
	Flags byte
}

func (p *clientInitPayload) marshal() []byte {
	b := make([]byte, payloadSize)
	copy(b[0:4], p.ID[:])
	binary.BigEndian.PutUint64(b[4:12], uint64(p.Time))
	copy(b[12:28], p.Nonce[:])
	b[28] = p.Flags
	// b[29:32] reserved zero
	return b
}

func unmarshalPayload(b []byte) clientInitPayload {
	var p clientInitPayload
	copy(p.ID[:], b[0:4])
	p.Time = int64(binary.BigEndian.Uint64(b[4:12]))
	copy(p.Nonce[:], b[12:28])
	p.Flags = b[28]
	return p
}

// ClientHandshake runs the initiator side over rw (an already-established
// carrier byte stream, e.g. a TLS conn). It proves possession of the PSK and
// authenticates the server, and returns per-direction traffic keys.
func ClientHandshake(rw io.ReadWriter, serverPub *ecdh.PublicKey, cred Credential, aeadFor func([]byte) (AEAD, error)) (*Keys, error) {
	if len(cred.PSK) != keySize {
		return nil, errors.New("prism: PSK must be 32 bytes")
	}
	// 1. fresh ephemeral
	eph, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	ePub := eph.PublicKey().Bytes()

	// 2. es = DH(e, S), key schedule up to k_init
	es, err := eph.ECDH(serverPub)
	if err != nil {
		return nil, err
	}
	ck0 := hkdfExtract([]byte(ProtocolName), es)
	ck1 := hkdfExtract(ck0, cred.PSK)
	kInit := hkdfExpand(ck1, labelInit, keySize)

	initAEAD, err := aeadFor(kInit)
	if err != nil {
		return nil, err
	}

	// 3. seal payload, AD binds the ephemeral
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, err
	}
	pl := clientInitPayload{ID: cred.ID, Time: time.Now().Unix(), Nonce: nonce, Flags: flagMux}
	hCI := mixHash([]byte(ProtocolName), ePub)
	ct := initAEAD.Seal(0, pl.marshal(), hCI)

	msg := make([]byte, 0, clientInitSize)
	msg = append(msg, ePub...)
	msg = append(msg, ct...)
	if _, err := rw.Write(msg); err != nil {
		return nil, err
	}

	// 4. read ServerResp = F_pub || confirm-tag
	resp := make([]byte, serverRespSize)
	if _, err := io.ReadFull(rw, resp); err != nil {
		return nil, fmt.Errorf("prism: reading server response: %w", err)
	}
	fPub, err := ecdh.X25519().NewPublicKey(resp[:keySize])
	if err != nil {
		return nil, err
	}
	ee, err := eph.ECDH(fPub)
	if err != nil {
		return nil, err
	}
	ck2 := hkdfExtract(ck1, ee)
	kResp := hkdfExpand(ck2, labelResp, keySize)
	respAEAD, err := aeadFor(kResp)
	if err != nil {
		return nil, err
	}
	hSR := mixHash([]byte(ProtocolName), ePub, ct, resp[:keySize])
	if _, err := respAEAD.Open(0, resp[keySize:], hSR); err != nil {
		// Server failed to prove it holds S_priv + PSK: possible MITM / wrong
		// server. Abort rather than leak data.
		return nil, errors.New("prism: server authentication failed")
	}

	return &Keys{
		Send: hkdfExpand(ck2, labelC2S, keySize),
		Recv: hkdfExpand(ck2, labelS2C, keySize),
	}, nil
}

// ServerHandshake runs the responder side. It reads a fixed ClientInit, trial-
// authenticates against every provisioned credential, enforces the freshness
// window and anti-replay, and on success writes ServerResp and returns traffic
// keys plus the matched credential. On ANY failure it returns ErrNotPrism and
// the bytes it consumed, so the caller can transparently serve cover traffic.
func ServerHandshake(rw io.ReadWriter, serverPriv *ecdh.PrivateKey, creds []Credential, replay *ReplayWindow, window time.Duration, aeadFor func([]byte) (AEAD, error)) (*Keys, *Credential, []byte, error) {
	init := make([]byte, clientInitSize)
	n, err := io.ReadFull(rw, init)
	if err != nil {
		// Too few bytes to even be a ClientInit — hand what we have to cover.
		return nil, nil, init[:n], ErrNotPrism
	}

	ePubBytes := init[:keySize]
	ct := init[keySize:]
	ePub, err := ecdh.X25519().NewPublicKey(ePubBytes)
	if err != nil {
		return nil, nil, init, ErrNotPrism
	}
	es, err := serverPriv.ECDH(ePub)
	if err != nil {
		return nil, nil, init, ErrNotPrism
	}
	ck0 := hkdfExtract([]byte(ProtocolName), es)
	hCI := mixHash([]byte(ProtocolName), ePubBytes)

	// Trial-decrypt against each credential's PSK. N is tiny (a few offices /
	// a device fleet); each trial is one GCM open over 48 bytes.
	for i := range creds {
		cred := creds[i]
		if len(cred.PSK) != keySize {
			continue
		}
		ck1 := hkdfExtract(ck0, cred.PSK)
		kInit := hkdfExpand(ck1, labelInit, keySize)
		initAEAD, err := aeadFor(kInit)
		if err != nil {
			continue
		}
		pt, err := initAEAD.Open(0, ct, hCI)
		if err != nil {
			continue // not this PSK
		}
		pl := unmarshalPayload(pt)
		// Bind the decrypted CID to the credential we matched (defence in depth).
		if subtle.ConstantTimeCompare(pl.ID[:], cred.ID[:]) != 1 {
			return nil, nil, init, ErrNotPrism
		}
		// Freshness window.
		skew := time.Since(time.Unix(pl.Time, 0))
		if skew < -window || skew > window {
			return nil, nil, init, ErrNotPrism
		}
		// Anti-replay: a fresh ephemeral per connection means a repeated E_pub
		// is a replay.
		if replay != nil && !replay.Accept(ePubBytes) {
			return nil, nil, init, ErrNotPrism
		}

		// Authenticated. Respond for forward secrecy + key confirmation.
		fEph, err := ecdh.X25519().GenerateKey(rand.Reader)
		if err != nil {
			return nil, nil, init, err
		}
		fPub := fEph.PublicKey().Bytes()
		ee, err := fEph.ECDH(ePub)
		if err != nil {
			return nil, nil, init, err
		}
		ck2 := hkdfExtract(ck1, ee)
		kResp := hkdfExpand(ck2, labelResp, keySize)
		respAEAD, err := aeadFor(kResp)
		if err != nil {
			return nil, nil, init, err
		}
		hSR := mixHash([]byte(ProtocolName), ePubBytes, ct, fPub)
		confirm := respAEAD.Seal(0, nil, hSR)

		resp := make([]byte, 0, serverRespSize)
		resp = append(resp, fPub...)
		resp = append(resp, confirm...)
		if _, err := rw.Write(resp); err != nil {
			return nil, nil, init, err
		}

		return &Keys{
			Send: hkdfExpand(ck2, labelS2C, keySize),
			Recv: hkdfExpand(ck2, labelC2S, keySize),
		}, &cred, nil, nil
	}

	// No credential authenticated: a prober, a scanner, or a real browser.
	return nil, nil, init, ErrNotPrism
}
