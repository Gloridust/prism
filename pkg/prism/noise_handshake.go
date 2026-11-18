package prism

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"io"
	"time"

	"github.com/flynn/noise"
)

// Noise_IKpsk1 handshake using the audited flynn/noise state machine.
//
//	<- s
//	...
//	-> e, es, s, ss, psk   (message 1: initiator → responder)
//	<- e, ee, se           (message 2: responder → initiator)
//
// The PSK is mixed at the end of message 1 (psk1), so the message-1 payload is
// only decryptable by a responder holding that client's PSK. That is what lets
// the server identify the credential by trial decryption AND stay silent toward
// anyone without a valid PSK: a prober that merely knows the server's public
// key gets cover traffic, never a Noise reply.
//
// Traffic keys come from the two CipherStates Split() returns (secret), bound
// to the handshake hash; they are never derived from the handshake hash alone,
// which is computable from the transcript.
//
// Wire format: each Noise message is prefixed with a 2-byte big-endian length.
// The message-1 payload is CID(4) || unix time(8) || cipher id(1); the cipher
// id selects the data-phase AEAD and travels encrypted.

var noiseSuite = noise.NewCipherSuite(noise.DH25519, noise.CipherAESGCM, noise.HashSHA256)

const (
	noisePayloadSize = 13
	noisePSKPlace    = 1
	// e(32) + enc s(32+16) + enc payload(13+16): anything else is not a client.
	noiseMsg1Size = 32 + 48 + noisePayloadSize + 16
)

var (
	labelNoiseC2S = []byte("prism-noise c2s v2")
	labelNoiseS2C = []byte("prism-noise s2c v2")
)

// Data-phase cipher ids carried in the Noise payload.
const (
	cipherIDAES    byte = 1
	cipherIDChaCha byte = 2
)

var cipherRegistry = []struct {
	id      byte
	factory AEADFactory
}{
	{cipherIDAES, NewAEAD},
	{cipherIDChaCha, NewChaCha20Poly1305AEAD},
}

// cipherProbe is a factory's fingerprint: its tag over an empty message under
// the all-zero key. Factories are funcs and cannot be compared directly.
func cipherProbe(f AEADFactory) []byte {
	a, err := f(make([]byte, keySize))
	if err != nil {
		return nil
	}
	return a.Seal(0, nil, nil)
}

func cipherIDOf(f AEADFactory) (byte, bool) {
	p := cipherProbe(f)
	for _, c := range cipherRegistry {
		if p != nil && bytes.Equal(p, cipherProbe(c.factory)) {
			return c.id, true
		}
	}
	return 0, false
}

// cipherByID returns the factory for id if it is among the enabled set.
func cipherByID(id byte, enabled []AEADFactory) AEADFactory {
	for _, f := range enabled {
		if got, ok := cipherIDOf(f); ok && got == id {
			return f
		}
	}
	return nil
}

func noiseTrafficKeys(hs *noise.HandshakeState, c2s, s2c *noise.CipherState) (kC2S, kS2C []byte) {
	h := hs.ChannelBinding()
	k1, k2 := c2s.UnsafeKey(), s2c.UnsafeKey()
	kC2S = hkdfExpand(hkdfExtract(h, k1[:]), labelNoiseC2S, keySize)
	kS2C = hkdfExpand(hkdfExtract(h, k2[:]), labelNoiseS2C, keySize)
	return
}

// NoiseClientHandshake performs the initiator side.
func NoiseClientHandshake(rw io.ReadWriter, serverPub *ecdh.PublicKey, cred Credential, aeadFor AEADFactory) (*Keys, error) {
	if len(cred.PSK) != keySize {
		return nil, errors.New("prism: PSK must be 32 bytes")
	}
	cid, ok := cipherIDOf(aeadFor)
	if !ok {
		return nil, errors.New("prism: noise handshake: unsupported cipher")
	}

	// The initiator static is a throwaway: clients are identified by CID+PSK,
	// and a fresh static per connection keeps handshakes unlinkable.
	staticPriv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}

	payload := make([]byte, noisePayloadSize)
	copy(payload[0:4], cred.ID[:])
	binary.BigEndian.PutUint64(payload[4:12], uint64(time.Now().Unix()))
	payload[12] = cid

	hs, err := noise.NewHandshakeState(noise.Config{
		CipherSuite:           noiseSuite,
		Pattern:               noise.HandshakeIK,
		Initiator:             true,
		StaticKeypair:         noise.DHKey{Private: staticPriv.Bytes(), Public: staticPriv.PublicKey().Bytes()},
		PeerStatic:            serverPub.Bytes(),
		PresharedKey:          cred.PSK,
		PresharedKeyPlacement: noisePSKPlace,
		Prologue:              []byte(ProtocolName),
	})
	if err != nil {
		return nil, err
	}

	msg1, _, _, err := hs.WriteMessage(nil, payload)
	if err != nil {
		return nil, err
	}
	if err := writeNoiseMsg(rw, msg1); err != nil {
		return nil, err
	}

	msg2, err := readNoiseMsg(rw)
	if err != nil {
		return nil, err
	}
	_, cs1, cs2, err := hs.ReadMessage(nil, msg2)
	if err != nil || cs1 == nil || cs2 == nil {
		return nil, errors.New("prism: noise handshake: server authentication failed")
	}

	// For the initiator cs1 encrypts initiator→responder.
	c2s, s2c := noiseTrafficKeys(hs, cs1, cs2)
	return &Keys{Send: c2s, Recv: s2c, aead: aeadFor}, nil
}

// NoiseServerHandshake performs the responder side. On any failure it returns
// ErrNotPrism and the bytes it consumed, for cover fallback.
func NoiseServerHandshake(rw io.ReadWriter, serverPriv *ecdh.PrivateKey, creds []Credential, replay *ReplayWindow, window time.Duration, aeads ...AEADFactory) (*Keys, *Credential, []byte, error) {
	if len(aeads) == 0 {
		aeads = []AEADFactory{NewAEAD}
	}

	// Read the 2-byte length incrementally so a short plain-HTTP request is
	// handed to cover at once instead of stalling until the deadline.
	want := 2 + noiseMsg1Size
	buf := make([]byte, want)
	n := 0
	for n < want {
		m, err := rw.Read(buf[n:])
		n += m
		if n >= 2 && int(binary.BigEndian.Uint16(buf[:2])) != noiseMsg1Size {
			return nil, nil, buf[:n], ErrNotPrism
		}
		if n >= want {
			break
		}
		if err != nil || bytes.Contains(buf[:n], httpEndOfHeaders) {
			return nil, nil, buf[:n], ErrNotPrism
		}
	}
	msg1 := buf[2:]

	static := noise.DHKey{Private: serverPriv.Bytes(), Public: serverPriv.PublicKey().Bytes()}

	for i := range creds {
		cred := creds[i]
		if len(cred.PSK) != keySize {
			continue
		}
		hs, err := noise.NewHandshakeState(noise.Config{
			CipherSuite:           noiseSuite,
			Pattern:               noise.HandshakeIK,
			Initiator:             false,
			StaticKeypair:         static,
			PresharedKey:          cred.PSK,
			PresharedKeyPlacement: noisePSKPlace,
			Prologue:              []byte(ProtocolName),
		})
		if err != nil {
			continue
		}
		payload, _, _, err := hs.ReadMessage(nil, msg1)
		if err != nil {
			continue // not this credential's PSK (or not a Prism client at all)
		}
		if len(payload) != noisePayloadSize ||
			subtle.ConstantTimeCompare(payload[0:4], cred.ID[:]) != 1 {
			return nil, nil, buf, ErrNotPrism
		}
		skew := time.Since(time.Unix(int64(binary.BigEndian.Uint64(payload[4:12])), 0))
		if skew < -window || skew > window {
			return nil, nil, buf, ErrNotPrism
		}
		aeadFor := cipherByID(payload[12], aeads)
		if aeadFor == nil {
			return nil, nil, buf, ErrNotPrism
		}
		if replay != nil && !replay.Accept(hs.PeerEphemeral()) {
			return nil, nil, buf, ErrNotPrism
		}

		msg2, cs1, cs2, err := hs.WriteMessage(nil, nil)
		if err != nil || cs1 == nil || cs2 == nil {
			return nil, nil, buf, ErrNotPrism
		}
		if err := writeNoiseMsg(rw, msg2); err != nil {
			return nil, nil, buf, err
		}
		c2s, s2c := noiseTrafficKeys(hs, cs1, cs2)
		return &Keys{Send: s2c, Recv: c2s, aead: aeadFor}, &cred, nil, nil
	}
	return nil, nil, buf, ErrNotPrism
}

func writeNoiseMsg(w io.Writer, msg []byte) error {
	out := make([]byte, 2+len(msg))
	binary.BigEndian.PutUint16(out, uint16(len(msg)))
	copy(out[2:], msg)
	_, err := w.Write(out)
	return err
}

func readNoiseMsg(r io.Reader) ([]byte, error) {
	hdr := make([]byte, 2)
	if _, err := io.ReadFull(r, hdr); err != nil {
		return nil, err
	}
	n := int(binary.BigEndian.Uint16(hdr))
	if n == 0 || n > 1024 {
		return nil, errors.New("prism: bad noise message length")
	}
	msg := make([]byte, n)
	if _, err := io.ReadFull(r, msg); err != nil {
		return nil, err
	}
	return msg, nil
}
