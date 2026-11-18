package prism

import (
	"bytes"
	"crypto/rand"
	"testing"
	"time"
)

func TestStealKeyDeterministic(t *testing.T) {
	psk := make([]byte, keySize)
	rand.Read(psk)
	k1 := StealKey(psk)
	k2 := StealKey(psk)
	if !bytes.Equal(k1, k2) {
		t.Fatal("StealKey must be deterministic")
	}
	if len(k1) != keySize {
		t.Fatalf("StealKey length = %d, want %d", len(k1), keySize)
	}
}

// fakeHello builds a ClientHello handshake message with a random 32-byte
// session_id followed by extra bytes standing in for suites and extensions.
func fakeHello(extra int) []byte {
	body := make([]byte, 2+32+1+32+extra)
	rand.Read(body)
	body[0], body[1] = 3, 3
	body[34] = 32
	h := append([]byte{0x01, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}, body...)
	return h
}

func TestStealMarkerRoundTrip(t *testing.T) {
	psk, _ := NewPSK()
	other, _ := NewPSK()
	now := time.Unix(1_800_000_000, 0)
	creds := []Credential{{ID: ClientID{9}, PSK: other}, {ID: ClientID{1, 2, 3, 4}, PSK: psk}}

	hello := fakeHello(300)
	before := append([]byte(nil), hello...)
	if err := EmbedStealMarker(hello, StealKey(psk), now); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(hello[:helloSIDOff+20], before[:helloSIDOff+20]) || !bytes.Equal(hello[helloSIDOff+32:], before[helloSIDOff+32:]) {
		t.Fatal("embedding touched bytes outside sid[20:32]")
	}
	got := VerifyStealMarker(hello, creds, 2*time.Minute, now.Add(30*time.Second))
	if got == nil || got.ID != creds[1].ID {
		t.Fatalf("matched %v, want credential 1", got)
	}
}

func TestStealMarkerRejects(t *testing.T) {
	psk, _ := NewPSK()
	wrong, _ := NewPSK()
	now := time.Unix(1_800_000_000, 0)
	creds := []Credential{{ID: ClientID{1}, PSK: psk}}
	window := 2 * time.Minute

	mk := func() []byte {
		h := fakeHello(300)
		EmbedStealMarker(h, StealKey(psk), now)
		return h
	}

	if VerifyStealMarker(mk(), []Credential{{PSK: wrong}}, window, now) != nil {
		t.Error("wrong PSK matched")
	}
	if VerifyStealMarker(mk(), creds, window, now.Add(window+time.Second)) != nil {
		t.Error("expired marker matched")
	}
	if VerifyStealMarker(mk(), creds, window, now.Add(-window-time.Second)) != nil {
		t.Error("marker from the future matched")
	}

	// The tag binds every byte of the hello: random, timestamp, and what
	// follows the session_id (cipher suites, key share, versions).
	for _, off := range []int{6, helloSIDOff, helloSIDOff + 21, helloSIDOff + 25, helloSIDOff + 40, len(mk()) - 1} {
		h := mk()
		h[off] ^= 0x01
		if VerifyStealMarker(h, creds, window, now) != nil {
			t.Errorf("hello tampered at offset %d still matched", off)
		}
	}

	// A marker cannot be transplanted into a different hello.
	a, b := mk(), fakeHello(300)
	copy(b[helloSIDOff:helloSIDOff+32], a[helloSIDOff:helloSIDOff+32])
	if VerifyStealMarker(b, creds, window, now) != nil {
		t.Error("session_id lifted into another hello matched")
	}

	// Truncated / fragmented / non-hello inputs.
	h := mk()
	for _, bad := range [][]byte{nil, h[:20], h[:len(h)-1], append([]byte{0x02}, h[1:]...)} {
		if VerifyStealMarker(bad, creds, window, now) != nil {
			t.Error("malformed hello matched")
		}
	}
	short := fakeHello(10)
	short[helloSIDLenOff] = 16
	if EmbedStealMarker(short, StealKey(psk), now) == nil {
		t.Error("embedding into a 16-byte session_id should fail")
	}
}

// The masked timestamp must not be recoverable or constant on the wire.
func TestStealTimestampIsMasked(t *testing.T) {
	psk, _ := NewPSK()
	now := time.Unix(1_800_000_000, 0)
	seen := map[string]bool{}
	for i := 0; i < 32; i++ {
		h := fakeHello(64)
		EmbedStealMarker(h, StealKey(psk), now)
		seen[string(h[helloSIDOff+20:helloSIDOff+24])] = true
	}
	if len(seen) < 30 {
		t.Fatalf("timestamp field repeated across hellos (%d distinct of 32)", len(seen))
	}
}

func TestParseClientHelloSessionID(t *testing.T) {
	// Build a minimal valid TLS record containing a ClientHello
	sid := make([]byte, 32)
	rand.Read(sid)

	// ClientHello body: version(2) + random(32) + sid_len(1) + sid(32) = 67
	ch := make([]byte, 67)
	ch[0] = 0x03 // version major
	ch[1] = 0x03 // version minor
	rand.Read(ch[2:34])
	ch[34] = 32 // session_id_len
	copy(ch[35:], sid)

	// Handshake header: type(1) + length(3) = 4
	hs := make([]byte, 4+len(ch))
	hs[0] = 0x01 // ClientHello
	hs[1] = 0
	hs[2] = byte(len(ch) >> 8)
	hs[3] = byte(len(ch))
	copy(hs[4:], ch)

	// TLS record header: type(1) + version(2) + length(2) = 5
	record := make([]byte, 5+len(hs))
	record[0] = 0x16 // Handshake
	record[1] = 0x03
	record[2] = 0x01
	record[3] = byte(len(hs) >> 8)
	record[4] = byte(len(hs))
	copy(record[5:], hs)

	got, err := ParseClientHelloSessionID(record)
	if err != nil {
		t.Fatalf("ParseClientHelloSessionID: %v", err)
	}
	if !bytes.Equal(got, sid) {
		t.Fatal("parsed session_id mismatch")
	}
}

func TestClientHelloRecordLen(t *testing.T) {
	hdr := []byte{0x16, 0x03, 0x01, 0x00, 0x80}
	if n := ClientHelloRecordLen(hdr); n != 5+128 {
		t.Fatalf("ClientHelloRecordLen = %d, want %d", n, 5+128)
	}
	if n := ClientHelloRecordLen([]byte{0x17, 0, 0, 0, 0}); n != -1 {
		t.Fatal("non-handshake should return -1")
	}
	if n := ClientHelloRecordLen([]byte{0x16, 0}); n != -1 {
		t.Fatal("short header should return -1")
	}
}
