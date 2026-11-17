package prism

import (
	"bytes"
	"crypto/rand"
	"testing"
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

func TestStealMarkerRoundTrip(t *testing.T) {
	psk, _ := NewPSK()
	sk := StealKey(psk)

	// Build a 32-byte session_id with random seed
	sid := make([]byte, 32)
	rand.Read(sid)

	EmbedStealMarker(sid, sk)

	// Verify should match
	cred := Credential{ID: ClientID{1, 2, 3, 4}, PSK: psk}
	got := VerifyStealMarker(sid, []Credential{cred})
	if got == nil {
		t.Fatal("VerifyStealMarker should match the correct credential")
	}
	if got.ID != cred.ID {
		t.Fatalf("matched credential ID = %v, want %v", got.ID, cred.ID)
	}
}

func TestStealMarkerRejectsWrongPSK(t *testing.T) {
	psk1, _ := NewPSK()
	psk2, _ := NewPSK()

	sid := make([]byte, 32)
	rand.Read(sid)
	EmbedStealMarker(sid, StealKey(psk1))

	cred2 := Credential{ID: ClientID{5, 6, 7, 8}, PSK: psk2}
	if VerifyStealMarker(sid, []Credential{cred2}) != nil {
		t.Fatal("wrong PSK must not match")
	}
}

func TestStealMarkerRejectsTamper(t *testing.T) {
	psk, _ := NewPSK()
	sk := StealKey(psk)

	sid := make([]byte, 32)
	rand.Read(sid)
	EmbedStealMarker(sid, sk)

	sid[25] ^= 0xff // tamper the tag

	cred := Credential{ID: ClientID{1, 2, 3, 4}, PSK: psk}
	if VerifyStealMarker(sid, []Credential{cred}) != nil {
		t.Fatal("tampered tag must not match")
	}
}

func TestStealMarkerShortSessionID(t *testing.T) {
	psk, _ := NewPSK()
	cred := Credential{ID: ClientID{1, 2, 3, 4}, PSK: psk}
	if VerifyStealMarker(make([]byte, 16), []Credential{cred}) != nil {
		t.Fatal("short session_id must not match")
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
