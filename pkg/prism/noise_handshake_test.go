package prism

import (
	"io"
	"net"
	"testing"
	"time"
)

func TestNoiseHandshakeRoundTrip(t *testing.T) {
	kp, err := GenerateServerKeypair()
	if err != nil {
		t.Fatal(err)
	}
	psk, err := NewPSK()
	if err != nil {
		t.Fatal(err)
	}
	cred := Credential{ID: [4]byte{0x01, 0x02, 0x03, 0x04}, PSK: psk}
	creds := []Credential{cred}

	cl, sv := net.Pipe()
	defer cl.Close()
	defer sv.Close()

	type result struct {
		keys *Keys
		cred *Credential
		err  error
	}
	sCh := make(chan result, 1)
	go func() {
		k, c, _, err := NoiseServerHandshake(sv, kp.Private, creds, nil, 120*time.Second)
		sCh <- result{k, c, err}
	}()

	cKeys, err := NoiseClientHandshake(cl, kp.Public, cred, NewAEAD)
	if err != nil {
		t.Fatalf("client handshake: %v", err)
	}

	sr := <-sCh
	if sr.err != nil {
		t.Fatalf("server handshake: %v", sr.err)
	}
	sKeys := sr.keys

	// Verify keys are correct: client's send == server's recv and vice versa.
	if string(cKeys.Send) != string(sKeys.Recv) {
		t.Error("client send key != server recv key")
	}
	if string(cKeys.Recv) != string(sKeys.Send) {
		t.Error("client recv key != server send key")
	}

	// Verify keys are non-zero and different from each other.
	zero := make([]byte, keySize)
	if string(cKeys.Send) == string(zero) || string(cKeys.Recv) == string(zero) {
		t.Error("traffic keys are zero")
	}
	if string(cKeys.Send) == string(cKeys.Recv) {
		t.Error("send and recv keys should be different")
	}
}

func TestNoiseHandshakeWrongPSK(t *testing.T) {
	kp, err := GenerateServerKeypair()
	if err != nil {
		t.Fatal(err)
	}
	psk1, _ := NewPSK()
	psk2, _ := NewPSK()
	// Different CID so server's CID check rejects it.
	clientCred := Credential{ID: [4]byte{0x01, 0x02, 0x03, 0x04}, PSK: psk1}
	serverCreds := []Credential{{ID: [4]byte{0x05, 0x06, 0x07, 0x08}, PSK: psk2}}

	cl, sv := net.Pipe()
	defer cl.Close()
	defer sv.Close()

	type result struct {
		err error
	}
	sCh := make(chan result, 1)
	go func() {
		_, _, _, err := NoiseServerHandshake(sv, kp.Private, serverCreds, nil, 120*time.Second)
		sCh <- result{err}
	}()

	go func() {
		// Client will either fail or hang; we just need the server to reject.
		NoiseClientHandshake(cl, kp.Public, clientCred, NewAEAD)
	}()

	sr := <-sCh
	if sr.err == nil {
		t.Error("server should reject mismatched credentials")
	}
}

func TestNoiseDataPhaseIntegration(t *testing.T) {
	kp, err := GenerateServerKeypair()
	if err != nil {
		t.Fatal(err)
	}
	psk, _ := NewPSK()
	cred := Credential{ID: [4]byte{0xAA, 0xBB, 0xCC, 0xDD}, PSK: psk}

	cl, sv := net.Pipe()

	type hsResult struct {
		keys *Keys
		err  error
	}
	sCh := make(chan hsResult, 1)
	go func() {
		k, _, _, err := NoiseServerHandshake(sv, kp.Private, []Credential{cred}, nil, 120*time.Second)
		sCh <- hsResult{k, err}
	}()

	cKeys, err := NoiseClientHandshake(cl, kp.Public, cred, NewAEAD)
	if err != nil {
		t.Fatalf("client noise handshake: %v", err)
	}
	sr := <-sCh
	if sr.err != nil {
		t.Fatalf("server noise handshake: %v", sr.err)
	}

	// Use the derived keys with NewSession for a full data-phase test.
	cSess, err := NewSession(cl, cKeys, true)
	if err != nil {
		t.Fatal(err)
	}
	sSess, err := NewSession(sv, sr.keys, false)
	if err != nil {
		t.Fatal(err)
	}
	defer cSess.Close()
	defer sSess.Close()

	// Open a stream and send data.
	go func() {
		st, err := sSess.Accept()
		if err != nil {
			return
		}
		io.Copy(st, st) // echo
		st.CloseWrite()
	}()

	st, err := cSess.OpenStream("echo.test:1234")
	if err != nil {
		t.Fatalf("open stream: %v", err)
	}
	msg := []byte("noise handshake integration test")
	st.Write(msg)
	st.CloseWrite()

	buf := make([]byte, 256)
	n, _ := io.ReadFull(st, buf)
	if string(buf[:n]) != string(msg) {
		t.Errorf("echo mismatch: got %q want %q", buf[:n], msg)
	}
}
