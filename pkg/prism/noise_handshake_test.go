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

// A peer that knows the server public key and a valid CID but not the PSK must
// get no Noise reply at all, so the server can fall back to cover.
func TestNoiseServerSilentWithoutPSK(t *testing.T) {
	kp, _ := GenerateServerKeypair()
	good, _ := NewPSK()
	bad, _ := NewPSK()
	id := ClientID{9, 9, 9, 9}

	cl, sv := net.Pipe()
	defer cl.Close()
	defer sv.Close()

	type result struct {
		consumed []byte
		err      error
	}
	sCh := make(chan result, 1)
	go func() {
		_, _, consumed, err := NoiseServerHandshake(sv, kp.Private, []Credential{{ID: id, PSK: good}}, nil, time.Minute)
		sCh <- result{consumed, err}
	}()

	cErr := make(chan error, 1)
	go func() {
		_, err := NoiseClientHandshake(cl, kp.Public, Credential{ID: id, PSK: bad}, NewAEAD)
		cErr <- err
	}()

	sr := <-sCh
	if sr.err != ErrNotPrism {
		t.Fatalf("server err = %v, want ErrNotPrism", sr.err)
	}
	if len(sr.consumed) != 2+noiseMsg1Size {
		t.Fatalf("consumed %d bytes, want the whole first message for cover replay", len(sr.consumed))
	}
	cl.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	if err := <-cErr; err == nil {
		t.Fatal("client without the PSK completed the handshake")
	}
}

func TestNoiseCipherNegotiation(t *testing.T) {
	kp, _ := GenerateServerKeypair()
	psk, _ := NewPSK()
	cred := Credential{ID: ClientID{1, 2, 3, 4}, PSK: psk}

	run := func(client AEADFactory, enabled ...AEADFactory) (*Keys, *Keys, error) {
		cl, sv := net.Pipe()
		defer cl.Close()
		defer sv.Close()
		type res struct {
			k   *Keys
			err error
		}
		ch := make(chan res, 1)
		go func() {
			k, _, _, err := NoiseServerHandshake(sv, kp.Private, []Credential{cred}, nil, time.Minute, enabled...)
			ch <- res{k, err}
		}()
		cl.SetDeadline(time.Now().Add(2 * time.Second))
		ck, cerr := NoiseClientHandshake(cl, kp.Public, cred, client)
		sr := <-ch
		if sr.err != nil {
			return nil, nil, sr.err
		}
		return ck, sr.k, cerr
	}

	// AES listed first, client uses ChaCha: the server must follow the client.
	ck, sk, err := run(NewChaCha20Poly1305AEAD, NewAEAD, NewChaCha20Poly1305AEAD)
	if err != nil {
		t.Fatalf("mixed fleet handshake: %v", err)
	}
	cid, _ := cipherIDOf(ck.aead)
	sid, _ := cipherIDOf(sk.aead)
	if cid != cipherIDChaCha || sid != cipherIDChaCha {
		t.Fatalf("data-phase cipher: client=%d server=%d, want ChaCha on both", cid, sid)
	}

	// A cipher the server did not enable is refused.
	if _, _, err := run(NewChaCha20Poly1305AEAD, NewAEAD); err != ErrNotPrism {
		t.Fatalf("disabled cipher: err = %v, want ErrNotPrism", err)
	}
}

func TestNoiseShortHTTPFallsBackImmediately(t *testing.T) {
	kp, _ := GenerateServerKeypair()
	psk, _ := NewPSK()
	cl, sv := net.Pipe()
	defer cl.Close()
	defer sv.Close()

	req := []byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n")
	go cl.Write(req)
	done := make(chan []byte, 1)
	go func() {
		_, _, consumed, _ := NoiseServerHandshake(sv, kp.Private, []Credential{{PSK: psk}}, nil, time.Minute)
		done <- consumed
	}()
	select {
	case consumed := <-done:
		if string(consumed) != string(req[:len(consumed)]) || len(consumed) == 0 {
			t.Fatalf("consumed %q", consumed)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("server blocked on a short HTTP request instead of falling back")
	}
}
