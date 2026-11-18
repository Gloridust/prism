package prism

import (
	"bytes"
	"crypto/rand"
	"io"
	"net"
	"testing"
	"time"
)

func testCred(t *testing.T) Credential {
	t.Helper()
	psk, err := NewPSK()
	if err != nil {
		t.Fatal(err)
	}
	return Credential{ID: ClientID{0xDE, 0xAD, 0xBE, 0xEF}, PSK: psk}
}

func TestAEADRoundTrip(t *testing.T) {
	key := make([]byte, keySize)
	rand.Read(key)
	a, err := NewAEAD(key)
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("the quick brown fox")
	ct := a.Seal(7, msg, []byte("ad"))
	pt, err := a.Open(7, ct, []byte("ad"))
	if err != nil || !bytes.Equal(pt, msg) {
		t.Fatalf("roundtrip failed: %v", err)
	}
	if _, err := a.Open(8, ct, []byte("ad")); err == nil {
		t.Fatal("wrong counter must fail")
	}
	if _, err := a.Open(7, ct, []byte("bad")); err == nil {
		t.Fatal("wrong ad must fail")
	}
	ct[0] ^= 1
	if _, err := a.Open(7, ct, []byte("ad")); err == nil {
		t.Fatal("tamper must fail")
	}
}

func TestReplayWindow(t *testing.T) {
	r := NewReplayWindow(time.Minute)
	e := make([]byte, 32)
	rand.Read(e)
	if !r.Accept(e) {
		t.Fatal("first use must be accepted")
	}
	if r.Accept(e) {
		t.Fatal("replay must be rejected")
	}
	e2 := make([]byte, 32)
	rand.Read(e2)
	if !r.Accept(e2) {
		t.Fatal("distinct ephemeral must be accepted")
	}
}

func runHandshake(t *testing.T) (cli, srv *Keys, cliConn, srvConn net.Conn, kp *ServerKeypair, cred Credential) {
	t.Helper()
	kp, err := GenerateServerKeypair()
	if err != nil {
		t.Fatal(err)
	}
	cred = testCred(t)
	cliConn, srvConn = net.Pipe()
	replay := NewReplayWindow(2 * time.Minute)

	type res struct {
		k   *Keys
		err error
	}
	ch := make(chan res, 1)
	go func() {
		k, _, _, err := ServerHandshake(srvConn, kp.Private, []Credential{cred}, replay, 2*time.Minute, NewAEAD)
		ch <- res{k, err}
	}()
	cli, err = ClientHandshake(cliConn, kp.Public, cred, NewAEAD)
	if err != nil {
		t.Fatalf("client handshake: %v", err)
	}
	r := <-ch
	if r.err != nil {
		t.Fatalf("server handshake: %v", r.err)
	}
	srv = r.k
	return
}

func TestHandshakeKeyAgreement(t *testing.T) {
	cli, srv, cliConn, srvConn, _, _ := runHandshake(t)
	defer cliConn.Close()
	defer srvConn.Close()
	if !bytes.Equal(cli.Send, srv.Recv) || !bytes.Equal(cli.Recv, srv.Send) {
		t.Fatal("handshake did not agree on direction keys")
	}
	if bytes.Equal(cli.Send, cli.Recv) {
		t.Fatal("directions must use distinct keys")
	}
}

func TestServerFallbackOnGarbage(t *testing.T) {
	kp, _ := GenerateServerKeypair()
	cred := testCred(t)
	cliConn, srvConn := net.Pipe()
	defer cliConn.Close()
	defer srvConn.Close()

	blob := make([]byte, 100)
	rand.Read(blob)
	go func() { cliConn.Write(blob) }()

	k, _, consumed, err := ServerHandshake(srvConn, kp.Private,
		[]Credential{cred}, NewReplayWindow(time.Minute), time.Minute, NewAEAD)
	if err != ErrNotPrism || k != nil {
		t.Fatalf("expected fallback, got k=%v err=%v", k, err)
	}
	if !bytes.Equal(consumed, blob[:clientInitSize]) {
		t.Fatal("fallback must return consumed bytes for cover replay")
	}
}

func TestSessionEcho(t *testing.T) {
	cli, srv, cliConn, srvConn, _, _ := runHandshake(t)
	defer cliConn.Close()
	defer srvConn.Close()

	cs, err := NewSession(cliConn, cli, true)
	if err != nil {
		t.Fatal(err)
	}
	ss, err := NewSession(srvConn, srv, false)
	if err != nil {
		t.Fatal(err)
	}

	// Server: accept streams and echo.
	go func() {
		for {
			st, err := ss.Accept()
			if err != nil {
				return
			}
			go func(st *Stream) {
				io.Copy(st, st)
				st.CloseWrite()
			}(st)
		}
	}()

	st, err := cs.OpenStream("example.com:80")
	if err != nil {
		t.Fatal(err)
	}
	payload := bytes.Repeat([]byte("prism-"), 5000) // ~30KB, spans frames
	go func() {
		st.Write(payload)
		st.CloseWrite()
	}()

	got, err := io.ReadAll(st)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("echo mismatch: got %d bytes want %d", len(got), len(payload))
	}
}

func TestSessionStreamTargetPropagation(t *testing.T) {
	cli, srv, cliConn, srvConn, _, _ := runHandshake(t)
	defer cliConn.Close()
	defer srvConn.Close()

	cs, _ := NewSession(cliConn, cli, true)
	ss, _ := NewSession(srvConn, srv, false)

	want := "1.2.3.4:443"
	go cs.OpenStream(want)
	st, err := ss.Accept()
	if err != nil {
		t.Fatal(err)
	}
	if st.Target() != want {
		t.Fatalf("target = %q, want %q", st.Target(), want)
	}
}

// A complete HTTP request shorter than a ClientInit must fall back to cover
// immediately — not block until the handshake deadline, which would be a timing
// tell under active probing — and hand back exactly the bytes consumed.
func TestServerFallbackOnShortHTTPRequest(t *testing.T) {
	kp, _ := GenerateServerKeypair()
	cred := testCred(t)
	cliConn, srvConn := net.Pipe()
	defer cliConn.Close()
	defer srvConn.Close()

	req := []byte("GET / HTTP/1.1\r\nHost: sg.example.com\r\n\r\n")
	if len(req) >= clientInitSize {
		t.Fatalf("test request must be shorter than a ClientInit (%d)", len(req))
	}
	go func() { cliConn.Write(req) }() // peer then stays open and silent, like a browser awaiting a reply

	type out struct {
		consumed []byte
		err      error
	}
	ch := make(chan out, 1)
	go func() {
		_, _, consumed, err := ServerHandshake(srvConn, kp.Private,
			[]Credential{cred}, NewReplayWindow(time.Minute), time.Minute)
		ch <- out{consumed, err}
	}()
	select {
	case o := <-ch:
		if o.err != ErrNotPrism {
			t.Fatalf("expected ErrNotPrism, got %v", o.err)
		}
		if !bytes.Equal(o.consumed, req) {
			t.Fatalf("consumed = %q, want the full request for cover replay", o.consumed)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("server blocked on a complete short HTTP request (probe timing tell)")
	}
}

func TestAddrRejectsHostileDomains(t *testing.T) {
	for _, host := range []string{"", "a b.com", "a\nb.com", "ex[ample.com", "a:b", "a/b", "evil.com\x00", "host%eth0"} {
		if _, err := EncodeAddr(net.JoinHostPort(host, "80")); err == nil && host != "" {
			t.Errorf("EncodeAddr accepted host %q", host)
		}
		raw := append([]byte{atypDomain, byte(len(host))}, host...)
		raw = append(raw, 0, 80)
		if _, err := DecodeAddr(raw); err == nil {
			t.Errorf("DecodeAddr accepted host %q", host)
		}
	}
	for _, hp := range []string{"example.com:443", "xn--fiqs8s.example:80", "_dmarc.a-b.example:53", "1.2.3.4:1", "[2001:db8::1]:2"} {
		b, err := EncodeAddr(hp)
		if err != nil {
			t.Fatalf("EncodeAddr(%q): %v", hp, err)
		}
		if got, err := DecodeAddr(b); err != nil || got != hp {
			t.Fatalf("round trip %q -> %q, %v", hp, got, err)
		}
	}
}
