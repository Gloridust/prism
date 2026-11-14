package prism

import (
	"bytes"
	"crypto/rand"
	"io"
	"net"
	"testing"
	"time"
)

func TestChaChaAEADRoundTrip(t *testing.T) {
	key := make([]byte, keySize)
	rand.Read(key)
	a, err := NewChaCha20Poly1305AEAD(key)
	if err != nil {
		t.Fatal(err)
	}
	if a.Overhead() != tagSize {
		t.Fatalf("overhead = %d, want %d", a.Overhead(), tagSize)
	}
	msg := []byte("the quick brown fox jumps over the lazy dog")
	ct := a.Seal(42, msg, []byte("ad"))
	pt, err := a.Open(42, ct, []byte("ad"))
	if err != nil || !bytes.Equal(pt, msg) {
		t.Fatalf("roundtrip failed: %v", err)
	}
	if _, err := a.Open(43, ct, []byte("ad")); err == nil {
		t.Fatal("wrong counter must fail")
	}
	if _, err := a.Open(42, ct, []byte("bad")); err == nil {
		t.Fatal("wrong ad must fail")
	}
	ct[0] ^= 1
	if _, err := a.Open(42, ct, []byte("ad")); err == nil {
		t.Fatal("tamper must fail")
	}
	if _, err := NewChaCha20Poly1305AEAD(make([]byte, 16)); err == nil {
		t.Fatal("short key must be rejected")
	}
}

// ChaCha and AES must share the wire framing (12B nonce, 16B tag) so the server
// can trial both against a fixed-length ClientInit, but they are different
// ciphers: the same key/counter/plaintext must NOT produce the same bytes.
func TestChaChaWireShapeMatchesAES(t *testing.T) {
	key := make([]byte, keySize)
	rand.Read(key)
	aes, _ := NewAEAD(key)
	cha, _ := NewChaCha20Poly1305AEAD(key)
	if aes.Overhead() != cha.Overhead() {
		t.Fatalf("overhead differs: aes=%d chacha=%d", aes.Overhead(), cha.Overhead())
	}
	msg := bytes.Repeat([]byte("x"), 64)
	ca := aes.Seal(0, msg, nil)
	cc := cha.Seal(0, msg, nil)
	if len(ca) != len(cc) {
		t.Fatalf("ciphertext length differs: aes=%d chacha=%d", len(ca), len(cc))
	}
	if bytes.Equal(ca, cc) {
		t.Fatal("AES and ChaCha produced identical ciphertext — not distinct ciphers")
	}
}

func TestAEADByName(t *testing.T) {
	for name, wantOK := range map[string]bool{
		"":                     true, // default
		CipherAES256GCM:        true,
		CipherChaCha20Poly1305: true,
		"rc4":                  false,
	} {
		f, err := AEADByName(name)
		if wantOK && (err != nil || f == nil) {
			t.Fatalf("AEADByName(%q) = (%v, %v), want ok", name, f, err)
		}
		if !wantOK && err == nil {
			t.Fatalf("AEADByName(%q) must error on unknown cipher", name)
		}
	}
}

func TestAEADFactoriesByName(t *testing.T) {
	fs, err := AEADFactoriesByName(nil)
	if err != nil || len(fs) != 1 {
		t.Fatalf("empty => default AES only: len=%d err=%v", len(fs), err)
	}
	fs, err = AEADFactoriesByName([]string{"aes-256-gcm", "chacha20-poly1305", "aes-256-gcm"})
	if err != nil || len(fs) != 2 {
		t.Fatalf("dedup to 2: len=%d err=%v", len(fs), err)
	}
	if _, err := AEADFactoriesByName([]string{"bogus"}); err == nil {
		t.Fatal("unknown cipher in list must error")
	}
}

// handshakePair runs a full client/server handshake over an in-memory pipe with
// the given client cipher and server-enabled cipher set, returning both sides'
// results. A deadline plus closing the server pipe on failure keeps a cipher
// mismatch from blocking the client's response read forever.
func handshakePair(t *testing.T, clientAEAD AEADFactory, serverAEADs ...AEADFactory) (cliKeys, srvKeys *Keys, cliConn, srvConn net.Conn, cliErr, srvErr error) {
	t.Helper()
	kp, err := GenerateServerKeypair()
	if err != nil {
		t.Fatal(err)
	}
	cred := testCred(t)
	cliConn, srvConn = net.Pipe()
	deadline := time.Now().Add(5 * time.Second)
	_ = cliConn.SetDeadline(deadline)
	_ = srvConn.SetDeadline(deadline)

	replay := NewReplayWindow(2 * time.Minute)
	type sres struct {
		k   *Keys
		err error
	}
	ch := make(chan sres, 1)
	go func() {
		k, _, _, err := ServerHandshake(srvConn, kp.Private, []Credential{cred}, replay, 2*time.Minute, serverAEADs...)
		if err != nil {
			srvConn.Close() // unblock the client's response read immediately
		}
		ch <- sres{k, err}
	}()
	cliKeys, cliErr = ClientHandshake(cliConn, kp.Public, cred, clientAEAD)
	r := <-ch
	srvKeys, srvErr = r.k, r.err
	_ = cliConn.SetDeadline(time.Time{})
	_ = srvConn.SetDeadline(time.Time{})
	return
}

// echoRoundTrip builds sessions from both sides' keys and verifies a payload
// echoes back intact — which only works if BOTH ends agreed on the same
// data-phase cipher.
func echoRoundTrip(t *testing.T, cli, srv *Keys, cc, sc net.Conn) {
	t.Helper()
	cs, err := NewSession(cc, cli, true)
	if err != nil {
		t.Fatal(err)
	}
	ss, err := NewSession(sc, srv, false)
	if err != nil {
		t.Fatal(err)
	}
	defer cs.Close()
	defer ss.Close()
	go echoServer(ss)

	st, err := cs.OpenStream("example.com:443")
	if err != nil {
		t.Fatal(err)
	}
	payload := bytes.Repeat([]byte("prism-chacha-"), 8192) // ~100KB, spans frames
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

func TestChaChaHandshakeAndSession(t *testing.T) {
	cli, srv, cc, sc, cerr, serr := handshakePair(t, NewChaCha20Poly1305AEAD, NewChaCha20Poly1305AEAD)
	defer cc.Close()
	defer sc.Close()
	if cerr != nil || serr != nil {
		t.Fatalf("handshake failed: cli=%v srv=%v", cerr, serr)
	}
	if !bytes.Equal(cli.Send, srv.Recv) || !bytes.Equal(cli.Recv, srv.Send) {
		t.Fatal("handshake did not agree on direction keys")
	}
	echoRoundTrip(t, cli, srv, cc, sc)
}

// The whole point of trial-decrypt: one server endpoint carries a mixed fleet,
// and a client whose cipher the server does not enable falls through to cover.
func TestCipherNegotiationMatrix(t *testing.T) {
	aes := AEADFactory(NewAEAD)
	cha := AEADFactory(NewChaCha20Poly1305AEAD)
	cases := []struct {
		name      string
		client    AEADFactory
		server    []AEADFactory
		wantMatch bool
	}{
		{"aes client / aes server", aes, []AEADFactory{aes}, true},
		{"chacha client / mixed server", cha, []AEADFactory{aes, cha}, true},
		{"aes client / mixed server", aes, []AEADFactory{aes, cha}, true},
		{"chacha client / aes-only server", cha, []AEADFactory{aes}, false},
		{"aes client / chacha-only server", aes, []AEADFactory{cha}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cli, srv, cc, sc, cerr, serr := handshakePair(t, c.client, c.server...)
			defer cc.Close()
			defer sc.Close()
			if c.wantMatch {
				if cerr != nil || serr != nil {
					t.Fatalf("expected a match: cli=%v srv=%v", cerr, serr)
				}
				echoRoundTrip(t, cli, srv, cc, sc)
				return
			}
			if serr != ErrNotPrism {
				t.Fatalf("cipher mismatch: server err = %v, want ErrNotPrism (cover fallback)", serr)
			}
			if cerr == nil {
				t.Fatal("cipher mismatch: client handshake should fail")
			}
		})
	}
}
