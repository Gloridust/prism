// Package e2e exercises the full carrier stack the way the deployed client and
// server use it: a uTLS (Chrome-fingerprinted) TLS handshake to a self-signed
// local server, the prism inner handshake on top, then the multiplexed data
// phase — for both the AES-256-GCM and ChaCha20-Poly1305 ciphers, with a 1 MiB
// integrity check and concurrent streams. It lives in its own module path so it
// can import both uTLS and pkg/prism exactly as cmd/prism-client does.
package e2e

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	utls "github.com/refraction-networking/utls"

	"github.com/gloridust/prism/pkg/prism"
)

func selfSignedCert(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		DNSNames:     []string{"localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, _ := x509.MarshalECPrivateKey(key)
	cert, err := tls.X509KeyPair(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}),
	)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

// serveCarrier runs the server side of one accepted TCP connection: real TLS
// termination, prism authentication against the enabled ciphers, then a stream
// echo. Unauthenticated peers are dropped (the real server would serve cover).
func serveCarrier(raw net.Conn, tlsCfg *tls.Config, priv *ecdh.PrivateKey, creds []prism.Credential, aeads []prism.AEADFactory) {
	defer raw.Close()
	tc := tls.Server(raw, tlsCfg)
	_ = tc.SetDeadline(time.Now().Add(10 * time.Second))
	if err := tc.Handshake(); err != nil {
		return
	}
	keys, _, _, err := prism.ServerHandshake(tc, priv, creds, prism.NewReplayWindow(2*time.Minute), 2*time.Minute, aeads...)
	if err != nil {
		return
	}
	_ = tc.SetDeadline(time.Time{})
	sess, err := prism.NewSession(tc, keys, false)
	if err != nil {
		return
	}
	defer sess.Close()
	for {
		st, err := sess.Accept()
		if err != nil {
			return
		}
		go func(st *prism.Stream) {
			io.Copy(st, st)
			st.CloseWrite()
		}(st)
	}
}

func runE2E(t *testing.T, clientCipher string) {
	kp, err := prism.GenerateServerKeypair()
	if err != nil {
		t.Fatal(err)
	}
	psk, err := prism.NewPSK()
	if err != nil {
		t.Fatal(err)
	}
	cred := prism.Credential{ID: prism.ClientID{0x01, 0x02, 0x03, 0x04}, PSK: psk}

	clientAEAD, err := prism.AEADByName(clientCipher)
	if err != nil {
		t.Fatal(err)
	}
	// Server enables BOTH ciphers (a mixed fleet), so the client's choice is
	// discovered by trial-decrypt — no on-wire selector.
	serverAEADs, err := prism.AEADFactoriesByName([]string{prism.CipherAES256GCM, prism.CipherChaCha20Poly1305})
	if err != nil {
		t.Fatal(err)
	}

	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{selfSignedCert(t)},
		MinVersion:   tls.VersionTLS12,
		NextProtos:   []string{"http/1.1"},
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go serveCarrier(conn, tlsCfg, kp.Private, []prism.Credential{cred}, serverAEADs)
		}
	}()

	// --- client: uTLS Chrome fingerprint + prism handshake ---
	raw, err := net.DialTimeout("tcp", ln.Addr().String(), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	uconn := utls.UClient(raw, &utls.Config{
		ServerName:         "localhost",
		InsecureSkipVerify: true, // self-signed, local test only
		MinVersion:         utls.VersionTLS12,
		NextProtos:         []string{"http/1.1"},
	}, utls.HelloChrome_Auto)
	_ = uconn.SetDeadline(time.Now().Add(10 * time.Second))
	if err := uconn.Handshake(); err != nil {
		t.Fatalf("uTLS handshake: %v", err)
	}
	if got := uconn.ConnectionState().NegotiatedProtocol; got != "http/1.1" {
		t.Fatalf("ALPN = %q, want http/1.1", got)
	}
	keys, err := prism.ClientHandshake(uconn, kp.Public, cred, clientAEAD)
	if err != nil {
		t.Fatalf("prism client handshake over uTLS: %v", err)
	}
	_ = uconn.SetDeadline(time.Time{})
	sess, err := prism.NewSession(uconn, keys, true)
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()

	// --- 1 MiB integrity over one stream ---
	t.Run("1MiB-integrity", func(t *testing.T) {
		const size = 1 << 20
		payload := make([]byte, size)
		rand.Read(payload)
		st, err := sess.OpenStream("egress.internal:443")
		if err != nil {
			t.Fatal(err)
		}
		defer st.Close()
		go func() {
			st.Write(payload)
			st.CloseWrite()
		}()
		got := make([]byte, size)
		if _, err := io.ReadFull(st, got); err != nil {
			t.Fatalf("read 1MiB: %v", err)
		}
		if !bytes.Equal(got, payload) {
			t.Fatal("1MiB payload corrupted over uTLS carrier")
		}
	})

	// --- many concurrent streams over the one carrier ---
	t.Run("concurrent-streams", func(t *testing.T) {
		var wg sync.WaitGroup
		for i := 0; i < 16; i++ {
			wg.Add(1)
			go func(n int) {
				defer wg.Done()
				st, err := sess.OpenStream("target:80")
				if err != nil {
					t.Errorf("open %d: %v", n, err)
					return
				}
				defer st.Close()
				sz := 2000 + n*777
				msg := bytes.Repeat([]byte{byte(n)}, sz)
				go func() {
					st.Write(msg)
					st.CloseWrite()
				}()
				got := make([]byte, sz)
				if _, err := io.ReadFull(st, got); err != nil {
					t.Errorf("stream %d read: %v", n, err)
					return
				}
				if !bytes.Equal(got, msg) {
					t.Errorf("stream %d mismatch", n)
				}
			}(i)
		}
		wg.Wait()
	})
}

func TestUTLSPrismEndToEnd(t *testing.T) {
	for _, c := range []string{prism.CipherAES256GCM, prism.CipherChaCha20Poly1305} {
		t.Run(c, func(t *testing.T) { runE2E(t, c) })
	}
}

// --- Steal mode e2e ---

// serveSteal is the steal-mode server: peeks at the ClientHello, verifies the
// steal marker in session_id, and either handles as Prism or relays to a "real"
// target that echoes HTTP.
func serveSteal(raw net.Conn, tlsCfg *tls.Config, priv *ecdh.PrivateKey, creds []prism.Credential, aeads []prism.AEADFactory, realTarget string) {
	defer raw.Close()
	_ = raw.SetReadDeadline(time.Now().Add(10 * time.Second))

	hdr := make([]byte, 5)
	if _, err := io.ReadFull(raw, hdr); err != nil {
		return
	}
	recordLen := prism.ClientHelloRecordLen(hdr)
	if recordLen < 0 || recordLen > 16389 {
		relayTCP(raw, hdr, realTarget)
		return
	}
	record := make([]byte, recordLen)
	copy(record, hdr)
	if _, err := io.ReadFull(raw, record[5:]); err != nil {
		return
	}
	_ = raw.SetReadDeadline(time.Time{})

	sid, err := prism.ParseClientHelloSessionID(record)
	if err != nil {
		relayTCP(raw, record, realTarget)
		return
	}
	if prism.VerifyStealMarker(sid, creds) == nil {
		relayTCP(raw, record, realTarget)
		return
	}

	// Authenticated → replay ClientHello into our TLS, then Prism.
	pc := &prefixReader{buf: record, r: raw}
	tc := tls.Server(&readerConn{ReadWriter: pc, Conn: raw}, tlsCfg)
	_ = tc.SetDeadline(time.Now().Add(10 * time.Second))
	if err := tc.Handshake(); err != nil {
		return
	}
	keys, _, _, err := prism.ServerHandshake(tc, priv, creds, prism.NewReplayWindow(2*time.Minute), 2*time.Minute, aeads...)
	if err != nil {
		return
	}
	_ = tc.SetDeadline(time.Time{})
	sess, err := prism.NewSession(tc, keys, false)
	if err != nil {
		return
	}
	defer sess.Close()
	for {
		st, err := sess.Accept()
		if err != nil {
			return
		}
		go func(st *prism.Stream) {
			io.Copy(st, st)
			st.CloseWrite()
		}(st)
	}
}

// prefixReader replays buf first, then reads from r.
type prefixReader struct {
	buf []byte
	r   io.Reader
}

func (p *prefixReader) Read(b []byte) (int, error) {
	if len(p.buf) > 0 {
		n := copy(b, p.buf)
		p.buf = p.buf[n:]
		return n, nil
	}
	return p.r.Read(b)
}

func (p *prefixReader) Write(b []byte) (int, error) {
	return p.r.(io.Writer).Write(b)
}

// readerConn wraps a ReadWriter + underlying Conn for tls.Server.
type readerConn struct {
	io.ReadWriter
	net.Conn
}

func (c *readerConn) Read(b []byte) (int, error)  { return c.ReadWriter.Read(b) }
func (c *readerConn) Write(b []byte) (int, error) { return c.ReadWriter.Write(b) }

func relayTCP(clientConn net.Conn, buffered []byte, dest string) {
	d, err := net.DialTimeout("tcp", dest, 5*time.Second)
	if err != nil {
		return
	}
	defer d.Close()
	if _, err := d.Write(buffered); err != nil {
		return
	}
	done := make(chan struct{}, 2)
	go func() { io.Copy(d, clientConn); done <- struct{}{} }()
	go func() { io.Copy(clientConn, d); done <- struct{}{} }()
	<-done
}

// TestStealModeEndToEnd verifies that:
//  1. A client with the steal marker completes TLS + Prism handshake + echo.
//  2. A plain browser-like connection gets relayed to the real target.
func TestStealModeEndToEnd(t *testing.T) {
	kp, err := prism.GenerateServerKeypair()
	if err != nil {
		t.Fatal(err)
	}
	psk, err := prism.NewPSK()
	if err != nil {
		t.Fatal(err)
	}
	cred := prism.Credential{ID: prism.ClientID{0xCA, 0xFE, 0xBA, 0xBE}, PSK: psk}
	stealKey := prism.StealKey(psk)

	serverAEADs, _ := prism.AEADFactoriesByName([]string{prism.CipherAES256GCM})

	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{selfSignedCert(t)},
		MinVersion:   tls.VersionTLS12,
		NextProtos:   []string{"h2", "http/1.1"},
	}

	// Start a fake "real target" that just echoes HTTP.
	fakeSite, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer fakeSite.Close()
	go func() {
		for {
			c, err := fakeSite.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				c.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 7\r\n\r\nSTOLEN!"))
				if tc, ok := c.(*net.TCPConn); ok {
					tc.CloseWrite()
				}
				io.Copy(io.Discard, c)
			}()
		}
	}()

	// Start the steal-mode server.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go serveSteal(conn, tlsCfg, kp.Private, []prism.Credential{cred}, serverAEADs, fakeSite.Addr().String())
		}
	}()

	t.Run("authenticated-client", func(t *testing.T) {
		raw, err := net.DialTimeout("tcp", ln.Addr().String(), 5*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		uconn := utls.UClient(raw, &utls.Config{
			ServerName:         "localhost",
			InsecureSkipVerify: true,
			MinVersion:         utls.VersionTLS12,
		}, utls.HelloChrome_Auto)

		// Inject steal marker.
		if err := uconn.BuildHandshakeState(); err != nil {
			t.Fatalf("BuildHandshakeState: %v", err)
		}
		sid := uconn.HandshakeState.Hello.SessionId
		if len(sid) < 32 {
			t.Fatalf("session_id too short: %d", len(sid))
		}
		prism.EmbedStealMarker(sid, stealKey)

		_ = uconn.SetDeadline(time.Now().Add(10 * time.Second))
		if err := uconn.Handshake(); err != nil {
			t.Fatalf("uTLS handshake: %v", err)
		}
		keys, err := prism.ClientHandshake(uconn, kp.Public, cred, prism.NewAEAD)
		if err != nil {
			t.Fatalf("prism handshake over steal: %v", err)
		}
		_ = uconn.SetDeadline(time.Time{})
		sess, err := prism.NewSession(uconn, keys, true)
		if err != nil {
			t.Fatal(err)
		}
		defer sess.Close()

		st, err := sess.OpenStream("echo:80")
		if err != nil {
			t.Fatal(err)
		}
		payload := bytes.Repeat([]byte("steal-"), 1000)
		go func() { st.Write(payload); st.CloseWrite() }()
		got, err := io.ReadAll(st)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, payload) {
			t.Fatalf("echo mismatch: got %d bytes want %d", len(got), len(payload))
		}
	})

	t.Run("unauthenticated-relayed", func(t *testing.T) {
		// A plain TCP connection (no steal marker) should be relayed to the
		// fake site. We send a minimal HTTP-ish request and expect "STOLEN!".
		raw, err := net.DialTimeout("tcp", ln.Addr().String(), 5*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		defer raw.Close()
		_ = raw.SetDeadline(time.Now().Add(5 * time.Second))
		// Send something that is NOT a valid TLS ClientHello.
		raw.Write([]byte("GET / HTTP/1.0\r\n\r\n"))
		buf := make([]byte, 256)
		n, _ := raw.Read(buf)
		if !bytes.Contains(buf[:n], []byte("STOLEN!")) {
			t.Fatalf("expected relay to real target, got: %q", buf[:n])
		}
	})
}

// --- WebSocket transport e2e ---

// serveCarrierOrWS is a combined server: regular TLS Prism connections work
// normally, and an HTTP WebSocket upgrade to wsPath runs Prism inside the WS.
// This mirrors the production server's serveCoverOrWS.
// testOneShotLn feeds a single connection to http.Server for the WS e2e test.
type testOneShotLn struct {
	ch   chan net.Conn
	done chan struct{}
	addr net.Addr
}

func (l *testOneShotLn) Accept() (net.Conn, error) {
	select {
	case c := <-l.ch:
		return c, nil
	case <-l.done:
		return nil, net.ErrClosed
	}
}
func (l *testOneShotLn) Close() error   { return nil }
func (l *testOneShotLn) Addr() net.Addr { return l.addr }

func serveCarrierOrWS(raw net.Conn, tlsCfg *tls.Config, priv *ecdh.PrivateKey, creds []prism.Credential, aeads []prism.AEADFactory, wsPath string) {
	tc := tls.Server(raw, tlsCfg)
	_ = tc.SetDeadline(time.Now().Add(10 * time.Second))
	if err := tc.Handshake(); err != nil {
		raw.Close()
		return
	}

	// Try Prism handshake first (raw TLS path).
	keys, _, consumed, err := prism.ServerHandshake(tc, priv, creds, prism.NewReplayWindow(2*time.Minute), 2*time.Minute, aeads...)
	if err == nil {
		_ = tc.SetDeadline(time.Time{})
		runEchoSession(tc, keys)
		raw.Close()
		return
	}

	// Not a Prism handshake — serve cover or WS upgrade.
	_ = tc.SetDeadline(time.Time{})
	pc := &prefixReader{buf: consumed, r: tc}
	conn := &readerConn{ReadWriter: pc, Conn: tc}

	osl := &testOneShotLn{ch: make(chan net.Conn, 1), done: make(chan struct{}), addr: tc.LocalAddr()}
	osl.ch <- conn

	var wsDone sync.WaitGroup
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ws := prism.WSServerUpgrade(w, r, wsPath)
		if ws == nil {
			w.WriteHeader(200)
			w.Write([]byte("cover"))
			return
		}
		wsDone.Add(1)
		close(osl.done) // unblock Serve's Accept
		defer wsDone.Done()
		defer ws.Close()
		_ = ws.SetReadDeadline(time.Now().Add(10 * time.Second))
		keys, _, _, err := prism.ServerHandshake(ws, priv, creds, prism.NewReplayWindow(2*time.Minute), 2*time.Minute, aeads...)
		if err != nil {
			return
		}
		_ = ws.SetReadDeadline(time.Time{})
		runEchoSession(ws, keys)
	})

	srv := &http.Server{Handler: handler, ReadTimeout: 30 * time.Second, WriteTimeout: 60 * time.Second}
	srv.Serve(osl)
	wsDone.Wait()
	raw.Close()
}

func runEchoSession(transport io.ReadWriteCloser, keys *prism.Keys) {
	sess, err := prism.NewSession(transport, keys, false)
	if err != nil {
		return
	}
	defer sess.Close()
	for {
		st, err := sess.Accept()
		if err != nil {
			return
		}
		go func(st *prism.Stream) {
			io.Copy(st, st)
			st.CloseWrite()
		}(st)
	}
}

func TestWebSocketTransportEndToEnd(t *testing.T) {
	kp, err := prism.GenerateServerKeypair()
	if err != nil {
		t.Fatal(err)
	}
	psk, err := prism.NewPSK()
	if err != nil {
		t.Fatal(err)
	}
	cred := prism.Credential{ID: prism.ClientID{0xDE, 0xAD, 0xBE, 0xEF}, PSK: psk}
	serverAEADs, _ := prism.AEADFactoriesByName([]string{prism.CipherAES256GCM})
	wsPath := "/_prism/ws"

	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{selfSignedCert(t)},
		MinVersion:   tls.VersionTLS12,
		NextProtos:   []string{"http/1.1"},
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go serveCarrierOrWS(conn, tlsCfg, kp.Private, []prism.Credential{cred}, serverAEADs, wsPath)
		}
	}()

	t.Run("ws-echo", func(t *testing.T) {
		raw, err := net.DialTimeout("tcp", ln.Addr().String(), 5*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		uconn := utls.UClient(raw, &utls.Config{
			ServerName:         "localhost",
			InsecureSkipVerify: true,
			MinVersion:         utls.VersionTLS12,
			NextProtos:         []string{"http/1.1"},
		}, utls.HelloChrome_Auto)
		_ = uconn.SetDeadline(time.Now().Add(10 * time.Second))
		if err := uconn.Handshake(); err != nil {
			t.Fatalf("uTLS handshake: %v", err)
		}

		// Upgrade to WebSocket.
		ws, err := prism.WSClientUpgrade(uconn, "localhost", wsPath)
		if err != nil {
			t.Fatalf("WS upgrade: %v", err)
		}

		// Prism handshake inside the WebSocket.
		keys, err := prism.ClientHandshake(ws, kp.Public, cred, prism.NewAEAD)
		if err != nil {
			t.Fatalf("prism handshake over WS: %v", err)
		}
		_ = uconn.SetDeadline(time.Time{})
		sess, err := prism.NewSession(ws, keys, true)
		if err != nil {
			t.Fatal(err)
		}
		defer sess.Close()

		// Echo a payload over WS transport.
		st, err := sess.OpenStream("echo:80")
		if err != nil {
			t.Fatal(err)
		}
		payload := bytes.Repeat([]byte("ws-"), 10000)
		go func() { st.Write(payload); st.CloseWrite() }()
		got, err := io.ReadAll(st)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, payload) {
			t.Fatalf("echo mismatch over WS: got %d bytes want %d", len(got), len(payload))
		}
	})

	t.Run("ws-concurrent-streams", func(t *testing.T) {
		raw, err := net.DialTimeout("tcp", ln.Addr().String(), 5*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		uconn := utls.UClient(raw, &utls.Config{
			ServerName:         "localhost",
			InsecureSkipVerify: true,
			MinVersion:         utls.VersionTLS12,
			NextProtos:         []string{"http/1.1"},
		}, utls.HelloChrome_Auto)
		_ = uconn.SetDeadline(time.Now().Add(10 * time.Second))
		if err := uconn.Handshake(); err != nil {
			t.Fatal(err)
		}
		ws, err := prism.WSClientUpgrade(uconn, "localhost", wsPath)
		if err != nil {
			t.Fatalf("WS upgrade: %v", err)
		}
		keys, err := prism.ClientHandshake(ws, kp.Public, cred, prism.NewAEAD)
		if err != nil {
			t.Fatalf("prism handshake over WS: %v", err)
		}
		_ = uconn.SetDeadline(time.Time{})
		sess, err := prism.NewSession(ws, keys, true)
		if err != nil {
			t.Fatal(err)
		}
		defer sess.Close()

		var wg sync.WaitGroup
		for i := 0; i < 8; i++ {
			wg.Add(1)
			go func(n int) {
				defer wg.Done()
				st, err := sess.OpenStream("target:80")
				if err != nil {
					t.Errorf("open %d: %v", n, err)
					return
				}
				defer st.Close()
				msg := bytes.Repeat([]byte{byte(n)}, 3000+n*500)
				go func() { st.Write(msg); st.CloseWrite() }()
				got := make([]byte, len(msg))
				if _, err := io.ReadFull(st, got); err != nil {
					t.Errorf("stream %d read: %v", n, err)
					return
				}
				if !bytes.Equal(got, msg) {
					t.Errorf("stream %d mismatch", n)
				}
			}(i)
		}
		wg.Wait()
	})
}

// --- Noise_IKpsk2 handshake e2e ---

func serveNoiseCarrier(raw net.Conn, tlsCfg *tls.Config, priv *ecdh.PrivateKey, creds []prism.Credential, aeads []prism.AEADFactory) {
	defer raw.Close()
	tc := tls.Server(raw, tlsCfg)
	_ = tc.SetDeadline(time.Now().Add(10 * time.Second))
	if err := tc.Handshake(); err != nil {
		return
	}
	keys, _, _, err := prism.NoiseServerHandshake(tc, priv, creds, prism.NewReplayWindow(2*time.Minute), 2*time.Minute, aeads...)
	if err != nil {
		return
	}
	_ = tc.SetDeadline(time.Time{})
	runEchoSession(tc, keys)
}

func TestNoiseHandshakeEndToEnd(t *testing.T) {
	kp, err := prism.GenerateServerKeypair()
	if err != nil {
		t.Fatal(err)
	}
	psk, err := prism.NewPSK()
	if err != nil {
		t.Fatal(err)
	}
	cred := prism.Credential{ID: prism.ClientID{0xAA, 0xBB, 0xCC, 0xDD}, PSK: psk}
	serverAEADs, _ := prism.AEADFactoriesByName([]string{prism.CipherAES256GCM})

	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{selfSignedCert(t)},
		MinVersion:   tls.VersionTLS12,
		NextProtos:   []string{"http/1.1"},
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go serveNoiseCarrier(conn, tlsCfg, kp.Private, []prism.Credential{cred}, serverAEADs)
		}
	}()

	t.Run("noise-echo", func(t *testing.T) {
		raw, err := net.DialTimeout("tcp", ln.Addr().String(), 5*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		uconn := utls.UClient(raw, &utls.Config{
			ServerName:         "localhost",
			InsecureSkipVerify: true,
			MinVersion:         utls.VersionTLS12,
			NextProtos:         []string{"http/1.1"},
		}, utls.HelloChrome_Auto)
		_ = uconn.SetDeadline(time.Now().Add(10 * time.Second))
		if err := uconn.Handshake(); err != nil {
			t.Fatalf("uTLS handshake: %v", err)
		}

		keys, err := prism.NoiseClientHandshake(uconn, kp.Public, cred, prism.NewAEAD)
		if err != nil {
			t.Fatalf("Noise handshake: %v", err)
		}
		_ = uconn.SetDeadline(time.Time{})
		sess, err := prism.NewSession(uconn, keys, true)
		if err != nil {
			t.Fatal(err)
		}
		defer sess.Close()

		st, err := sess.OpenStream("echo:80")
		if err != nil {
			t.Fatal(err)
		}
		payload := bytes.Repeat([]byte("noise-ik-"), 5000)
		go func() { st.Write(payload); st.CloseWrite() }()
		got, err := io.ReadAll(st)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, payload) {
			t.Fatalf("echo mismatch over Noise: got %d bytes want %d", len(got), len(payload))
		}
	})

	t.Run("noise-wrong-psk-rejected", func(t *testing.T) {
		raw, err := net.DialTimeout("tcp", ln.Addr().String(), 5*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		uconn := utls.UClient(raw, &utls.Config{
			ServerName:         "localhost",
			InsecureSkipVerify: true,
			MinVersion:         utls.VersionTLS12,
			NextProtos:         []string{"http/1.1"},
		}, utls.HelloChrome_Auto)
		_ = uconn.SetDeadline(time.Now().Add(10 * time.Second))
		if err := uconn.Handshake(); err != nil {
			t.Fatalf("uTLS handshake: %v", err)
		}

		badPSK, _ := prism.NewPSK()
		badCred := prism.Credential{ID: prism.ClientID{0xAA, 0xBB, 0xCC, 0xDD}, PSK: badPSK}
		_, err = prism.NoiseClientHandshake(uconn, kp.Public, badCred, prism.NewAEAD)
		if err == nil {
			t.Fatal("expected Noise handshake to fail with wrong PSK")
		}
	})

	t.Run("noise-concurrent-streams", func(t *testing.T) {
		raw, err := net.DialTimeout("tcp", ln.Addr().String(), 5*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		uconn := utls.UClient(raw, &utls.Config{
			ServerName:         "localhost",
			InsecureSkipVerify: true,
			MinVersion:         utls.VersionTLS12,
			NextProtos:         []string{"http/1.1"},
		}, utls.HelloChrome_Auto)
		_ = uconn.SetDeadline(time.Now().Add(10 * time.Second))
		if err := uconn.Handshake(); err != nil {
			t.Fatalf("uTLS handshake: %v", err)
		}
		keys, err := prism.NoiseClientHandshake(uconn, kp.Public, cred, prism.NewAEAD)
		if err != nil {
			t.Fatal(err)
		}
		_ = uconn.SetDeadline(time.Time{})
		sess, err := prism.NewSession(uconn, keys, true)
		if err != nil {
			t.Fatal(err)
		}
		defer sess.Close()

		var wg sync.WaitGroup
		for i := 0; i < 8; i++ {
			wg.Add(1)
			go func(n int) {
				defer wg.Done()
				st, err := sess.OpenStream("target:80")
				if err != nil {
					t.Errorf("open %d: %v", n, err)
					return
				}
				defer st.Close()
				msg := bytes.Repeat([]byte{byte(n)}, 2000+n*300)
				go func() { st.Write(msg); st.CloseWrite() }()
				got := make([]byte, len(msg))
				if _, err := io.ReadFull(st, got); err != nil {
					t.Errorf("stream %d read: %v", n, err)
					return
				}
				if !bytes.Equal(got, msg) {
					t.Errorf("stream %d mismatch", n)
				}
			}(i)
		}
		wg.Wait()
	})
}

// --- UDP relay e2e ---

func serveUDPEchoCarrier(raw net.Conn, tlsCfg *tls.Config, priv *ecdh.PrivateKey, creds []prism.Credential, aeads []prism.AEADFactory) {
	defer raw.Close()
	tc := tls.Server(raw, tlsCfg)
	_ = tc.SetDeadline(time.Now().Add(10 * time.Second))
	if err := tc.Handshake(); err != nil {
		return
	}
	keys, _, _, err := prism.ServerHandshake(tc, priv, creds, prism.NewReplayWindow(2*time.Minute), 2*time.Minute, aeads...)
	if err != nil {
		return
	}
	_ = tc.SetDeadline(time.Time{})
	sess, err := prism.NewSession(tc, keys, false)
	if err != nil {
		return
	}
	defer sess.Close()
	for {
		st, err := sess.Accept()
		if err != nil {
			return
		}
		if st.IsUDP() {
			go func(st *prism.Stream) {
				defer st.Close()
				for {
					addr, data, err := prism.ReadDatagram(st)
					if err != nil {
						return
					}
					if err := prism.WriteDatagram(st, addr, data); err != nil {
						return
					}
				}
			}(st)
		} else {
			go func(st *prism.Stream) {
				io.Copy(st, st)
				st.CloseWrite()
			}(st)
		}
	}
}

func TestUDPRelayEndToEnd(t *testing.T) {
	kp, err := prism.GenerateServerKeypair()
	if err != nil {
		t.Fatal(err)
	}
	psk, err := prism.NewPSK()
	if err != nil {
		t.Fatal(err)
	}
	cred := prism.Credential{ID: prism.ClientID{0xDA, 0x7A, 0x01, 0x02}, PSK: psk}
	serverAEADs, _ := prism.AEADFactoriesByName([]string{prism.CipherAES256GCM})

	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{selfSignedCert(t)},
		MinVersion:   tls.VersionTLS12,
		NextProtos:   []string{"http/1.1"},
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go serveUDPEchoCarrier(conn, tlsCfg, kp.Private, []prism.Credential{cred}, serverAEADs)
		}
	}()

	raw, err := net.DialTimeout("tcp", ln.Addr().String(), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	uconn := utls.UClient(raw, &utls.Config{
		ServerName:         "localhost",
		InsecureSkipVerify: true,
		MinVersion:         utls.VersionTLS12,
		NextProtos:         []string{"http/1.1"},
	}, utls.HelloChrome_Auto)
	_ = uconn.SetDeadline(time.Now().Add(10 * time.Second))
	if err := uconn.Handshake(); err != nil {
		t.Fatalf("uTLS handshake: %v", err)
	}
	keys, err := prism.ClientHandshake(uconn, kp.Public, cred, prism.NewAEAD)
	if err != nil {
		t.Fatalf("prism handshake: %v", err)
	}
	_ = uconn.SetDeadline(time.Time{})
	sess, err := prism.NewSession(uconn, keys, true)
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()

	t.Run("single-datagram", func(t *testing.T) {
		st, err := sess.OpenUDP()
		if err != nil {
			t.Fatal(err)
		}
		defer st.Close()

		payload := []byte("hello-udp-relay")
		target := "8.8.8.8:53"
		if err := prism.WriteDatagram(st, target, payload); err != nil {
			t.Fatal(err)
		}
		gotAddr, gotData, err := prism.ReadDatagram(st)
		if err != nil {
			t.Fatal(err)
		}
		if gotAddr != target {
			t.Fatalf("addr mismatch: got %q want %q", gotAddr, target)
		}
		if !bytes.Equal(gotData, payload) {
			t.Fatalf("data mismatch: got %q want %q", gotData, payload)
		}
	})

	t.Run("multiple-datagrams", func(t *testing.T) {
		st, err := sess.OpenUDP()
		if err != nil {
			t.Fatal(err)
		}
		defer st.Close()

		targets := []string{"1.1.1.1:53", "8.8.4.4:443", "192.0.2.1:1234"}
		for i, tgt := range targets {
			payload := bytes.Repeat([]byte{byte(i + 0x41)}, 100+i*50)
			if err := prism.WriteDatagram(st, tgt, payload); err != nil {
				t.Fatalf("write dgram %d: %v", i, err)
			}
			gotAddr, gotData, err := prism.ReadDatagram(st)
			if err != nil {
				t.Fatalf("read dgram %d: %v", i, err)
			}
			if gotAddr != tgt {
				t.Fatalf("dgram %d addr: got %q want %q", i, gotAddr, tgt)
			}
			if !bytes.Equal(gotData, payload) {
				t.Fatalf("dgram %d data mismatch", i)
			}
		}
	})

	t.Run("large-datagram", func(t *testing.T) {
		st, err := sess.OpenUDP()
		if err != nil {
			t.Fatal(err)
		}
		defer st.Close()

		payload := make([]byte, 8000)
		rand.Read(payload)
		target := "10.0.0.1:9999"
		if err := prism.WriteDatagram(st, target, payload); err != nil {
			t.Fatal(err)
		}
		gotAddr, gotData, err := prism.ReadDatagram(st)
		if err != nil {
			t.Fatal(err)
		}
		if gotAddr != target {
			t.Fatalf("addr: got %q want %q", gotAddr, target)
		}
		if !bytes.Equal(gotData, payload) {
			t.Fatal("large datagram mismatch")
		}
	})
}

// --- QUIC/H3 transport e2e ---

func serveQUICCarrier(ctx context.Context, addr string, tlsCfg *tls.Config, priv *ecdh.PrivateKey, creds []prism.Credential, aeads []prism.AEADFactory) (*prism.QUICListener, error) {
	ql, err := prism.NewQUICListener(addr, tlsCfg)
	if err != nil {
		return nil, err
	}

	go func() {
		for {
			conn, err := ql.Accept(ctx)
			if err != nil {
				return
			}
			go func(conn *quic.Conn) {
				qc, err := prism.QUICServerAccept(conn, 10*time.Second)
				if err != nil {
					return
				}
				_ = qc.SetDeadline(time.Now().Add(10 * time.Second))
				keys, _, _, err := prism.ServerHandshake(qc, priv, creds, prism.NewReplayWindow(2*time.Minute), 2*time.Minute, aeads...)
				if err != nil {
					qc.Close()
					return
				}
				_ = qc.SetDeadline(time.Time{})
				runEchoSession(qc, keys)
			}(conn)
		}
	}()

	return ql, nil
}

func TestQUICTransportEndToEnd(t *testing.T) {
	kp, err := prism.GenerateServerKeypair()
	if err != nil {
		t.Fatal(err)
	}
	psk, err := prism.NewPSK()
	if err != nil {
		t.Fatal(err)
	}
	cred := prism.Credential{ID: prism.ClientID{0xC0, 0x1C, 0xE0, 0x01}, PSK: psk}
	serverAEADs, _ := prism.AEADFactoriesByName([]string{prism.CipherAES256GCM})

	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{selfSignedCert(t)},
		MinVersion:   tls.VersionTLS13,
		NextProtos:   []string{"h3", "prism-quic"},
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ql, err := serveQUICCarrier(ctx, "127.0.0.1:0", tlsCfg, kp.Private, []prism.Credential{cred}, serverAEADs)
	if err != nil {
		t.Fatal(err)
	}
	defer ql.Close()
	t.Logf("QUIC listener on %s", ql.Addr())

	t.Run("quic-echo", func(t *testing.T) {
		clientTLS := &tls.Config{
			InsecureSkipVerify: true,
			NextProtos:         []string{"h3", "prism-quic"},
		}
		qc, err := prism.QUICClientDial(ql.Addr().String(), clientTLS, 5*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		defer qc.Close()

		keys, err := prism.ClientHandshake(qc, kp.Public, cred, prism.NewAEAD)
		if err != nil {
			t.Fatalf("prism handshake over QUIC: %v", err)
		}
		sess, err := prism.NewSession(qc, keys, true)
		if err != nil {
			t.Fatal(err)
		}
		defer sess.Close()

		st, err := sess.OpenStream("echo:443")
		if err != nil {
			t.Fatal(err)
		}
		payload := bytes.Repeat([]byte("quic-"), 10000)
		go func() { st.Write(payload); st.CloseWrite() }()
		got, err := io.ReadAll(st)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, payload) {
			t.Fatalf("echo mismatch over QUIC: got %d bytes want %d", len(got), len(payload))
		}
	})

	t.Run("quic-concurrent-streams", func(t *testing.T) {
		clientTLS := &tls.Config{
			InsecureSkipVerify: true,
			NextProtos:         []string{"h3", "prism-quic"},
		}
		qc, err := prism.QUICClientDial(ql.Addr().String(), clientTLS, 5*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		defer qc.Close()

		keys, err := prism.ClientHandshake(qc, kp.Public, cred, prism.NewAEAD)
		if err != nil {
			t.Fatalf("prism handshake over QUIC: %v", err)
		}
		sess, err := prism.NewSession(qc, keys, true)
		if err != nil {
			t.Fatal(err)
		}
		defer sess.Close()

		var wg sync.WaitGroup
		for i := 0; i < 8; i++ {
			wg.Add(1)
			go func(n int) {
				defer wg.Done()
				st, err := sess.OpenStream("target:80")
				if err != nil {
					t.Errorf("open %d: %v", n, err)
					return
				}
				defer st.Close()
				msg := bytes.Repeat([]byte{byte(n)}, 3000+n*500)
				go func() { st.Write(msg); st.CloseWrite() }()
				got := make([]byte, len(msg))
				if _, err := io.ReadFull(st, got); err != nil {
					t.Errorf("stream %d read: %v", n, err)
					return
				}
				if !bytes.Equal(got, msg) {
					t.Errorf("stream %d mismatch", n)
				}
			}(i)
		}
		wg.Wait()
	})
}
