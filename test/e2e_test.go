// Package e2e exercises the full carrier stack the way the deployed client and
// server use it: a uTLS (Chrome-fingerprinted) TLS handshake to a self-signed
// local server, the prism inner handshake on top, then the multiplexed data
// phase — for both the AES-256-GCM and ChaCha20-Poly1305 ciphers, with a 1 MiB
// integrity check and concurrent streams. It lives in its own module path so it
// can import both uTLS and pkg/prism exactly as cmd/prism-client does.
package e2e

import (
	"bytes"
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
	"sync"
	"testing"
	"time"

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
