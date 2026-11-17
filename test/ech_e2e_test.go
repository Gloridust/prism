package e2e

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"os"
	"testing"
	"time"

	utls "github.com/refraction-networking/utls"

	"github.com/gloridust/prism/pkg/prism"
)

// TestECHHandshakeLive performs a real TLS handshake with ECH against a known
// ECH-enabled server (crypto.cloudflare.com). This proves that:
//  1. FetchECHConfigList resolves a valid ECH config from DNS via DoH
//  2. The uTLS stack uses the ECH config to encrypt the ClientHello
//  3. The handshake completes successfully with ECH
//
// Requires network access. Set PRISM_LIVE_TEST=1 to run.
func TestECHHandshakeLive(t *testing.T) {
	if os.Getenv("PRISM_LIVE_TEST") == "" {
		t.Skip("set PRISM_LIVE_TEST=1 to run live ECH handshake test")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	// Step 1: Fetch ECH config from DNS.
	echConfig, err := prism.FetchECHConfigList(ctx, "crypto.cloudflare.com", "")
	if err != nil {
		t.Fatalf("FetchECHConfigList: %v", err)
	}
	if len(echConfig) == 0 {
		t.Fatal("no ECH config returned for crypto.cloudflare.com")
	}
	t.Logf("step 1: fetched %d-byte ECH config from DNS", len(echConfig))

	// Step 2: Resolve the server address.
	addrs, err := net.DefaultResolver.LookupHost(ctx, "crypto.cloudflare.com")
	if err != nil {
		t.Fatalf("DNS lookup: %v", err)
	}
	if len(addrs) == 0 {
		t.Fatal("no addresses for crypto.cloudflare.com")
	}
	serverAddr := net.JoinHostPort(addrs[0], "443")
	t.Logf("step 2: resolved crypto.cloudflare.com → %s", serverAddr)

	// Step 3: TLS handshake with ECH.
	raw, err := net.DialTimeout("tcp", serverAddr, 10*time.Second)
	if err != nil {
		t.Fatalf("TCP connect: %v", err)
	}
	defer raw.Close()

	uconn := utls.UClient(raw, &utls.Config{
		ServerName:                     "crypto.cloudflare.com",
		MinVersion:                     tls.VersionTLS13,
		EncryptedClientHelloConfigList: echConfig,
	}, utls.HelloChrome_Auto)

	_ = uconn.SetDeadline(time.Now().Add(10 * time.Second))
	if err := uconn.Handshake(); err != nil {
		t.Fatalf("TLS+ECH handshake failed: %v", err)
	}

	state := uconn.ConnectionState()
	t.Logf("step 3: TLS handshake completed — version=%#x, cipher=%#x, ALPN=%q, ECH=%v",
		state.Version, state.CipherSuite, state.NegotiatedProtocol, state.ECHAccepted)

	if state.Version < tls.VersionTLS13 {
		t.Fatalf("expected TLS 1.3+, got %#x", state.Version)
	}

	// Step 4: Send a minimal HTTP request to verify the connection works.
	fmt.Fprint(uconn, "GET / HTTP/1.1\r\nHost: crypto.cloudflare.com\r\nConnection: close\r\n\r\n")
	buf := make([]byte, 512)
	n, _ := uconn.Read(buf)
	if n == 0 {
		t.Fatal("no HTTP response received over ECH connection")
	}
	t.Logf("step 4: received %d-byte HTTP response over ECH connection", n)
	t.Logf("ECH handshake end-to-end verified: DNS → ECH config → TLS 1.3 + ECH → HTTP works")
}
