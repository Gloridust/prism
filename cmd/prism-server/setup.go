package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"os"
	"time"

	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"

	"github.com/gloridust/prism/pkg/prism"
)

// buildTLSConfig builds the carrier TLS config. Precedence:
//  1. ACME (automatic Let's Encrypt) — preferred for production.
//  2. cert_file + key_file — e.g. a certbot-issued cert you renew yourself.
//  3. self_signed — LOCAL TESTING ONLY; a careful prober will distinguish it.
func buildTLSConfig(c *Config) (*tls.Config, error) {
	if c.ACME != nil && c.ACME.Enabled {
		return acmeTLSConfig(c.ACME)
	}

	var cert tls.Certificate
	var err error
	switch {
	case c.CertFile != "" && c.KeyFile != "":
		cert, err = tls.LoadX509KeyPair(c.CertFile, c.KeyFile)
	case c.SelfSigned != "":
		log.Printf("WARNING: self-signed certificate for %q — TESTING ONLY. A careful "+
			"prober will distinguish it from a real site; configure acme{} or "+
			"cert_file+key_file for production.", c.SelfSigned)
		cert, err = selfSigned(c.SelfSigned)
	default:
		return nil, fmt.Errorf("configure acme (recommended), cert_file+key_file, or self_signed (testing only)")
	}
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
		// Advertise only HTTP/1.1: the cover fallback is an HTTP/1.1 server, and
		// a consistent ALPN avoids the "ALPN says h2 but traffic isn't h2" tell.
		// Production hardening: serve real h2/h3 cover and match it here.
		NextProtos: []string{"http/1.1"},
	}, nil
}

// acmeTLSConfig wires golang.org/x/crypto/acme/autocert for automatic issuance
// and renewal via the TLS-ALPN-01 challenge. That challenge rides this server's
// existing :443 listener — autocert's GetCertificate answers the acme-tls/1
// handshake transparently — so no port 80 and no extra web server are needed.
// Requirements: the domains resolve to this box and 443 is reachable from the
// internet.
func acmeTLSConfig(a *ACMEConfig) (*tls.Config, error) {
	if len(a.Domains) == 0 {
		return nil, fmt.Errorf("acme.enabled requires at least one domain in acme.domains")
	}
	cacheDir := a.CacheDir
	if cacheDir == "" {
		cacheDir = "/etc/prism/acme"
	}
	if err := os.MkdirAll(cacheDir, 0o700); err != nil {
		return nil, fmt.Errorf("acme cache dir %s: %w", cacheDir, err)
	}
	m := &autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		HostPolicy: autocert.HostWhitelist(a.Domains...),
		Cache:      autocert.DirCache(cacheDir),
		Email:      a.Email,
	}
	if a.DirectoryURL != "" {
		m.Client = &acme.Client{DirectoryURL: a.DirectoryURL}
	}
	tc := m.TLSConfig()
	// autocert advertises h2+http/1.1+acme-tls/1; we serve only HTTP/1.1 cover,
	// so drop h2 to keep ALPN consistent with the carrier/cover while preserving
	// the acme-tls/1 entry autocert needs to answer the challenge handshake.
	tc.NextProtos = []string{"http/1.1", acme.ALPNProto}
	tc.MinVersion = tls.VersionTLS12
	log.Printf("ACME enabled for %v (cache %s); first handshake per domain fetches a cert via TLS-ALPN-01", a.Domains, cacheDir)
	return tc, nil
}

func selfSigned(domain string) (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: domain},
		DNSNames:     []string{domain},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().AddDate(1, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	keyDER, _ := x509.MarshalECPrivateKey(key)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return tls.X509KeyPair(certPEM, keyPEM)
}

// runKeygen prints a ready-to-edit server identity plus one client credential.
func runKeygen(domain string) error {
	kp, err := prism.GenerateServerKeypair()
	if err != nil {
		return err
	}
	id := make([]byte, 4)
	rand.Read(id)
	psk, err := prism.NewPSK()
	if err != nil {
		return err
	}
	priv := prism.EncodeKey(kp.Private.Bytes())
	pub := prism.EncodeKey(kp.Public.Bytes())
	idB64 := prism.EncodeKey(id)
	pskB64 := prism.EncodeKey(psk)

	if domain == "" {
		domain = "sg.example.com"
	}

	fmt.Printf(`# ---- prism keygen ----
# Server identity (keep private_key SECRET, on the Singapore box only):
#   private_key: %s
#   public_key : %s   <- clients need this
#
# One client credential (provision one per office/device; revoke by removing):
#   id : %s
#   psk: %s

## paste into server.json (self_signed is TESTING ONLY; for production set
## "acme":{"enabled":true,"domains":["%s"],"email":"you@example.com"} and drop
## self_signed. List "chacha20-poly1305" in "ciphers" too to serve routers.):
{
  "listen": ":443",
  "self_signed": "%s",
  "private_key": "%s",
  "credentials": [
    { "name": "office-1", "id": "%s", "psk": "%s" }
  ],
  "ciphers": ["aes-256-gcm"],
  "window_seconds": 120,
  "cover_backend": ""
}

## paste into client.json (set "cipher":"chacha20-poly1305" on routers without
## AES-NI; it must also be in the server's "ciphers". allow_insecure=true only
## matches self_signed — set it back to false once you use a real/ACME cert.):
{
  "server": "%s:443",
  "sni": "%s",
  "server_public_key": "%s",
  "id": "%s",
  "psk": "%s",
  "allow_insecure": true,
  "cipher": "aes-256-gcm",
  "socks_listen": "127.0.0.1:1080"
}
`,
		priv, pub, idB64, pskB64,
		domain, domain, priv, idB64, pskB64,
		domain, domain, pub, idB64, pskB64)
	return nil
}
