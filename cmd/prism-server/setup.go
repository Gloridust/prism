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
	"math/big"
	"time"

	"github.com/gloridust/prism/pkg/prism"
)

// buildTLSConfig loads the carrier TLS cert. A real certificate for your own
// domain is strongly preferred; self-signed is testing-only.
func buildTLSConfig(c *Config) (*tls.Config, error) {
	var cert tls.Certificate
	var err error
	switch {
	case c.CertFile != "" && c.KeyFile != "":
		cert, err = tls.LoadX509KeyPair(c.CertFile, c.KeyFile)
	case c.SelfSigned != "":
		cert, err = selfSigned(c.SelfSigned)
	default:
		return nil, fmt.Errorf("configure cert_file+key_file (recommended) or self_signed")
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

## paste into server.json:
{
  "listen": ":443",
  "self_signed": "%s",
  "private_key": "%s",
  "credentials": [
    { "name": "office-1", "id": "%s", "psk": "%s" }
  ],
  "window_seconds": 120,
  "cover_backend": ""
}

## paste into client.json:
{
  "server": "%s:443",
  "sni": "%s",
  "server_public_key": "%s",
  "id": "%s",
  "psk": "%s",
  "allow_insecure": true,
  "socks_listen": "127.0.0.1:1080"
}
`,
		priv, pub, idB64, pskB64,
		domain, priv, idB64, pskB64,
		domain, domain, pub, idB64, pskB64)
	return nil
}
