package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"net"
	"time"
)

// destProfile is what a passive observer can learn from the steal target's
// TLS answer: the parameters in its (cleartext) ServerHello and the size of
// its (encrypted) certificate flight.
type destProfile struct {
	version  uint16
	suite    uint16
	alpn     string
	chainLen int // total DER bytes of the certificate chain
}

// probeStealDest handshakes with the real target the way a browser would.
func probeStealDest(dest, sni string) (*destProfile, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	d := tls.Dialer{Config: &tls.Config{ServerName: sni, NextProtos: []string{"h2", "http/1.1"}}}
	c, err := d.DialContext(ctx, "tcp", dest)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	cs := c.(*tls.Conn).ConnectionState()
	p := &destProfile{version: cs.Version, suite: cs.CipherSuite, alpn: cs.NegotiatedProtocol}
	for _, cert := range cs.PeerCertificates {
		p.chainLen += len(cert.Raw)
	}
	return p, nil
}

// stealTLSConfig builds the TLS config shown to marked clients so that, to an
// on-path observer, this server's answer resembles the real target's: same
// ALPN choice and a certificate flight of the same size. Mismatches that
// cannot be papered over are logged, so the operator can pick a better target.
func stealTLSConfig(dest, sni string) (*tls.Config, error) {
	cfg := &tls.Config{MinVersion: tls.VersionTLS13, NextProtos: []string{"h2", "http/1.1"}}
	padTo := 0

	p, err := probeStealDest(dest, sni)
	switch {
	case err != nil:
		log.Printf("WARNING: steal target %s (SNI %s) could not be probed: %v — "+
			"this server's TLS answer to marked clients is not matched to it", dest, sni, err)
	default:
		if p.version != tls.VersionTLS13 {
			log.Printf("WARNING: steal target %s negotiates %s, but marked clients are answered in TLS 1.3 — "+
				"an observer can tell the two apart; choose a TLS 1.3 target", dest, tls.VersionName(p.version))
		}
		if p.suite != tls.TLS_AES_128_GCM_SHA256 {
			log.Printf("NOTE: steal target %s picks %s; this server answers browsers with TLS_AES_128_GCM_SHA256 "+
				"on AES-capable CPUs. Prefer a target that picks the same suite", dest, tls.CipherSuiteName(p.suite))
		}
		switch p.alpn {
		case "h2":
		case "http/1.1":
			cfg.NextProtos = []string{"http/1.1"}
		default:
			cfg.NextProtos = nil
		}
		padTo = p.chainLen
		log.Printf("steal target %s: %s, %s, ALPN %q, %d-byte certificate chain (matched)",
			dest, tls.VersionName(p.version), tls.CipherSuiteName(p.suite), p.alpn, p.chainLen)
	}

	cert, err := selfSignedSized(sni, padTo)
	if err != nil {
		return nil, err
	}
	cfg.Certificates = []tls.Certificate{cert}
	return cfg, nil
}

// padExtOID is a private-arc extension that carries filler bytes.
var padExtOID = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 55555, 1, 1}

// selfSignedSized makes an ephemeral certificate for domain whose DER length is
// size bytes (when size is larger than the certificate would naturally be).
func selfSignedSized(domain string, size int) (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	build := func(pad int) ([]byte, error) {
		tmpl := x509.Certificate{
			SerialNumber: big.NewInt(time.Now().UnixNano()),
			Subject:      pkix.Name{CommonName: domain},
			NotBefore:    time.Now().Add(-time.Hour),
			NotAfter:     time.Now().AddDate(1, 0, 0),
			KeyUsage:     x509.KeyUsageDigitalSignature,
			ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		}
		if ip := net.ParseIP(domain); ip != nil {
			tmpl.IPAddresses = []net.IP{ip}
		} else {
			tmpl.DNSNames = []string{domain}
		}
		if pad > 0 {
			filler := make([]byte, pad)
			rand.Read(filler)
			tmpl.ExtraExtensions = []pkix.Extension{{Id: padExtOID, Value: filler}}
		}
		return x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	}
	der, err := build(0)
	if err != nil {
		return tls.Certificate{}, err
	}
	// ECDSA signatures vary by a byte or two, so converge on the exact size.
	// Each attempt can land a byte or two off, because an ECDSA signature's
	// encoded length varies; keep correcting until one lands exactly.
	for pad, i := size-len(der)-24, 0; len(der) != size && pad > 0 && i < 64; i++ {
		if der, err = build(pad); err != nil {
			return tls.Certificate{}, err
		}
		if len(der) == size {
			break
		}
		pad += size - len(der)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return tls.Certificate{}, err
	}
	cert, err := tls.X509KeyPair(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}))
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("steal certificate: %w", err)
	}
	return cert, nil
}
