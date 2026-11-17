module github.com/gloridust/prism

go 1.26.0

// DEPENDENCY TRADEOFF (production hardening, see README "依赖与取舍"):
// Prism started zero-third-party-dependency (pure Go stdlib). These two direct
// deps are the deliberate cost of real-network hardening and cannot be done in
// the stdlib:
//   - refraction-networking/utls: present a real-browser (Chrome) TLS
//     ClientHello; Go's crypto/tls ClientHello is fingerprintable.
//   - golang.org/x/crypto: ChaCha20-Poly1305 for routers without AES-NI, and
//     acme/autocert for automatic Let's Encrypt certificates.
// All of pkg/prism except the ChaCha cipher remains stdlib-only. Vendor these
// (go mod vendor) if your build host lacks module access.
require (
	github.com/refraction-networking/utls v1.8.2
	golang.org/x/crypto v0.54.0
)

require (
	github.com/andybalholm/brotli v1.0.6 // indirect
	github.com/flynn/noise v1.1.0 // indirect
	github.com/klauspost/compress v1.17.4 // indirect
	github.com/quic-go/quic-go v0.65.0 // indirect
	golang.org/x/net v0.56.0 // indirect
	golang.org/x/sys v0.47.0 // indirect
	golang.org/x/text v0.40.0 // indirect
)
