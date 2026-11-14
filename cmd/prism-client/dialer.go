package main

import (
	"crypto/ecdh"
	"errors"
	"net"
	"sync"
	"time"

	utls "github.com/refraction-networking/utls"

	"github.com/gloridust/prism/pkg/prism"
)

// Dialer keeps a small pool of Prism carrier sessions to the Singapore server
// and hands out multiplexed streams over them. The mux has per-stream credit
// flow control (no head-of-line blocking); the pool adds parallelism and
// failover across carriers.
type Dialer struct {
	server    string
	tlsCfg    *utls.Config
	serverPub *ecdh.PublicKey
	cred      prism.Credential
	aead      prism.AEADFactory

	mu   sync.Mutex
	pool []*prism.Session
	rr   int
}

// NewDialer prepares the pool (connections are established lazily on first use).
func NewDialer(c *ClientConfig, cred *prism.Credential) (*Dialer, error) {
	pub, err := prism.ParseServerPublic(c.ServerPublicKey)
	if err != nil {
		return nil, err
	}
	aead, err := prism.AEADByName(c.cipher())
	if err != nil {
		return nil, err
	}
	return &Dialer{
		server:    c.Server,
		serverPub: pub,
		cred:      *cred,
		aead:      aead,
		pool:      make([]*prism.Session, c.PoolSize),
		// uTLS Config carries only the fields we steer (SNI/ALPN/verify); the
		// ClientHello itself is dictated by the mimicked browser profile below,
		// which is the whole point — Go's native crypto/tls ClientHello is
		// fingerprintable, so we present Chrome's instead.
		tlsCfg: &utls.Config{
			ServerName:         c.SNI,
			InsecureSkipVerify: c.AllowInsecure, // #nosec G402 - gated by config, testing/self-signed
			MinVersion:         utls.VersionTLS12,
			NextProtos:         []string{"http/1.1"},
		},
	}, nil
}

func sessionDead(s *prism.Session) bool {
	if s == nil {
		return true
	}
	select {
	case <-s.Done():
		return true
	default:
		return false
	}
}

func (d *Dialer) dialSession() (*prism.Session, error) {
	raw, err := net.DialTimeout("tcp", d.server, 10*time.Second)
	if err != nil {
		return nil, err
	}
	// Present a current-stable-Chrome ClientHello so the carrier handshake is
	// fingerprint-indistinguishable from an ordinary browser; SNI and ALPN are
	// exactly as configured (our own domain, http/1.1). The prism inner
	// handshake then runs unchanged on top of the established TLS stream.
	tlsConn := utls.UClient(raw, d.tlsCfg, utls.HelloChrome_Auto)
	tlsConn.SetDeadline(time.Now().Add(10 * time.Second))
	if err := tlsConn.Handshake(); err != nil {
		raw.Close()
		return nil, err
	}
	keys, err := prism.ClientHandshake(tlsConn, d.serverPub, d.cred, d.aead)
	if err != nil {
		raw.Close()
		return nil, err
	}
	tlsConn.SetDeadline(time.Time{})
	return prism.NewSession(tlsConn, keys, true)
}

// Open returns a stream to target "host:port", redialing dead carriers.
func (d *Dialer) Open(target string) (*prism.Stream, error) {
	var lastErr error
	n := len(d.pool)
	for attempt := 0; attempt <= n; attempt++ {
		d.mu.Lock()
		i := d.rr % n
		d.rr++
		sess := d.pool[i]
		if sessionDead(sess) {
			ns, err := d.dialSession()
			if err != nil {
				d.mu.Unlock()
				lastErr = err
				continue
			}
			d.pool[i] = ns
			sess = ns
		}
		d.mu.Unlock()

		st, err := sess.OpenStream(target)
		if err == nil {
			return st, nil
		}
		lastErr = err
		d.mu.Lock()
		if d.pool[i] == sess {
			d.pool[i] = nil
		}
		d.mu.Unlock()
	}
	if lastErr == nil {
		lastErr = errors.New("prism: no carrier available")
	}
	return nil, lastErr
}

// OpenConn adapts Open to a net.Conn for use as http.Transport.DialContext.
func (d *Dialer) OpenConn(target string) (net.Conn, error) {
	st, err := d.Open(target)
	if err != nil {
		return nil, err
	}
	return &streamConn{st}, nil
}

// Live reports how many carriers are currently up (for the control panel).
func (d *Dialer) Live() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	n := 0
	for _, s := range d.pool {
		if !sessionDead(s) {
			n++
		}
	}
	return n
}

// Close tears every carrier down.
func (d *Dialer) Close() {
	d.mu.Lock()
	defer d.mu.Unlock()
	for i, s := range d.pool {
		if s != nil {
			s.Close()
			d.pool[i] = nil
		}
	}
}

// streamConn makes a *prism.Stream satisfy net.Conn. Deadlines are no-ops; the
// relay/transport rely on Close to unblock, which is sufficient here.
type streamConn struct{ *prism.Stream }

type dummyAddr struct{}

func (dummyAddr) Network() string { return "prism" }
func (dummyAddr) String() string  { return "prism" }

func (c *streamConn) LocalAddr() net.Addr                { return dummyAddr{} }
func (c *streamConn) RemoteAddr() net.Addr               { return dummyAddr{} }
func (c *streamConn) SetDeadline(t time.Time) error      { return nil }
func (c *streamConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *streamConn) SetWriteDeadline(t time.Time) error { return nil }
