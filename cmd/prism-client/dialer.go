package main

import (
	"crypto/ecdh"
	"crypto/tls"
	"errors"
	"io"
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
//
// Each pool slot carries its own mutex that serialises (re)dialing THAT slot,
// so a dial (TCP+TLS+handshake, up to ~10s) never holds a pool-wide lock: a
// burst of new connections at startup — or after a carrier drops — dials up to
// PoolSize carriers in parallel instead of queuing behind one slow dial, while
// two requests racing on the same dead slot still dial only once.
type Dialer struct {
	server    string
	sni       string
	tlsCfg    *utls.Config
	serverPub *ecdh.PublicKey
	cred      prism.Credential
	aead      prism.AEADFactory
	shaping     string
	stealKey    []byte // non-nil in steal mode
	wsPath      string // non-empty = WebSocket transport
	maxLifetime time.Duration
	iatMaxMs    int
	useNoise    bool   // use audited Noise_IKpsk2 handshake
	useQUIC     bool   // use QUIC/H3 transport

	pool []*carrier

	rrMu sync.Mutex
	rr   int
}

// carrier is one pool slot: a (lazily dialed) session guarded by its own mutex.
type carrier struct {
	mu   sync.Mutex // serialises (re)dial of this slot
	sess *prism.Session
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
	pool := make([]*carrier, c.PoolSize)
	for i := range pool {
		pool[i] = &carrier{}
	}
	var stealKey []byte
	skipVerify := c.AllowInsecure
	if c.Steal {
		stealKey = prism.StealKey(cred.PSK)
		skipVerify = true // outer TLS cert is ephemeral; real auth is the inner Prism handshake
	}
	var wsPath string
	if c.Transport == "ws" {
		wsPath = c.WSPath
		if wsPath == "" {
			wsPath = "/_prism/ws"
		}
	}
	var maxLife time.Duration
	if c.MaxLifetimeSec > 0 {
		maxLife = time.Duration(c.MaxLifetimeSec) * time.Second
	}
	return &Dialer{
		server:    c.Server,
		sni:       c.SNI,
		serverPub: pub,
		cred:      *cred,
		aead:      aead,
		shaping:   c.Shaping,
		stealKey:    stealKey,
		wsPath:      wsPath,
		maxLifetime: maxLife,
		iatMaxMs:    c.IATMaxMs,
		useNoise:    c.Handshake == "noise",
		useQUIC:     c.Transport == "quic",
		pool:        pool,
		// uTLS Config carries only the fields we steer (SNI/ALPN/verify); the
		// ClientHello itself is dictated by the mimicked browser profile below,
		// which is the whole point — Go's native crypto/tls ClientHello is
		// fingerprintable, so we present Chrome's instead.
		tlsCfg: &utls.Config{
			ServerName:         c.SNI,
			InsecureSkipVerify: skipVerify, // #nosec G402 - gated by config or steal mode
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
		return s.Draining()
	}
}

func (d *Dialer) dialSession() (*prism.Session, error) {
	if d.useQUIC {
		return d.dialQUICSession()
	}
	raw, err := net.DialTimeout("tcp", d.server, 10*time.Second)
	if err != nil {
		return nil, err
	}
	// Present a current-stable-Chrome ClientHello so the carrier handshake is
	// fingerprint-indistinguishable from an ordinary browser. SNI is our own
	// domain as configured; the ALPN list is Chrome's own (h2, http/1.1) since
	// the preset dictates the extensions, and the server — which only offers
	// http/1.1 — selects http/1.1, exactly as a real Chrome would experience
	// against an HTTP/1.1-only site. The prism inner handshake then runs
	// unchanged on top of the established TLS stream.
	tlsConn := utls.UClient(raw, d.tlsCfg, utls.HelloChrome_Auto)
	if d.stealKey != nil {
		// Steal mode: embed an HMAC tag in the TLS session_id so the server
		// can distinguish us from probers before completing TLS. Build the
		// ClientHello first, inject the marker, then send it.
		if err := tlsConn.BuildHandshakeState(); err != nil {
			raw.Close()
			return nil, err
		}
		sid := tlsConn.HandshakeState.Hello.SessionId
		if len(sid) >= 32 {
			prism.EmbedStealMarker(sid, d.stealKey)
		}
	}
	tlsConn.SetDeadline(time.Now().Add(10 * time.Second))
	if err := tlsConn.Handshake(); err != nil {
		raw.Close()
		return nil, err
	}

	// Choose transport: raw TLS stream or WebSocket inside TLS.
	var transport io.ReadWriteCloser = tlsConn
	if d.wsPath != "" {
		ws, err := prism.WSClientUpgrade(tlsConn, d.sni, d.wsPath)
		if err != nil {
			raw.Close()
			return nil, err
		}
		transport = ws
	}

	var keys *prism.Keys
	if d.useNoise {
		keys, err = prism.NoiseClientHandshake(transport, d.serverPub, d.cred, d.aead)
	} else {
		keys, err = prism.ClientHandshake(transport, d.serverPub, d.cred, d.aead)
	}
	if err != nil {
		raw.Close()
		return nil, err
	}
	tlsConn.SetDeadline(time.Time{})
	opts := []prism.Option{prism.WithShaping(d.shaping)}
	if d.maxLifetime > 0 {
		opts = append(opts, prism.WithMaxLifetime(d.maxLifetime))
	}
	if d.iatMaxMs > 0 {
		opts = append(opts, prism.WithIAT(d.iatMaxMs))
	}
	return prism.NewSession(transport, keys, true, opts...)
}

func (d *Dialer) dialQUICSession() (*prism.Session, error) {
	tlsCfg := &tls.Config{
		ServerName:         d.sni,
		InsecureSkipVerify: d.stealKey != nil,
		MinVersion:         tls.VersionTLS12,
		NextProtos:         []string{"h3", "prism-quic"},
	}
	qc, err := prism.QUICClientDial(d.server, tlsCfg, 10*time.Second)
	if err != nil {
		return nil, err
	}
	var keys *prism.Keys
	if d.useNoise {
		keys, err = prism.NoiseClientHandshake(qc, d.serverPub, d.cred, d.aead)
	} else {
		keys, err = prism.ClientHandshake(qc, d.serverPub, d.cred, d.aead)
	}
	if err != nil {
		qc.Close()
		return nil, err
	}
	opts := []prism.Option{prism.WithShaping(d.shaping)}
	if d.maxLifetime > 0 {
		opts = append(opts, prism.WithMaxLifetime(d.maxLifetime))
	}
	if d.iatMaxMs > 0 {
		opts = append(opts, prism.WithIAT(d.iatMaxMs))
	}
	return prism.NewSession(qc, keys, true, opts...)
}

// nextSlot returns the next pool slot round-robin (brief lock, no dial).
func (d *Dialer) nextSlot() *carrier {
	d.rrMu.Lock()
	c := d.pool[d.rr%len(d.pool)]
	d.rr++
	d.rrMu.Unlock()
	return c
}

// ensure returns a live session for slot c, dialing one if needed. The dial
// runs under c's own mutex only, so other slots dial concurrently and the
// pool-wide round-robin lock is never held across a network round trip.
func (d *Dialer) ensure(c *carrier) (*prism.Session, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !sessionDead(c.sess) {
		return c.sess, nil
	}
	ns, err := d.dialSession()
	if err != nil {
		return nil, err
	}
	c.sess = ns
	return ns, nil
}

// openWith tries each slot at most once, (re)dialing dead carriers, and opens a
// stream via the given opener (TCP or UDP).
func (d *Dialer) openWith(open func(*prism.Session) (*prism.Stream, error)) (*prism.Stream, error) {
	var lastErr error
	for attempt := 0; attempt <= len(d.pool); attempt++ {
		c := d.nextSlot()
		sess, err := d.ensure(c)
		if err != nil {
			lastErr = err
			continue
		}
		st, err := open(sess)
		if err == nil {
			return st, nil
		}
		lastErr = err
		// Session died between ensure and use: drop it so the slot redials.
		c.mu.Lock()
		if c.sess == sess {
			c.sess = nil
		}
		c.mu.Unlock()
	}
	if lastErr == nil {
		lastErr = errors.New("prism: no carrier available")
	}
	return nil, lastErr
}

// Open returns a TCP stream to target "host:port", redialing dead carriers.
func (d *Dialer) Open(target string) (*prism.Stream, error) {
	return d.openWith(func(s *prism.Session) (*prism.Stream, error) { return s.OpenStream(target) })
}

// OpenUDP returns a UDP-relay stream, redialing dead carriers.
func (d *Dialer) OpenUDP() (*prism.Stream, error) {
	return d.openWith(func(s *prism.Session) (*prism.Stream, error) { return s.OpenUDP() })
}

// OpenConn adapts Open to a net.Conn for use as http.Transport.DialContext.
func (d *Dialer) OpenConn(target string) (net.Conn, error) {
	st, err := d.Open(target)
	if err != nil {
		return nil, err
	}
	return &streamConn{st}, nil
}

// Live reports how many carriers are currently up (for the control panel). It
// skips slots that are mid-dial (TryLock) so a status poll never blocks on a
// 10s dial.
func (d *Dialer) Live() int {
	n := 0
	for _, c := range d.pool {
		if c.mu.TryLock() {
			if !sessionDead(c.sess) {
				n++
			}
			c.mu.Unlock()
		}
	}
	return n
}

// Close tears every carrier down.
func (d *Dialer) Close() {
	for _, c := range d.pool {
		c.mu.Lock()
		if c.sess != nil {
			c.sess.Close()
			c.sess = nil
		}
		c.mu.Unlock()
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
