package main

import (
	"context"
	"crypto/ecdh"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log"
	mrand "math/rand"
	"net"
	"sync"
	"sync/atomic"
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
	eps      []*endpoint  // primary first, then backups
	cur      atomic.Int32 // index of the endpoint currently in use
	failback atomic.Int64 // unix nanos of the last attempt to return to the primary

	cred        prism.Credential
	aead        prism.AEADFactory
	shaping     string
	headPad     int    // per-stream head frames to length-randomise
	stealKey    []byte // non-nil in steal mode
	wsPath      string // non-empty = WebSocket transport
	maxLifetime time.Duration
	iatMaxMs    int
	useNoise    bool // use audited Noise_IKpsk2 handshake
	useQUIC     bool // use QUIC/H3 transport

	pool []*carrier

	rrMu sync.Mutex
	rr   int
}

// endpoint is one egress server the client may use.
type endpoint struct {
	server    string // "host:port"
	sni       string
	serverPub *ecdh.PublicKey
	tlsCfg    *utls.Config
	ech       []byte
}

// failbackEvery is how often a client running on a backup retries the primary.
const failbackEvery = 5 * time.Minute

// carrier is one pool slot: a (lazily dialed) session guarded by its own mutex.
type carrier struct {
	mu   sync.Mutex // serialises (re)dial of this slot
	sess *prism.Session

	// Dial backoff: after a failed dial the slot fails fast until retryAt, so
	// an unreachable server costs each new connection microseconds instead of
	// a fresh 10s timeout per slot.
	fails   int
	retryAt time.Time
	lastErr error
}

const (
	dialBackoffMin = 500 * time.Millisecond
	dialBackoffMax = 30 * time.Second
)

func dialBackoff(fails int) time.Duration {
	d := dialBackoffMin << min(fails-1, 10)
	if d > dialBackoffMax {
		d = dialBackoffMax
	}
	// Jitter so a fleet does not redial in lockstep after an outage.
	return d/2 + time.Duration(mrand.Int63n(int64(d/2)+1))
}

// NewDialer prepares the pool (connections are established lazily on first use).
func NewDialer(c *ClientConfig, cred *prism.Credential) (*Dialer, error) {
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
	headPad := prism.DefaultHeadFrames
	if c.HeadPadding != nil && !*c.HeadPadding {
		headPad = 0
	}
	var maxLife time.Duration
	if c.MaxLifetimeSec > 0 {
		maxLife = time.Duration(c.MaxLifetimeSec) * time.Second
	}
	d := &Dialer{
		cred:        *cred,
		aead:        aead,
		shaping:     c.Shaping,
		headPad:     headPad,
		stealKey:    stealKey,
		wsPath:      wsPath,
		maxLifetime: maxLife,
		iatMaxMs:    c.IATMaxMs,
		useNoise:    c.Handshake == "noise",
		useQUIC:     c.Transport == "quic",
		pool:        pool,
	}
	servers := append([]ServerEndpoint{{Server: c.Server, SNI: c.SNI, ServerPublicKey: c.ServerPublicKey}}, c.Backups...)
	for i, se := range servers {
		ep, err := newEndpoint(c, se, skipVerify)
		if err != nil {
			return nil, fmt.Errorf("server %d (%s): %w", i, se.Server, err)
		}
		d.eps = append(d.eps, ep)
	}
	return d, nil
}

// newEndpoint resolves one server's key, ECH config and TLS settings.
func newEndpoint(c *ClientConfig, se ServerEndpoint, skipVerify bool) (*endpoint, error) {
	pub, err := prism.ParseServerPublic(se.ServerPublicKey)
	if err != nil {
		return nil, fmt.Errorf("server_public_key: %w", err)
	}
	var ech []byte
	switch {
	case c.ECH == "auto":
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		var fetchErr error
		ech, fetchErr = prism.FetchECHConfigList(ctx, se.SNI, c.ECHDoH)
		cancel()
		if fetchErr != nil {
			log.Printf("ECH auto-fetch for %s failed, continuing without ECH: %v", se.SNI, fetchErr)
		} else if ech != nil {
			log.Printf("ECH config for %s fetched from DNS (%d bytes)", se.SNI, len(ech))
		}
	case c.ECH != "":
		if ech, err = base64.StdEncoding.DecodeString(c.ECH); err != nil {
			return nil, errors.New("ech: invalid base64 config list")
		}
	}
	minVersion := uint16(utls.VersionTLS12)
	if len(ech) > 0 || c.Steal {
		minVersion = utls.VersionTLS13
	}
	return &endpoint{
		server:    se.Server,
		sni:       se.SNI,
		serverPub: pub,
		ech:       ech,
		// uTLS Config carries only the fields we steer (SNI/verify); the
		// ClientHello itself is dictated by the mimicked browser profile, which
		// is the whole point — Go's native crypto/tls ClientHello is
		// fingerprintable, so we present Chrome's instead. When ECH is set,
		// ServerName is the inner (real) name; uTLS uses the ECH config's
		// public_name as the outer SNI.
		tlsCfg: &utls.Config{
			ServerName:                     se.SNI,
			InsecureSkipVerify:             skipVerify, // #nosec G402 - gated by config or steal mode
			MinVersion:                     minVersion,
			NextProtos:                     []string{"http/1.1"},
			EncryptedClientHelloConfigList: ech,
		},
	}, nil
}

// Server reports the egress currently in use.
func (d *Dialer) Server() string { return d.eps[d.cur.Load()].server }

// dialSession connects to the current egress, failing over to the next one in
// order when it is unreachable, and periodically trying to return to the
// primary once running on a backup.
func (d *Dialer) dialSession() (*prism.Session, error) {
	start := int(d.cur.Load())
	if start != 0 {
		now := time.Now().UnixNano()
		if last := d.failback.Load(); now-last > int64(failbackEvery) && d.failback.CompareAndSwap(last, now) {
			start = 0
		}
	}
	var firstErr error
	for i := range d.eps {
		idx := (start + i) % len(d.eps)
		sess, err := d.dialEndpoint(d.eps[idx])
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		if prev := int(d.cur.Swap(int32(idx))); prev != idx {
			log.Printf("egress switched: %s -> %s", d.eps[prev].server, d.eps[idx].server)
			if idx != 0 {
				d.failback.Store(time.Now().UnixNano())
			}
		}
		return sess, nil
	}
	return nil, firstErr
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

func (d *Dialer) dialEndpoint(ep *endpoint) (*prism.Session, error) {
	if d.useQUIC {
		return d.dialQUICSession(ep)
	}
	raw, err := net.DialTimeout("tcp", ep.server, 10*time.Second)
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
	tlsConn := utls.UClient(raw, ep.tlsCfg, utls.HelloChrome_Auto)
	if d.wsPath != "" {
		// A WebSocket handshake is HTTP/1.1-only, and Chrome opens wss://
		// connections offering just http/1.1 — so do we, or the server would
		// pick h2 and the upgrade could never happen.
		if err := forceHTTP1ALPN(tlsConn); err != nil {
			raw.Close()
			return nil, err
		}
	}
	if d.stealKey != nil {
		// Steal mode: embed an HMAC tag in the TLS session_id so the server
		// can distinguish us from probers before completing TLS. Build the
		// ClientHello first, inject the marker, then send it.
		if err := tlsConn.BuildHandshakeState(); err != nil {
			raw.Close()
			return nil, err
		}
		// The marker is an HMAC over the whole marshaled hello, written into
		// its session_id; mirror it into the struct field so both agree.
		hello := tlsConn.HandshakeState.Hello
		if err := prism.EmbedStealMarker(hello.Raw, d.stealKey, time.Now()); err != nil {
			raw.Close()
			return nil, err
		}
		copy(hello.SessionId, prism.HelloSessionID(hello.Raw))
	}
	tlsConn.SetDeadline(time.Now().Add(10 * time.Second))
	if err := tlsConn.Handshake(); err != nil {
		raw.Close()
		return nil, err
	}

	// Choose transport: raw TLS stream or WebSocket inside TLS.
	var transport io.ReadWriteCloser = tlsConn
	if d.wsPath != "" {
		ws, err := prism.WSClientUpgrade(tlsConn, ep.sni, d.wsPath)
		if err != nil {
			raw.Close()
			return nil, err
		}
		transport = ws
	}

	var keys *prism.Keys
	if d.useNoise {
		keys, err = prism.NoiseClientHandshake(transport, ep.serverPub, d.cred, d.aead)
	} else {
		keys, err = prism.ClientHandshake(transport, ep.serverPub, d.cred, d.aead)
	}
	if err != nil {
		raw.Close()
		return nil, err
	}
	tlsConn.SetDeadline(time.Time{})
	opts := []prism.Option{prism.WithShaping(d.shaping), prism.WithHeadPadding(d.headPad)}
	if d.maxLifetime > 0 {
		opts = append(opts, prism.WithMaxLifetime(d.maxLifetime))
	}
	if d.iatMaxMs > 0 {
		opts = append(opts, prism.WithIAT(d.iatMaxMs))
	}
	return prism.NewSession(transport, keys, true, opts...)
}

// forceHTTP1ALPN rewrites the mimicked ClientHello's ALPN list to http/1.1.
func forceHTTP1ALPN(c *utls.UConn) error {
	if err := c.BuildHandshakeState(); err != nil {
		return err
	}
	for _, ext := range c.Extensions {
		if alpn, ok := ext.(*utls.ALPNExtension); ok {
			alpn.AlpnProtocols = []string{"http/1.1"}
		}
	}
	return c.MarshalClientHello()
}

func (d *Dialer) dialQUICSession(ep *endpoint) (*prism.Session, error) {
	tlsCfg := &tls.Config{
		ServerName:                     ep.sni,
		InsecureSkipVerify:             ep.tlsCfg.InsecureSkipVerify, // #nosec G402 - gated by config
		MinVersion:                     tls.VersionTLS13,
		NextProtos:                     []string{"h3"},
		EncryptedClientHelloConfigList: ep.ech,
	}
	qc, err := prism.QUICClientDial(ep.server, tlsCfg, 10*time.Second)
	if err != nil {
		return nil, err
	}
	// Without a deadline a server that never answers the inner handshake would
	// park this dial forever while holding the carrier slot.
	qc.SetDeadline(time.Now().Add(10 * time.Second))
	var keys *prism.Keys
	if d.useNoise {
		keys, err = prism.NoiseClientHandshake(qc, ep.serverPub, d.cred, d.aead)
	} else {
		keys, err = prism.ClientHandshake(qc, ep.serverPub, d.cred, d.aead)
	}
	if err != nil {
		qc.Close()
		return nil, err
	}
	qc.SetDeadline(time.Time{})
	opts := []prism.Option{prism.WithShaping(d.shaping), prism.WithHeadPadding(d.headPad)}
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
	if c.fails > 0 && time.Now().Before(c.retryAt) {
		return nil, c.lastErr
	}
	ns, err := d.dialSession()
	if err != nil {
		c.fails++
		c.lastErr = err
		c.retryAt = time.Now().Add(dialBackoff(c.fails))
		if c.fails == 1 {
			log.Printf("carrier dial failed: %v", err)
		}
		return nil, err
	}
	if c.fails > 0 {
		log.Printf("carrier re-established after %d failed attempt(s)", c.fails)
	}
	c.fails, c.lastErr = 0, nil
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
