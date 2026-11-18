package prism

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

// QUIC carrier: the Prism byte stream rides inside one HTTP/3 request — the
// client POSTs to a path, its request body is the client→server direction and
// the response body is server→client. The server is therefore a real HTTP/3
// server: any request that does not complete the Prism handshake, on any path,
// is answered by the cover site, so probing the UDP port finds an ordinary
// HTTP/3 website.

// DefaultH3Path is the request path used when none is configured.
const DefaultH3Path = "/_prism/h3"

func quicConfig() *quic.Config {
	return &quic.Config{MaxIdleTimeout: 60 * time.Second, KeepAlivePeriod: 15 * time.Second}
}

// --- server ---

// H3Listener is an HTTP/3 server bound to a UDP address.
type H3Listener struct {
	srv  *http3.Server
	conn net.PacketConn
}

// ListenH3 starts an HTTP/3 server on addr serving handler.
func ListenH3(addr string, tlsCfg *tls.Config, handler http.Handler) (*H3Listener, error) {
	pc, err := net.ListenPacket("udp", addr)
	if err != nil {
		return nil, err
	}
	cfg := tlsCfg.Clone()
	cfg.MinVersion = tls.VersionTLS13
	srv := &http3.Server{
		TLSConfig:   http3.ConfigureTLSConfig(cfg),
		QUICConfig:  quicConfig(),
		Handler:     handler,
		IdleTimeout: 2 * time.Minute,
	}
	go srv.Serve(pc)
	return &H3Listener{srv: srv, conn: pc}, nil
}

// Addr returns the UDP address the server listens on.
func (l *H3Listener) Addr() net.Addr { return l.conn.LocalAddr() }

// Close stops the server.
func (l *H3Listener) Close() error {
	l.srv.Close()
	return l.conn.Close()
}

// H3ServerConn adapts one HTTP/3 request to the carrier byte stream.
type H3ServerConn struct {
	w  http.ResponseWriter
	r  *http.Request
	rc *http.ResponseController

	once sync.Once
}

// NewH3ServerConn wraps a request. Nothing is written until the first Write,
// so a caller whose handshake fails can still answer the request normally.
func NewH3ServerConn(w http.ResponseWriter, r *http.Request) *H3ServerConn {
	return &H3ServerConn{w: w, r: r, rc: http.NewResponseController(w)}
}

func (c *H3ServerConn) Read(p []byte) (int, error) { return c.r.Body.Read(p) }

func (c *H3ServerConn) Write(p []byte) (int, error) {
	n, err := c.w.Write(p)
	if err != nil {
		return n, err
	}
	return n, c.rc.Flush()
}

// Close ends the request in both directions, unblocking any pending Read.
func (c *H3ServerConn) Close() error {
	c.once.Do(func() {
		_ = c.rc.SetReadDeadline(time.Unix(1, 0))
		_ = c.rc.SetWriteDeadline(time.Unix(1, 0))
		c.r.Body.Close()
	})
	return nil
}

func (c *H3ServerConn) SetReadDeadline(t time.Time) error { return c.rc.SetReadDeadline(t) }

// --- client ---

// H3ClientConn is the client side of the carrier: one streaming HTTP/3 POST.
type H3ClientConn struct {
	pw     *io.PipeWriter
	cancel func()

	respCh chan struct{} // closed when the response (or its error) is in
	resp   *http.Response
	err    error

	mu    sync.Mutex
	timer *time.Timer
	once  sync.Once
}

// H3Dial opens a QUIC connection to addr and starts a streaming POST to path.
// host is the :authority (normally the SNI).
func H3Dial(addr, host, path string, tlsCfg *tls.Config, timeout time.Duration) (*H3ClientConn, error) {
	if path == "" {
		path = DefaultH3Path
	}
	cfg := tlsCfg.Clone()
	cfg.NextProtos = []string{http3.NextProtoH3}
	cfg.MinVersion = tls.VersionTLS13

	dialCtx, dialCancel := context.WithTimeout(context.Background(), timeout)
	defer dialCancel()
	qconn, err := quic.DialAddr(dialCtx, addr, cfg, quicConfig())
	if err != nil {
		return nil, err
	}
	cc := (&http3.Transport{}).NewClientConn(qconn)

	ctx, cancel := context.WithCancel(context.Background())
	pr, pw := io.Pipe()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://"+host+path, pr)
	if err != nil {
		cancel()
		qconn.CloseWithError(0, "")
		return nil, err
	}
	req.ContentLength = -1
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36")

	c := &H3ClientConn{pw: pw, respCh: make(chan struct{}),
		cancel: func() { cancel(); qconn.CloseWithError(0, "") }}
	go func() {
		c.resp, c.err = cc.RoundTrip(req)
		if c.err == nil && c.resp.StatusCode != http.StatusOK {
			c.resp.Body.Close()
			c.err = fmt.Errorf("prism: h3 carrier refused (HTTP %d)", c.resp.StatusCode)
		}
		close(c.respCh)
	}()
	return c, nil
}

func (c *H3ClientConn) Read(p []byte) (int, error) {
	<-c.respCh
	if c.err != nil {
		return 0, c.err
	}
	return c.resp.Body.Read(p)
}

func (c *H3ClientConn) Write(p []byte) (int, error) { return c.pw.Write(p) }

// Close tears the request and its QUIC connection down.
func (c *H3ClientConn) Close() error {
	c.once.Do(func() {
		c.pw.CloseWithError(errors.New("prism: carrier closed"))
		c.cancel()
	})
	return nil
}

// SetDeadline closes the carrier at t (zero clears it). It exists to bound the
// handshake; afterwards QUIC's own idle timeout detects a dead peer.
func (c *H3ClientConn) SetDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.timer != nil {
		c.timer.Stop()
		c.timer = nil
	}
	if !t.IsZero() {
		c.timer = time.AfterFunc(time.Until(t), func() { c.Close() })
	}
	return nil
}
