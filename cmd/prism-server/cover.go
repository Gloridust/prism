package main

import (
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"time"

	"golang.org/x/net/http2"

	"github.com/gloridust/prism/pkg/prism"
)

// prefixConn re-attaches bytes already consumed during the failed Prism
// handshake in front of the live connection, so the cover HTTP server sees the
// visitor's request exactly as sent.
type prefixConn struct {
	net.Conn
	pre []byte
}

func (c *prefixConn) Read(p []byte) (int, error) {
	if len(c.pre) > 0 {
		n := copy(p, c.pre)
		c.pre = c.pre[n:]
		return n, nil
	}
	return c.Conn.Read(p)
}

// oneShotListener feeds a single already-accepted connection to http.Server so
// we get stdlib HTTP/1.1+keep-alive parsing and response writing for free.
type oneShotListener struct {
	conn net.Conn
	done chan struct{}
	ch   chan net.Conn
}

func newOneShotListener(c net.Conn) *oneShotListener {
	l := &oneShotListener{conn: c, done: make(chan struct{}), ch: make(chan net.Conn, 1)}
	l.ch <- c
	return l
}

func (l *oneShotListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.ch:
		return c, nil
	case <-l.done:
		return nil, net.ErrClosed
	}
}
func (l *oneShotListener) Close() error   { close(l.done); return nil }
func (l *oneShotListener) Addr() net.Addr { return l.conn.LocalAddr() }

// coverHandler builds the handler an unauthenticated visitor hits.
func coverHandler(c *Config) http.Handler {
	if c.CoverBackend != "" {
		if u, err := url.Parse(c.CoverBackend); err == nil {
			return httputil.NewSingleHostReverseProxy(u)
		}
	}
	if c.CoverStaticDir != "" {
		return http.FileServer(http.Dir(c.CoverStaticDir))
	}
	// Built-in placeholder: a plain, boring page. Replace with a real backend
	// in production — a believable site is the whole point of the fallback.
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Server", "nginx")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("<!doctype html><html><head><title>Welcome</title></head>" +
			"<body><h1>It works.</h1></body></html>"))
	})
}

// serveCover hands a fallen-back connection to a throwaway HTTP server. If the
// TLS ALPN negotiated "h2" it speaks HTTP/2 (via x/net/http2) so the cover site
// looks like a modern web server to browsers and CDN health-checks.
func serveCover(conn net.Conn, consumed []byte, h http.Handler) {
	pc := &prefixConn{Conn: conn, pre: consumed}
	if tc, ok := conn.(*tls.Conn); ok && tc.ConnectionState().NegotiatedProtocol == "h2" {
		h2s := &http2.Server{}
		h2s.ServeConn(pc, &http2.ServeConnOpts{Handler: h})
		return
	}
	srv := &http.Server{
		Handler:      h,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 60 * time.Second,
	}
	l := newOneShotListener(pc)
	srv.Serve(l)
}

// serveCoverOrWS is like serveCover but intercepts WebSocket upgrades to
// wsPath and runs a Prism session on the WebSocket stream. HTTP/2 connections
// are served via http2.Server.ServeConn (WS upgrades only come over HTTP/1.1).
func (s *server) serveCoverOrWS(conn net.Conn, consumed []byte) {
	pc := &prefixConn{Conn: conn, pre: consumed}

	// HTTP/2 connections cannot carry WebSocket upgrades (the WS handshake is
	// HTTP/1.1-only), so serve cover directly.
	if tc, ok := conn.(*tls.Conn); ok && tc.ConnectionState().NegotiatedProtocol == "h2" {
		h2s := &http2.Server{}
		h2s.ServeConn(pc, &http2.ServeConnOpts{Handler: s.cover})
		return
	}

	l := newOneShotListener(pc)
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ws := prism.WSServerUpgrade(w, r, s.wsPath)
		if ws == nil {
			s.cover.ServeHTTP(w, r)
			return
		}
		l.Close()
		defer ws.Close()
		s.handleWSSession(ws)
	})

	srv := &http.Server{
		Handler:      handler,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 60 * time.Second,
	}
	srv.Serve(l)
}

// handleWSSession runs the full Prism handshake and session on a WebSocket.
func (s *server) handleWSSession(ws *prism.WSConn) {
	_ = ws.SetReadDeadline(time.Now().Add(handshakeTimeout))
	s.credsMu.RLock()
	creds := s.creds
	s.credsMu.RUnlock()
	keys, cred, _, err := prism.ServerHandshake(ws, s.priv, creds, s.replay, s.window, s.aeads...)
	if err != nil {
		return
	}
	_ = ws.SetReadDeadline(time.Time{})

	name := "?"
	if cred != nil {
		name = fmt.Sprintf("%x", cred.ID)
	}
	sess, err := prism.NewSession(ws, keys, false, prism.WithShaping(s.shaping), prism.WithMaxStreams(s.maxStreams))
	if err != nil {
		return
	}
	defer sess.Close()
	if cred != nil {
		rec := &sessConn{sess: sess, id: cred.ID}
		s.register(rec)
		defer s.unregister(rec)
	}
	log.Printf("client %s connected via WebSocket from %s", name, ws.RemoteAddr())

	for {
		st, err := sess.Accept()
		if err != nil {
			return
		}
		go s.handleStream(st)
	}
}
