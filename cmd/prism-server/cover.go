package main

import (
	"crypto/tls"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"sync"
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
	once sync.Once
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
func (l *oneShotListener) Close() error   { l.once.Do(func() { close(l.done) }); return nil }
func (l *oneShotListener) Addr() net.Addr { return l.conn.LocalAddr() }

// serveHTTP1 serves one connection with h and returns once that connection is
// closed or hijacked, so the caller's goroutine never outlives the visitor.
func serveHTTP1(conn net.Conn, h http.Handler) {
	l := newOneShotListener(conn)
	srv := &http.Server{
		Handler:      h,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 60 * time.Second,
		IdleTimeout:  2 * time.Minute,
		ErrorLog:     log.New(io.Discard, "", 0),
		ConnState: func(_ net.Conn, st http.ConnState) {
			if st == http.StateClosed || st == http.StateHijacked {
				l.Close()
			}
		},
	}
	srv.Serve(l)
}

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
		h2s := &http2.Server{IdleTimeout: 2 * time.Minute}
		h2s.ServeConn(pc, &http2.ServeConnOpts{Handler: h})
		return
	}
	serveHTTP1(pc, h)
}

// serveCoverOrWS is like serveCover but intercepts a WebSocket upgrade to
// wsPath and runs a Prism session on it; it returns when that session ends.
// HTTP/2 connections cannot carry the HTTP/1.1 upgrade, so they get cover.
func (s *server) serveCoverOrWS(conn net.Conn, consumed []byte) {
	if tc, ok := conn.(*tls.Conn); ok && tc.ConnectionState().NegotiatedProtocol == "h2" {
		serveCover(conn, consumed, s.cover)
		return
	}
	var wsDone chan struct{}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		done := make(chan struct{})
		wsDone = done // set before the hijack, which is what releases serveHTTP1
		ws := prism.WSServerUpgrade(w, r, s.wsPath)
		if ws == nil {
			wsDone = nil
			s.cover.ServeHTTP(w, r)
			return
		}
		defer close(done)
		defer ws.Close()
		s.handleWSSession(ws)
	})
	serveHTTP1(&prefixConn{Conn: conn, pre: consumed}, handler)
	if wsDone != nil {
		<-wsDone
	}
}

// handleWSSession runs the Prism handshake and session on a WebSocket.
func (s *server) handleWSSession(ws *prism.WSConn) {
	_ = ws.SetDeadline(time.Now().Add(handshakeTimeout))
	keys, cred, _, err := s.handshake(ws)
	if err != nil {
		return
	}
	_ = ws.SetDeadline(time.Time{})
	s.runSession(ws, keys, cred, "ws", ws.RemoteAddr())
}
