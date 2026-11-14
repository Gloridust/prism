package main

import (
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"time"
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

// serveCover hands a fallen-back connection to a throwaway HTTP server.
func serveCover(conn net.Conn, consumed []byte, h http.Handler) {
	pc := &prefixConn{Conn: conn, pre: consumed}
	srv := &http.Server{
		Handler:      h,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 60 * time.Second,
	}
	l := newOneShotListener(pc)
	// Serve returns when the connection is closed/idle; it blocks until then.
	srv.Serve(l)
}
