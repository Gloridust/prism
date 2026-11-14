package main

import (
	"context"
	"io"
	"net"
	"net/http"
	"time"
)

// newHTTPProxy builds a forward HTTP proxy (CONNECT for HTTPS, plain for HTTP)
// that routes everything through the Prism dialer. Desktop apps and browsers
// that speak to an HTTP proxy use this; it is also what the auto system-proxy
// points at on Windows.
func newHTTPProxy(d *Dialer) *http.Server {
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return d.OpenConn(addr)
		},
		DisableKeepAlives: true,
	}
	h := &httpProxy{d: d, transport: transport}
	return &http.Server{Handler: h, ReadHeaderTimeout: 30 * time.Second}
}

type httpProxy struct {
	d         *Dialer
	transport *http.Transport
}

func (p *httpProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		p.handleConnect(w, r)
		return
	}
	p.handlePlain(w, r)
}

func (p *httpProxy) handleConnect(w http.ResponseWriter, r *http.Request) {
	st, err := p.d.Open(r.Host)
	if err != nil {
		http.Error(w, "upstream error", http.StatusBadGateway)
		return
	}
	defer st.Close()

	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "no hijack", http.StatusInternalServerError)
		return
	}
	conn, _, err := hj.Hijack()
	if err != nil {
		return
	}
	defer conn.Close()
	conn.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n"))
	relayConn(conn, st)
}

func (p *httpProxy) handlePlain(w http.ResponseWriter, r *http.Request) {
	if r.URL.Scheme == "" {
		http.Error(w, "proxy requires absolute URI", http.StatusBadRequest)
		return
	}
	r.RequestURI = ""
	// Hop-by-hop headers must not be forwarded.
	for _, h := range []string{"Proxy-Connection", "Connection", "Keep-Alive", "Proxy-Authenticate", "Proxy-Authorization", "Te", "Trailer", "Transfer-Encoding", "Upgrade"} {
		r.Header.Del(h)
	}
	resp, err := p.transport.RoundTrip(r)
	if err != nil {
		http.Error(w, "upstream error", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	for k, vs := range resp.Header {
		for _, v := range vs {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}
