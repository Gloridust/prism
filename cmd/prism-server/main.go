// Command prism-server is the Singapore egress: it terminates the Prism carrier
// (TLS), authenticates clients, multiplexes their streams out to the internet,
// and serves cover traffic to everyone else so the box looks like an ordinary
// web server under active probing.
package main

import (
	"context"
	"crypto/ecdh"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/gloridust/prism/pkg/prism"
)

const handshakeTimeout = 10 * time.Second

func main() {
	log.SetFlags(log.LstdFlags | log.Lmsgprefix)
	log.SetPrefix("[prism-server] ")

	if len(os.Args) >= 2 && os.Args[1] == "keygen" {
		domain := ""
		if len(os.Args) >= 3 {
			domain = os.Args[2]
		}
		if err := runKeygen(domain); err != nil {
			log.Fatal(err)
		}
		return
	}

	cfgPath := flag.String("c", "server.json", "path to config JSON")
	flag.Parse()

	cfg, priv, creds, err := loadConfig(*cfgPath)
	if err != nil {
		log.Fatalf("config: %v", err)
	}
	tlsCfg, err := buildTLSConfig(cfg)
	if err != nil {
		log.Fatalf("tls: %v", err)
	}
	aeads, err := prism.AEADFactoriesByName(cfg.Ciphers)
	if err != nil {
		log.Fatalf("ciphers: %v", err)
	}

	s := &server{
		tls:          tlsCfg,
		priv:         priv,
		creds:        creds,
		replay:       prism.NewReplayWindow(cfg.window()),
		window:       cfg.window(),
		cover:        coverHandler(cfg),
		aeads:        aeads,
		allowPrivate: cfg.AllowPrivate,
	}

	ln, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		log.Fatalf("listen %s: %v", cfg.Listen, err)
	}
	ciphers := cfg.Ciphers
	if len(ciphers) == 0 {
		ciphers = []string{prism.CipherAES256GCM}
	}
	log.Printf("listening on %s with %d credential(s), ciphers %v", cfg.Listen, len(creds), ciphers)
	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("accept: %v", err)
			continue
		}
		go s.handle(conn)
	}
}

type server struct {
	tls          *tls.Config
	priv         *ecdh.PrivateKey
	creds        []prism.Credential
	replay       *prism.ReplayWindow
	window       time.Duration
	cover        http.Handler
	aeads        []prism.AEADFactory // carrier ciphers to trial, in order
	allowPrivate bool                // permit egress to private/loopback targets
}

func (s *server) handle(raw net.Conn) {
	defer raw.Close()

	tlsConn := tls.Server(raw, s.tls)
	ctx, cancel := context.WithTimeout(context.Background(), handshakeTimeout)
	defer cancel()
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		return
	}

	_ = tlsConn.SetReadDeadline(time.Now().Add(handshakeTimeout))
	keys, cred, consumed, err := prism.ServerHandshake(tlsConn, s.priv, s.creds, s.replay, s.window, s.aeads...)
	if err != nil {
		// Not an authenticated client -> behave exactly like a web server.
		_ = tlsConn.SetReadDeadline(time.Time{})
		serveCover(tlsConn, consumed, s.cover)
		return
	}
	_ = tlsConn.SetReadDeadline(time.Time{})

	name := "?"
	if cred != nil {
		name = fmt.Sprintf("%x", cred.ID)
	}
	sess, err := prism.NewSession(tlsConn, keys, false)
	if err != nil {
		return
	}
	defer sess.Close()
	log.Printf("client %s connected from %s", name, raw.RemoteAddr())

	for {
		st, err := sess.Accept()
		if err != nil {
			return
		}
		go s.handleStream(st)
	}
}

func (s *server) handleStream(st *prism.Stream) {
	defer st.Close()
	if st.IsUDP() {
		s.handleUDP(st)
		return
	}
	remote, err := safeDial(st.Target(), s.allowPrivate, 10*time.Second)
	if err != nil {
		if errors.Is(err, errBlockedTarget) {
			log.Printf("blocked egress to %s (private/loopback/metadata; set allow_private to permit)", st.Target())
		}
		return
	}
	defer remote.Close()
	relay(st, remote)
}

// relay copies bidirectionally between a Prism stream and a TCP connection,
// propagating half-close in each direction.
func relay(st *prism.Stream, remote net.Conn) {
	done := make(chan struct{}, 2)
	go func() {
		io.Copy(remote, st)
		if tc, ok := remote.(*net.TCPConn); ok {
			tc.CloseWrite()
		}
		done <- struct{}{}
	}()
	go func() {
		io.Copy(st, remote)
		st.CloseWrite()
		done <- struct{}{}
	}()
	<-done
	<-done
}
