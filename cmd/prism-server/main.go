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
	"os/signal"
	"sync"
	"syscall"
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

	stealMode := cfg.Steal != nil && cfg.Steal.Dest != ""
	var tlsCfg *tls.Config
	if stealMode {
		// In steal mode the server presents an ephemeral self-signed cert only
		// to authenticated clients (they skip verification; real auth is the
		// inner Prism handshake). Probers never see it — their connection is
		// relayed to the real target site.
		sni := cfg.Steal.Dest
		if len(cfg.Steal.ServerNames) > 0 {
			sni = cfg.Steal.ServerNames[0]
		}
		// Strip port from SNI if present.
		if h, _, err := net.SplitHostPort(sni); err == nil {
			sni = h
		}
		cert, err := selfSigned(sni)
		if err != nil {
			log.Fatalf("steal self-signed cert: %v", err)
		}
		tlsCfg = &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12,
			NextProtos:   []string{"h2", "http/1.1"},
		}
	} else {
		var err error
		tlsCfg, err = buildTLSConfig(cfg)
		if err != nil {
			log.Fatalf("tls: %v", err)
		}
	}

	aeads, err := prism.AEADFactoriesByName(cfg.Ciphers)
	if err != nil {
		log.Fatalf("ciphers: %v", err)
	}

	maxStreams := cfg.MaxStreams
	if maxStreams == 0 {
		maxStreams = 1024 // default per-carrier cap; set negative in config for unlimited
	} else if maxStreams < 0 {
		maxStreams = 0 // explicit unlimited
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
		shaping:      cfg.Shaping,
		maxStreams:   maxStreams,
		cfgPath:      *cfgPath,
		wsPath:       cfg.WSPath,
		active:       make(map[*sessConn]struct{}),
	}
	if stealMode {
		s.stealDest = cfg.Steal.Dest
	}

	// SIGHUP hot-reloads credentials and kicks any session whose credential was
	// removed — revoke a leaked client without dropping everyone else.
	sigc := make(chan os.Signal, 1)
	signal.Notify(sigc, syscall.SIGHUP)
	go func() {
		for range sigc {
			s.reload()
		}
	}()

	ln, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		log.Fatalf("listen %s: %v", cfg.Listen, err)
	}
	ciphers := cfg.Ciphers
	if len(ciphers) == 0 {
		ciphers = []string{prism.CipherAES256GCM}
	}
	handler := s.handle
	if stealMode {
		handler = s.handleSteal
		log.Printf("STEAL mode: authenticated → Prism, others → %s", s.stealDest)
	}
	log.Printf("listening on %s with %d credential(s), ciphers %v", cfg.Listen, len(creds), ciphers)
	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("accept: %v", err)
			continue
		}
		go handler(conn)
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
	shaping      string              // egress length-shaping profile
	maxStreams   int                 // per-carrier stream cap (0 = unlimited)
	cfgPath      string              // for SIGHUP reload
	stealDest    string              // steal mode: relay destination (e.g. "www.microsoft.com:443")
	wsPath       string              // WebSocket upgrade path (e.g. "/_prism/ws"); empty = disabled

	credsMu sync.RWMutex // guards creds (reloadable)
	actMu   sync.Mutex   // guards active
	active  map[*sessConn]struct{}
}

// sessConn tracks a live authenticated session and the credential it used, so a
// credential reload can close (kick) sessions whose credential was revoked.
type sessConn struct {
	sess *prism.Session
	id   prism.ClientID
}

func (s *server) register(r *sessConn) {
	s.actMu.Lock()
	s.active[r] = struct{}{}
	s.actMu.Unlock()
}

func (s *server) unregister(r *sessConn) {
	s.actMu.Lock()
	delete(s.active, r)
	s.actMu.Unlock()
}

// reload re-reads the config file and swaps in its credentials, then closes any
// live session whose credential is no longer present. Only credentials reload;
// TLS cert, listener, ciphers and policy flags still need a restart.
func (s *server) reload() {
	_, _, creds, err := loadConfig(s.cfgPath)
	if err != nil {
		log.Printf("reload failed, keeping current config: %v", err)
		return
	}
	s.credsMu.Lock()
	s.creds = creds
	s.credsMu.Unlock()

	valid := make(map[prism.ClientID]bool, len(creds))
	for _, c := range creds {
		valid[c.ID] = true
	}
	s.actMu.Lock()
	var kick []*sessConn
	for r := range s.active {
		if !valid[r.id] {
			kick = append(kick, r)
		}
	}
	s.actMu.Unlock()
	for _, r := range kick {
		r.sess.Close()
	}
	log.Printf("reloaded %d credential(s); kicked %d revoked session(s)", len(creds), len(kick))
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
	s.credsMu.RLock()
	creds := s.creds
	s.credsMu.RUnlock()
	keys, cred, consumed, err := prism.ServerHandshake(tlsConn, s.priv, creds, s.replay, s.window, s.aeads...)
	if err != nil {
		_ = tlsConn.SetReadDeadline(time.Time{})
		if s.wsPath != "" {
			s.serveCoverOrWS(tlsConn, consumed)
		} else {
			serveCover(tlsConn, consumed, s.cover)
		}
		return
	}
	_ = tlsConn.SetReadDeadline(time.Time{})

	name := "?"
	if cred != nil {
		name = fmt.Sprintf("%x", cred.ID)
	}
	sess, err := prism.NewSession(tlsConn, keys, false, prism.WithShaping(s.shaping), prism.WithMaxStreams(s.maxStreams))
	if err != nil {
		return
	}
	defer sess.Close()
	if cred != nil {
		rec := &sessConn{sess: sess, id: cred.ID}
		s.register(rec)
		defer s.unregister(rec)
	}
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
