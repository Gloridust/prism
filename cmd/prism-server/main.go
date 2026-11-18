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
	"sync/atomic"
	"syscall"
	"time"

	"github.com/gloridust/prism/pkg/prism"
	"github.com/quic-go/quic-go"
)

const handshakeTimeout = 10 * time.Second

// version is set at build time with -ldflags "-X main.version=...".
var version = "dev"

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
	showVersion := flag.Bool("version", false, "print version and exit")
	checkOnly := flag.Bool("check", false, "validate the config and exit")
	flag.Parse()
	if *showVersion {
		fmt.Println("prism-server", version)
		return
	}

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
		// relayed to the real target site. TLS 1.3 only, so that certificate is
		// always encrypted under the client's key share.
		sni := cfg.Steal.Dest
		if len(cfg.Steal.ServerNames) > 0 {
			sni = cfg.Steal.ServerNames[0]
		}
		if h, _, err := net.SplitHostPort(sni); err == nil {
			sni = h
		}
		tlsCfg, err = stealTLSConfig(cfg.Steal.Dest, sni)
		if err != nil {
			log.Fatalf("steal tls: %v", err)
		}
	} else {
		tlsCfg, err = buildTLSConfig(cfg)
		if err != nil {
			log.Fatalf("tls: %v", err)
		}
	}

	aeads, err := prism.AEADFactoriesByName(cfg.Ciphers)
	if err != nil {
		log.Fatalf("ciphers: %v", err)
	}
	if *checkOnly {
		fmt.Printf("config OK: %d credential(s)\n", len(creds))
		return
	}

	maxStreams := cfg.MaxStreams
	if maxStreams == 0 {
		maxStreams = 1024 // default per-carrier cap; set negative in config for unlimited
	} else if maxStreams < 0 {
		maxStreams = 0 // explicit unlimited
	}
	maxConns := cfg.MaxConns
	if maxConns == 0 {
		maxConns = 4096
	}

	s := &server{
		tls:          tlsCfg,
		priv:         priv,
		creds:        creds,
		credCfgs:     cfg.creds,
		credsFile:    cfg.CredentialsFile,
		replay:       prism.NewReplayWindow(cfg.window()),
		stealReplay:  prism.NewReplayWindow(2 * cfg.window()),
		window:       cfg.window(),
		cover:        coverHandler(cfg),
		aeads:        aeads,
		allowPrivate: cfg.AllowPrivate,
		shaping:      cfg.Shaping,
		headPad:      headPadFrames(cfg.HeadPadding),
		maxStreams:   maxStreams,
		cfgPath:      *cfgPath,
		wsPath:       cfg.WSPath,
		useNoise:     cfg.Handshake == "noise",
		acct:         newAccounting(),
		active:       make(map[*sessConn]struct{}),
	}
	s.acct.syncQuotas(cfg.creds)
	if stealMode {
		s.stealDest = cfg.Steal.Dest
	}

	if cfg.Admin != nil && cfg.Admin.Listen != "" {
		admin := newAdminAPI(s, cfg.Admin.Token)
		go func() {
			if err := admin.listenAndServe(cfg.Admin.Listen); err != nil {
				log.Fatalf("admin API: %v", err)
			}
		}()
	}

	// Bind everything before serving so a bad address fails the start.
	ln, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		log.Fatalf("listen %s: %v", cfg.Listen, err)
	}
	var ql *prism.QUICListener
	if cfg.QUICListen != "" {
		if stealMode {
			log.Fatalf("quic_listen cannot be combined with steal (QUIC has no relay-to-real-site fallback)")
		}
		ql, err = prism.NewQUICListener(cfg.QUICListen, tlsCfg)
		if err != nil {
			log.Fatalf("quic listen %s: %v", cfg.QUICListen, err)
		}
		go s.serveQUIC(ql)
		log.Printf("QUIC listening on %s", cfg.QUICListen)
	}

	// SIGHUP hot-reloads credentials; SIGINT/SIGTERM shut down cleanly.
	sigc := make(chan os.Signal, 2)
	signal.Notify(sigc, syscall.SIGHUP, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		for sig := range sigc {
			if sig == syscall.SIGHUP {
				s.reload()
				continue
			}
			log.Printf("%v: shutting down", sig)
			ln.Close()
			if ql != nil {
				ql.Close()
			}
			s.closeAll()
			os.Exit(0)
		}
	}()

	ciphers := cfg.Ciphers
	if len(ciphers) == 0 {
		ciphers = []string{prism.CipherAES256GCM}
	}
	handler := s.handle
	if stealMode {
		handler = s.handleSteal
		log.Printf("STEAL mode: authenticated → Prism, others → %s", s.stealDest)
	}
	hs := "legacy"
	if s.useNoise {
		hs = "noise"
	}
	log.Printf("prism-server %s listening on %s: %d credential(s), ciphers %v, handshake %s",
		version, cfg.Listen, len(creds), ciphers, hs)
	serveTCP(ln, handler, maxConns)
}

// headPadFrames maps the head_padding switch (default on) to a frame count.
func headPadFrames(on *bool) int {
	if on != nil && !*on {
		return 0
	}
	return prism.DefaultHeadFrames
}

// serveTCP accepts connections until the listener closes, backing off on
// transient errors (e.g. EMFILE) and shedding load past maxConns.
func serveTCP(ln net.Listener, handler func(net.Conn), maxConns int) {
	var sem chan struct{}
	if maxConns > 0 {
		sem = make(chan struct{}, maxConns)
	}
	var delay time.Duration
	for {
		conn, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			if delay == 0 {
				delay = 5 * time.Millisecond
			} else if delay *= 2; delay > time.Second {
				delay = time.Second
			}
			log.Printf("accept: %v (retrying in %v)", err, delay)
			time.Sleep(delay)
			continue
		}
		delay = 0
		if sem != nil {
			select {
			case sem <- struct{}{}:
			default:
				conn.Close()
				continue
			}
		}
		go func() {
			if sem != nil {
				defer func() { <-sem }()
			}
			handler(conn)
		}()
	}
}

type server struct {
	tls          *tls.Config
	priv         *ecdh.PrivateKey
	replay       *prism.ReplayWindow
	stealReplay  *prism.ReplayWindow // single-use steal markers
	window       time.Duration
	cover        http.Handler
	aeads        []prism.AEADFactory // carrier ciphers to trial, in order
	allowPrivate bool                // permit egress to private/loopback targets
	shaping      string              // egress length-shaping profile
	headPad      int                 // per-stream head frames to length-randomise
	maxStreams   int                 // per-carrier stream cap (0 = unlimited)
	cfgPath      string              // for SIGHUP reload
	stealDest    string              // steal mode: relay destination (e.g. "www.microsoft.com:443")
	wsPath       string              // WebSocket upgrade path (e.g. "/_prism/ws"); empty = disabled
	useNoise     bool                // use the Noise handshake
	acct         *accounting         // per-credential traffic + quotas

	credsMu   sync.RWMutex // guards creds, credCfgs
	creds     []prism.Credential
	credCfgs  []CredConfig
	credsFile string // writable credential store ("" = inline config only)

	actMu  sync.Mutex // guards active
	active map[*sessConn]struct{}

	// Counters for /metrics.
	nAuthed, nCover, nStealRelay atomic.Int64
}

// sessConn tracks a live authenticated session and the credential it used, so a
// credential change can close (kick) sessions whose credential was revoked.
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

func (s *server) snapshotCreds() []prism.Credential {
	s.credsMu.RLock()
	defer s.credsMu.RUnlock()
	return s.creds
}

// kick closes live sessions whose credential matches pred and returns how many.
func (s *server) kick(pred func(prism.ClientID) bool) int {
	s.actMu.Lock()
	var kick []*sessConn
	for r := range s.active {
		if pred(r.id) {
			kick = append(kick, r)
		}
	}
	s.actMu.Unlock()
	for _, r := range kick {
		r.sess.Close()
	}
	return len(kick)
}

func (s *server) closeAll() { s.kick(func(prism.ClientID) bool { return true }) }

// setCreds swaps in a new credential list and kicks every session whose
// credential was removed or whose PSK changed.
func (s *server) setCreds(ccs []CredConfig) (kicked int, err error) {
	creds, err := parseCreds(ccs)
	if err != nil {
		return 0, err
	}
	s.credsMu.Lock()
	old := make(map[prism.ClientID][]byte, len(s.creds))
	for _, c := range s.creds {
		old[c.ID] = c.PSK
	}
	s.creds, s.credCfgs = creds, ccs
	s.credsMu.Unlock()
	if s.acct != nil {
		s.acct.syncQuotas(ccs)
	}

	valid := make(map[prism.ClientID]bool, len(creds))
	for _, c := range creds {
		if prev, ok := old[c.ID]; !ok || string(prev) == string(c.PSK) {
			valid[c.ID] = true
		}
	}
	return s.kick(func(id prism.ClientID) bool { return !valid[id] }), nil
}

// reload re-reads the config (and credentials file) and applies its
// credentials. Only credentials and quotas reload; TLS cert, listeners, ciphers
// and policy flags need a restart.
func (s *server) reload() {
	cfg, _, _, err := loadConfig(s.cfgPath)
	if err != nil {
		log.Printf("reload failed, keeping current config: %v", err)
		return
	}
	kicked, err := s.setCreds(cfg.creds)
	if err != nil {
		log.Printf("reload failed, keeping current config: %v", err)
		return
	}
	log.Printf("reloaded %d credential(s); kicked %d revoked session(s)", len(cfg.creds), kicked)
}

// handshake runs the configured inner handshake on an established carrier.
func (s *server) handshake(rw io.ReadWriter) (*prism.Keys, *prism.Credential, []byte, error) {
	creds := s.snapshotCreds()
	if s.useNoise {
		return prism.NoiseServerHandshake(rw, s.priv, creds, s.replay, s.window, s.aeads...)
	}
	return prism.ServerHandshake(rw, s.priv, creds, s.replay, s.window, s.aeads...)
}

// runSession serves one authenticated carrier until it ends.
func (s *server) runSession(tr io.ReadWriteCloser, keys *prism.Keys, cred *prism.Credential, via string, remote net.Addr) {
	sess, err := prism.NewSession(tr, keys, false, prism.WithShaping(s.shaping), prism.WithMaxStreams(s.maxStreams), prism.WithHeadPadding(s.headPad))
	if err != nil {
		tr.Close()
		return
	}
	defer sess.Close()

	rec := &sessConn{sess: sess, id: cred.ID}
	s.register(rec)
	defer s.unregister(rec)
	// The credential may have been revoked between the handshake snapshot and
	// registration, in which case no kick would ever reach this session.
	still := false
	for _, c := range s.snapshotCreds() {
		if c.ID == cred.ID && string(c.PSK) == string(cred.PSK) {
			still = true
			break
		}
	}
	if !still {
		return
	}

	s.nAuthed.Add(1)
	m := s.acct.meter(cred.ID)
	m.conns.Add(1)
	m.lastSeen.Store(time.Now().Unix())
	log.Printf("client %x (%s) connected via %s from %s", cred.ID, cred.Name, via, remote)

	for {
		st, err := sess.Accept()
		if err != nil {
			return
		}
		go s.handleStream(st, m)
	}
}

func (s *server) handle(raw net.Conn) {
	defer raw.Close()

	tlsConn := tls.Server(raw, s.tls)
	ctx, cancel := context.WithTimeout(context.Background(), handshakeTimeout)
	err := tlsConn.HandshakeContext(ctx)
	cancel()
	if err != nil {
		return
	}

	_ = tlsConn.SetDeadline(time.Now().Add(handshakeTimeout))
	keys, cred, consumed, hsErr := s.handshake(tlsConn)
	_ = tlsConn.SetDeadline(time.Time{})
	if hsErr != nil {
		s.nCover.Add(1)
		if s.wsPath != "" {
			s.serveCoverOrWS(tlsConn, consumed)
		} else {
			serveCover(tlsConn, consumed, s.cover)
		}
		return
	}
	s.runSession(tlsConn, keys, cred, "tls", raw.RemoteAddr())
}

func (s *server) serveQUIC(ql *prism.QUICListener) {
	for {
		conn, err := ql.Accept(context.Background())
		if err != nil {
			return
		}
		go s.handleQUICConn(conn)
	}
}

func (s *server) handleQUICConn(qconn *quic.Conn) {
	qc, err := prism.QUICServerAccept(qconn, handshakeTimeout)
	if err != nil {
		qconn.CloseWithError(0, "")
		return
	}
	defer qc.Close()

	qc.SetDeadline(time.Now().Add(handshakeTimeout))
	keys, cred, _, hsErr := s.handshake(qc)
	if hsErr != nil {
		return
	}
	qc.SetDeadline(time.Time{})
	s.runSession(qc, keys, cred, "quic", qconn.RemoteAddr())
}

func (s *server) handleStream(st *prism.Stream, m *meter) {
	defer st.Close()
	if !m.allowed() {
		return // daily quota exhausted
	}
	if st.IsUDP() {
		s.handleUDP(st, m)
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
	relay(st, remote, m)
}

// relay copies bidirectionally between a Prism stream and a TCP connection,
// propagating half-close in each direction and metering both.
func relay(st *prism.Stream, remote net.Conn, m *meter) {
	done := make(chan struct{}, 2)
	go func() {
		copyMetered(remote, st, func(n int64) bool { return m.add(n, 0) })
		if tc, ok := remote.(*net.TCPConn); ok {
			tc.CloseWrite()
		}
		done <- struct{}{}
	}()
	go func() {
		copyMetered(st, remote, func(n int64) bool { return m.add(0, n) })
		st.CloseWrite()
		done <- struct{}{}
	}()
	<-done
	if !m.allowed() {
		// Out of quota: don't leave the other direction parked on a read.
		st.Close()
		remote.Close()
	}
	<-done
}
