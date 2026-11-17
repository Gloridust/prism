package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"time"

	"github.com/gloridust/prism/pkg/prism"
)

// StealConfig enables REALITY-style active probing resistance. When configured,
// the server inspects raw TLS ClientHellos before completing TLS: authenticated
// clients (identified by an HMAC tag in the session_id) are handled as Prism
// carriers, while everyone else has their entire TCP connection relayed to the
// real target ("dest"). An active prober that connects sees the real target's
// certificate, ALPN, and behaviour — indistinguishable from connecting directly.
type StealConfig struct {
	Dest        string   `json:"dest"`         // e.g. "www.microsoft.com:443"
	ServerNames []string `json:"server_names"` // SNI(s) for the self-signed cert shown to authenticated clients
}

// handleSteal is the connection handler in steal mode. It peeks at the raw
// ClientHello, verifies the steal marker, and routes accordingly.
func (s *server) handleSteal(raw net.Conn) {
	defer raw.Close()

	_ = raw.SetReadDeadline(time.Now().Add(handshakeTimeout))

	// Read the TLS record header (5 bytes) to learn the record length.
	hdr := make([]byte, 5)
	if _, err := io.ReadFull(raw, hdr); err != nil {
		return
	}
	recordLen := prism.ClientHelloRecordLen(hdr)
	if recordLen < 0 || recordLen > 16389 {
		// Not a TLS handshake — relay to real target with what we've read.
		s.relayToStealDest(raw, hdr)
		return
	}

	// Read the full TLS record.
	record := make([]byte, recordLen)
	copy(record, hdr)
	if _, err := io.ReadFull(raw, record[5:]); err != nil {
		return
	}
	_ = raw.SetReadDeadline(time.Time{})

	// Extract session_id and verify the steal marker.
	sid, err := prism.ParseClientHelloSessionID(record)
	if err != nil {
		s.relayToStealDest(raw, record)
		return
	}

	s.credsMu.RLock()
	creds := s.creds
	s.credsMu.RUnlock()

	if prism.VerifyStealMarker(sid, creds) == nil {
		// Not an authenticated client — relay to real target.
		s.relayToStealDest(raw, record)
		return
	}

	// Authenticated Prism client. Replay the ClientHello into our own TLS
	// server (self-signed cert for the steal SNI). The client skips cert
	// verification in steal mode; real authentication happens inside (Prism
	// handshake with PSK + X25519).
	pc := &prefixConn{Conn: raw, pre: record}
	tlsConn := tls.Server(pc, s.tls)
	ctx, cancel := context.WithTimeout(context.Background(), handshakeTimeout)
	defer cancel()
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		return
	}

	// From here, identical to the normal handle() path.
	_ = tlsConn.SetReadDeadline(time.Now().Add(handshakeTimeout))
	s.credsMu.RLock()
	creds = s.creds // re-snapshot under lock (may have changed)
	s.credsMu.RUnlock()
	keys, cred, consumed, err := prism.ServerHandshake(tlsConn, s.priv, creds, s.replay, s.window, s.aeads...)
	if err != nil {
		_ = tlsConn.SetReadDeadline(time.Time{})
		serveCover(tlsConn, consumed, s.cover)
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
	log.Printf("steal: client %s connected from %s", name, raw.RemoteAddr())

	for {
		st, err := sess.Accept()
		if err != nil {
			return
		}
		go s.handleStream(st)
	}
}

// relayToStealDest relays a connection (with already-buffered bytes) to the
// steal target. The peer completes the TLS handshake with the real target and
// sees its real certificate — indistinguishable from a direct connection.
func (s *server) relayToStealDest(clientConn net.Conn, buffered []byte) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var d net.Dialer
	dest, err := d.DialContext(ctx, "tcp", s.stealDest)
	if err != nil {
		return
	}
	defer dest.Close()

	if _, err := dest.Write(buffered); err != nil {
		return
	}

	done := make(chan struct{}, 2)
	go func() {
		io.Copy(dest, clientConn)
		if tc, ok := dest.(*net.TCPConn); ok {
			tc.CloseWrite()
		}
		done <- struct{}{}
	}()
	go func() {
		io.Copy(clientConn, dest)
		if tc, ok := clientConn.(*net.TCPConn); ok {
			tc.CloseWrite()
		}
		done <- struct{}{}
	}()
	<-done
	<-done
}
