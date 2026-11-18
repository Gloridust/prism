package main

import (
	"context"
	"crypto/tls"
	"io"
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

	// An authenticated client's hello carries a marker bound to the whole
	// ClientHello and to the current time; each one is accepted once.
	hello := record[5:]
	cred := prism.VerifyStealMarker(hello, s.snapshotCreds(), s.window, time.Now())
	if cred == nil || !s.stealReplay.Accept(prism.HelloSessionID(hello)) {
		s.relayToStealDest(raw, record)
		return
	}

	// Authenticated Prism client. Replay the ClientHello into our own TLS
	// server (ephemeral cert). The client skips cert verification in steal
	// mode; real authentication is the inner Prism handshake.
	pc := &prefixConn{Conn: raw, pre: record}
	tlsConn := tls.Server(pc, s.tls)
	ctx, cancel := context.WithTimeout(context.Background(), handshakeTimeout)
	err := tlsConn.HandshakeContext(ctx)
	cancel()
	if err != nil {
		return
	}

	_ = tlsConn.SetDeadline(time.Now().Add(handshakeTimeout))
	keys, cred, consumed, err := s.handshake(tlsConn)
	_ = tlsConn.SetDeadline(time.Time{})
	if err != nil {
		if s.wsPath != "" {
			s.serveCoverOrWS(tlsConn, consumed)
		} else {
			serveCover(tlsConn, consumed, s.cover)
		}
		return
	}
	s.runSession(tlsConn, keys, cred, "steal", raw.RemoteAddr())
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
