package prism

import (
	"net"
	"testing"
	"time"
)

func withShortLiveness(t *testing.T) {
	t.Helper()
	ki, it := keepaliveInterval, idleTimeout
	keepaliveInterval, idleTimeout = 20*time.Millisecond, 120*time.Millisecond
	t.Cleanup(func() { keepaliveInterval, idleTimeout = ki, it })
}

// A carrier that goes silent must be torn down within idleTimeout, not block
// indefinitely — this is what detects a dead long-haul link in bounded time.
func TestSessionIdleTimeout(t *testing.T) {
	withShortLiveness(t)
	a, b := net.Pipe()
	defer b.Close()
	sess, err := NewSession(a, &Keys{Send: make([]byte, 32), Recv: make([]byte, 32)}, true)
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()
	select {
	case <-sess.Done(): // torn down by idle timeout
	case <-time.After(2 * time.Second):
		t.Fatal("session did not tear down on a silent carrier")
	}
}

// A fully connected but trafficless session must stay alive: the keepalive on
// each end keeps the other's idle timer from firing.
func TestSessionKeepaliveKeepsAlive(t *testing.T) {
	withShortLiveness(t)
	cli, srv, cliConn, srvConn, _, _ := runHandshake(t)
	defer cliConn.Close()
	defer srvConn.Close()
	cs, _ := NewSession(cliConn, cli, true)
	ss, _ := NewSession(srvConn, srv, false)
	defer cs.Close()
	defer ss.Close()
	select {
	case <-cs.Done():
		t.Fatal("live session was torn down despite keepalives")
	case <-ss.Done():
		t.Fatal("live session was torn down despite keepalives")
	case <-time.After(400 * time.Millisecond): // many keepalive intervals
	}
}
