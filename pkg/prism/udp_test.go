package prism

import (
	"bytes"
	"testing"
	"time"
)

// A UDP-relay stream must be flagged IsUDP on the accepting side and carry
// addressed datagrams intact in both directions.
func TestUDPStreamDatagrams(t *testing.T) {
	cli, srv, cliConn, srvConn, _, _ := runHandshake(t)
	defer cliConn.Close()
	defer srvConn.Close()
	cs, _ := NewSession(cliConn, cli, true)
	ss, _ := NewSession(srvConn, srv, false)
	defer cs.Close()
	defer ss.Close()

	gotUDP := make(chan bool, 1)
	go func() {
		st, err := ss.Accept()
		if err != nil {
			return
		}
		gotUDP <- st.IsUDP()
		for { // echo each datagram back to its stated target
			host, data, err := ReadDatagram(st)
			if err != nil {
				return
			}
			if err := WriteDatagram(st, host, data); err != nil {
				return
			}
		}
	}()

	st, err := cs.OpenUDP()
	if err != nil {
		t.Fatal(err)
	}
	select {
	case isUDP := <-gotUDP:
		if !isUDP {
			t.Fatal("server did not see the stream as UDP")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("server never accepted the UDP stream")
	}

	targets := []string{"1.2.3.4:53", "example.com:443", "[2001:db8::1]:853"}
	for _, tgt := range targets {
		payload := []byte("datagram-to-" + tgt)
		if err := WriteDatagram(st, tgt, payload); err != nil {
			t.Fatal(err)
		}
		host, data, err := ReadDatagram(st)
		if err != nil {
			t.Fatal(err)
		}
		if host != tgt {
			t.Errorf("echo target = %q, want %q", host, tgt)
		}
		if !bytes.Equal(data, payload) {
			t.Errorf("echo payload mismatch for %s", tgt)
		}
	}
}
