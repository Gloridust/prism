package prism

import (
	"testing"
	"time"
)

func TestMaxStreamsCap(t *testing.T) {
	cli, srv, cliConn, srvConn, _, _ := runHandshake(t)
	defer cliConn.Close()
	defer srvConn.Close()
	cs, _ := NewSession(cliConn, cli, true, WithMaxStreams(3))
	ss, _ := NewSession(srvConn, srv, false)
	defer cs.Close()
	defer ss.Close()
	go func() {
		for {
			if _, err := ss.Accept(); err != nil {
				return
			}
		}
	}()

	var sts []*Stream
	for i := 0; i < 3; i++ {
		st, err := cs.OpenStream("1.2.3.4:80")
		if err != nil {
			t.Fatalf("open %d: %v", i, err)
		}
		sts = append(sts, st)
	}
	if cs.StreamCount() != 3 {
		t.Fatalf("StreamCount = %d, want 3", cs.StreamCount())
	}
	if _, err := cs.OpenStream("1.2.3.4:80"); err != ErrTooManyStreams {
		t.Fatalf("over cap: got %v, want ErrTooManyStreams", err)
	}
	// Closing one frees a slot.
	sts[0].Close()
	if _, err := cs.OpenStream("1.2.3.4:80"); err != nil {
		t.Fatalf("after freeing a slot: %v", err)
	}
	_ = time.Now
}
