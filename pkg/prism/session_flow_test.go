package prism

import (
	"bytes"
	"crypto/rand"
	"io"
	"sync"
	"testing"
)

// echoServer accepts every stream on ss and echoes it back.
func echoServer(ss *Session) {
	for {
		st, err := ss.Accept()
		if err != nil {
			return
		}
		go func(st *Stream) {
			io.Copy(st, st)
			st.CloseWrite()
		}(st)
	}
}

// A transfer far larger than streamWindow only completes if WND credits are
// returned by the receiver as it consumes — i.e. it exercises flow control.
func TestFlowControlLargeTransfer(t *testing.T) {
	cli, srv, cliConn, srvConn, _, _ := runHandshake(t)
	defer cliConn.Close()
	defer srvConn.Close()

	cs, _ := NewSession(cliConn, cli, true)
	ss, _ := NewSession(srvConn, srv, false)
	defer cs.Close()
	defer ss.Close()
	go echoServer(ss)

	const size = 4 << 20 // 4MiB >> streamWindow (512KiB)
	payload := make([]byte, size)
	rand.Read(payload)

	st, err := cs.OpenStream("egress.internal:443")
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		st.Write(payload)
		st.CloseWrite()
	}()

	got := make([]byte, size)
	if _, err := io.ReadFull(st, got); err != nil {
		t.Fatalf("read: %v", err)
	}
	wg.Wait()
	if !bytes.Equal(got, payload) {
		t.Fatal("large flow-controlled transfer corrupted")
	}
}

// Many streams multiplexed over one carrier must all complete; with per-stream
// flow control a slow/large stream does not head-of-line block the others.
func TestConcurrentStreamsNoHOL(t *testing.T) {
	cli, srv, cliConn, srvConn, _, _ := runHandshake(t)
	defer cliConn.Close()
	defer srvConn.Close()

	cs, _ := NewSession(cliConn, cli, true)
	ss, _ := NewSession(srvConn, srv, false)
	defer cs.Close()
	defer ss.Close()
	go echoServer(ss)

	var wg sync.WaitGroup
	for i := 0; i < 24; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			st, err := cs.OpenStream("target:80")
			if err != nil {
				t.Errorf("open %d: %v", n, err)
				return
			}
			defer st.Close()
			// Mix sizes: a few large (>window), many small.
			sz := 3000
			if n%6 == 0 {
				sz = 1 << 20
			}
			msg := make([]byte, sz)
			for j := range msg {
				msg[j] = byte(n)
			}
			go func() { st.Write(msg); st.CloseWrite() }()
			got := make([]byte, sz)
			if _, err := io.ReadFull(st, got); err != nil {
				t.Errorf("stream %d read: %v", n, err)
				return
			}
			if !bytes.Equal(got, msg) {
				t.Errorf("stream %d mismatch", n)
			}
		}(i)
	}
	wg.Wait()
}
