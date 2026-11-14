package mux

import (
	"bytes"
	"crypto/rand"
	"io"
	"net"
	"sync"
	"testing"
)

// 用 net.Pipe 连接 client/server 两个 Session。
func pair() (*Session, *Session) {
	a, b := net.Pipe()
	return Client(a), Server(b)
}

func TestStreamEcho(t *testing.T) {
	cs, ss := pair()
	defer cs.Close()
	defer ss.Close()

	go func() {
		st, err := ss.AcceptStream()
		if err != nil {
			return
		}
		io.Copy(st, st) // echo
		st.CloseWrite()
	}()

	st, err := cs.OpenStream()
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("hello prism mux")
	if _, err := st.Write(msg); err != nil {
		t.Fatal(err)
	}
	st.CloseWrite()

	got, err := io.ReadAll(st)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, msg) {
		t.Fatalf("echo mismatch: got %q want %q", got, msg)
	}
}

// 大数据传输，跨越初始窗口，验证流量控制（WND 信用）正确回补。
func TestFlowControlLargeTransfer(t *testing.T) {
	cs, ss := pair()
	defer cs.Close()
	defer ss.Close()

	const size = 4 << 20 // 4MiB >> InitialWindow(256KiB)
	payload := make([]byte, size)
	rand.Read(payload)

	go func() {
		st, err := ss.AcceptStream()
		if err != nil {
			return
		}
		io.Copy(st, st)
		st.CloseWrite()
	}()

	st, err := cs.OpenStream()
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
		t.Fatal("large transfer mismatch")
	}
}

// 多条并发流互不干扰。
func TestConcurrentStreams(t *testing.T) {
	cs, ss := pair()
	defer cs.Close()
	defer ss.Close()

	go func() {
		for {
			st, err := ss.AcceptStream()
			if err != nil {
				return
			}
			go func(s *Stream) {
				io.Copy(s, s)
				s.CloseWrite()
			}(st)
		}
	}()

	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			st, err := cs.OpenStream()
			if err != nil {
				t.Errorf("open: %v", err)
				return
			}
			defer st.Close()
			msg := bytes.Repeat([]byte{byte(n)}, 5000)
			st.Write(msg)
			st.CloseWrite()
			got, _ := io.ReadAll(st)
			if !bytes.Equal(got, msg) {
				t.Errorf("stream %d mismatch len=%d", n, len(got))
			}
		}(i)
	}
	wg.Wait()
}
