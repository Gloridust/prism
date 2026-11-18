package prism

import (
	"bytes"
	"errors"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

// rawPeer speaks the frame format by hand so tests can misbehave in ways a real
// Session never would.
type rawPeer struct {
	conn       net.Conn
	send, recv AEAD
	sendCtr    uint64
	got        atomic.Int64 // frames received
}

func hostilePair(t *testing.T, initiator bool) (*Session, *rawPeer) {
	t.Helper()
	a, b := net.Pipe()
	k1, k2 := bytes.Repeat([]byte{1}, keySize), bytes.Repeat([]byte{2}, keySize)
	sess, err := NewSession(a, &Keys{Send: k1, Recv: k2}, initiator)
	if err != nil {
		t.Fatal(err)
	}
	send, _ := NewAEAD(k2)
	recv, _ := NewAEAD(k1)
	p := &rawPeer{conn: b, send: send, recv: recv}
	go func() { // drain whatever the session sends so its writes never block
		hdr := make([]byte, 2)
		for {
			if _, err := io.ReadFull(b, hdr); err != nil {
				return
			}
			if _, err := io.CopyN(io.Discard, b, int64(be.Uint16(hdr))); err != nil {
				return
			}
			p.got.Add(1)
		}
	}()
	t.Cleanup(func() { sess.Close(); b.Close() })
	return sess, p
}

func (p *rawPeer) frame(cmd byte, id uint32, data []byte) error {
	plain := make([]byte, hdrSize+len(data))
	plain[0] = cmd
	be.PutUint32(plain[1:5], id)
	be.PutUint16(plain[5:7], uint16(len(data)))
	copy(plain[7:], data)
	return p.raw(p.send.Seal(p.sendCtr, plain, nil))
}

func (p *rawPeer) raw(ct []byte) error {
	p.sendCtr++
	out := make([]byte, 2+len(ct))
	be.PutUint16(out, uint16(len(ct)))
	copy(out[2:], ct)
	p.conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	_, err := p.conn.Write(out)
	return err
}

func waitDone(t *testing.T, s *Session) {
	t.Helper()
	select {
	case <-s.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("session was not torn down")
	}
}

// A peer that ignores the window must not be able to make us buffer without
// bound: the session ends once it overruns what it was granted.
func TestHostileWindowOverrunTearsDown(t *testing.T) {
	sess, p := hostilePair(t, false)
	target, _ := EncodeAddr("example.com:443")
	if err := p.frame(cmdSYN, 1, target); err != nil {
		t.Fatal(err)
	}
	st, err := sess.Accept()
	if err != nil {
		t.Fatal(err)
	}

	chunk := make([]byte, maxPayload)
	sent := 0
	for sent <= streamWindow+maxPayload {
		if err := p.frame(cmdData, 1, chunk); err != nil {
			break // session already gone
		}
		sent += len(chunk)
	}
	waitDone(t, sess)
	if !errors.Is(sess.closeErr, ErrFlowControl) {
		t.Fatalf("close error = %v, want ErrFlowControl", sess.closeErr)
	}
	st.rmu.Lock()
	queued := st.queued
	st.rmu.Unlock()
	if queued > streamWindow {
		t.Fatalf("buffered %d bytes, beyond the %d window", queued, streamWindow)
	}
}

// A well-behaved sender that fills exactly one window is fine.
func TestExactWindowIsAccepted(t *testing.T) {
	sess, p := hostilePair(t, false)
	target, _ := EncodeAddr("example.com:443")
	p.frame(cmdSYN, 1, target)
	st, err := sess.Accept()
	if err != nil {
		t.Fatal(err)
	}
	for sent := 0; sent < streamWindow; {
		n := min(maxPayload, streamWindow-sent)
		if err := p.frame(cmdData, 1, make([]byte, n)); err != nil {
			t.Fatal(err)
		}
		sent += n
	}
	got, err := io.ReadFull(st, make([]byte, streamWindow))
	if err != nil || got != streamWindow {
		t.Fatalf("read %d, %v", got, err)
	}
	select {
	case <-sess.Done():
		t.Fatal("session torn down by a conforming sender")
	default:
	}
}

// Absurd or repeated WND credits must neither panic nor inflate the window
// (the int conversion used to go negative on 32-bit routers).
func TestHostileCreditIsClamped(t *testing.T) {
	sess, p := hostilePair(t, true)
	st, err := sess.OpenStream("example.com:443")
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range []uint32{0xffffffff, 0x80000000, 0x7fffffff, 1} {
		var b [4]byte
		be.PutUint32(b[:], v)
		for i := 0; i < 4; i++ {
			if err := p.frame(cmdWnd, st.id, b[:]); err != nil {
				t.Fatal(err)
			}
		}
	}
	p.frame(cmdPad, 0, nil) // sequence point: everything above is dispatched after this
	deadline := time.Now().Add(2 * time.Second)
	for {
		st.wmu.Lock()
		win := st.sendWin
		st.wmu.Unlock()
		if win < 0 || win > streamWindow {
			t.Fatalf("send window = %d, want within [0, %d]", win, streamWindow)
		}
		if time.Now().After(deadline) {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	// The writer still stops at one window instead of running away.
	done := make(chan int, 1)
	go func() {
		n, _ := st.Write(make([]byte, 2*streamWindow))
		done <- n
	}()
	select {
	case n := <-done:
		t.Fatalf("Write returned %d without credit; window not enforced", n)
	case <-time.After(300 * time.Millisecond):
	}
}

func TestHostileFramesEndSession(t *testing.T) {
	cases := map[string]func(p *rawPeer) error{
		"forged ciphertext": func(p *rawPeer) error { return p.raw(bytes.Repeat([]byte{0xAB}, 64)) },
		"shorter than tag":  func(p *rawPeer) error { return p.raw([]byte{1, 2, 3}) },
		"replayed counter": func(p *rawPeer) error {
			ct := p.send.Seal(0, make([]byte, hdrSize), nil)
			if err := p.raw(ct); err != nil {
				return err
			}
			return p.raw(ct) // same nonce again: must fail authentication
		},
		"sub-header plaintext": func(p *rawPeer) error { return p.raw(p.send.Seal(p.sendCtr, []byte{cmdPad}, nil)) },
	}
	for name, attack := range cases {
		t.Run(name, func(t *testing.T) {
			sess, p := hostilePair(t, false)
			attack(p)
			waitDone(t, sess)
		})
	}
}

// Malformed-but-authenticated frames are ignored without killing the session.
func TestOddFramesAreIgnored(t *testing.T) {
	sess, p := hostilePair(t, false)
	p.frame(cmdData, 999, []byte("no such stream"))
	p.frame(cmdWnd, 999, []byte{1})
	p.frame(cmdFIN, 12345, nil)
	p.frame(cmdRST, 12345, nil)
	p.frame(0x7f, 1, []byte("unknown command"))
	p.frame(cmdSYN, 3, []byte{0x09, 1, 2}) // bad address type

	// Claimed length longer than the frame.
	plain := make([]byte, hdrSize+2)
	plain[0] = cmdData
	be.PutUint16(plain[5:7], 500)
	p.raw(p.send.Seal(p.sendCtr, plain, nil))

	target, _ := EncodeAddr("ok.example:1")
	p.frame(cmdSYN, 5, target)
	p.frame(cmdSYN, 5, target) // duplicate id
	st, err := sess.Accept()
	if err != nil || st.Target() != "ok.example:1" {
		t.Fatalf("session did not survive odd frames: %v", err)
	}
	if n := sess.StreamCount(); n != 1 {
		t.Fatalf("stream count = %d, want 1", n)
	}
}

func TestMaxStreamsResetsExcess(t *testing.T) {
	a, b := net.Pipe()
	k1, k2 := bytes.Repeat([]byte{1}, keySize), bytes.Repeat([]byte{2}, keySize)
	srv, _ := NewSession(a, &Keys{Send: k1, Recv: k2}, false, WithMaxStreams(4))
	cli, _ := NewSession(b, &Keys{Send: k2, Recv: k1}, true)
	defer srv.Close()
	defer cli.Close()
	go func() {
		for {
			if _, err := srv.Accept(); err != nil {
				return
			}
		}
	}()
	var streams []*Stream
	for i := 0; i < 12; i++ {
		st, err := cli.OpenStream("h.example:1")
		if err != nil {
			t.Fatal(err)
		}
		streams = append(streams, st)
	}
	time.Sleep(200 * time.Millisecond)
	if n := srv.StreamCount(); n != 4 {
		t.Fatalf("server holds %d streams, want the cap of 4", n)
	}
	// The excess streams were reset, so reads on them fail rather than hang.
	streams[11].s.transport.(net.Conn).SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := streams[11].Read(make([]byte, 1)); !errors.Is(err, ErrStreamReset) {
		t.Fatalf("excess stream read err = %v, want ErrStreamReset", err)
	}
}

// wireSizes records the length of every frame a session writes.
type wireSizes struct {
	net.Conn
	sizes chan int
}

func (w *wireSizes) Write(p []byte) (int, error) {
	select {
	case w.sizes <- len(p):
	default:
	}
	return w.Conn.Write(p)
}

// With head padding, the frames that carry a tunnelled TLS handshake no longer
// reveal its record sizes; bulk frames after the head are untouched.
func TestHeadPaddingHidesHandshakeSizes(t *testing.T) {
	a, b := net.Pipe()
	rec := &wireSizes{Conn: a, sizes: make(chan int, 256)}
	k1, k2 := bytes.Repeat([]byte{1}, keySize), bytes.Repeat([]byte{2}, keySize)
	cli, _ := NewSession(rec, &Keys{Send: k1, Recv: k2}, true, WithHeadPadding(4))
	srv, _ := NewSession(b, &Keys{Send: k2, Recv: k1}, false)
	defer cli.Close()
	defer srv.Close()

	got := make(chan []byte, 1)
	go func() {
		st, err := srv.Accept()
		if err != nil {
			return
		}
		data, _ := io.ReadAll(st)
		got <- data
	}()

	const overhead = 2 + tagSize + hdrSize
	clientHello := bytes.Repeat([]byte{0x16}, 517)
	var want []byte
	seen := map[int]bool{}
	for round := 0; round < 12; round++ {
		st, err := cli.OpenStream("tls.example.com:443")
		if err != nil {
			t.Fatal(err)
		}
		syn := <-rec.sizes
		if (syn-overhead)%64 != 0 {
			t.Fatalf("SYN frame is %d bytes on the wire; target length not hidden", syn)
		}
		st.Write(clientHello)
		sz := <-rec.sizes
		if sz-overhead < 900 || sz-overhead >= 1400 {
			t.Fatalf("517-byte hello went out as %d bytes, want padded into [900,1400)", sz-overhead)
		}
		seen[sz] = true
		if round == 0 {
			for i := 0; i < 3; i++ { // rest of the head
				st.Write([]byte("x"))
				<-rec.sizes
			}
			st.Write(clientHello) // past the head: exact size again
			if sz := <-rec.sizes; sz != overhead+517 {
				t.Fatalf("post-head frame is %d bytes, want unpadded %d", sz, overhead+517)
			}
			want = append(append(append([]byte{}, clientHello...), "xxx"...), clientHello...)
			st.CloseWrite()
			<-rec.sizes
			if data := <-got; !bytes.Equal(data, want) {
				t.Fatal("padding corrupted the stream payload")
			}
		} else {
			st.Close()
			<-rec.sizes
		}
	}
	if len(seen) < 6 {
		t.Fatalf("padded hello took only %d distinct sizes in 12 streams", len(seen))
	}
}
