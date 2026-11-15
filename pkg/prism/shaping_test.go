package prism

import (
	"io"
	"net"
	"testing"
	"time"
)

// firstRecordLen returns the ciphertext length of the first on-wire record a
// shaped/unshaped session emits (the SYN from OpenStream). It fully drains that
// record so the synchronous pipe write completes, and is time-guarded so a
// regression fails fast instead of hanging.
func firstRecordLen(t *testing.T, shape string) int {
	t.Helper()
	a, b := net.Pipe()
	s, err := NewSession(a, &Keys{Send: make([]byte, 32), Recv: make([]byte, 32)}, true, WithShaping(shape))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })

	go func() {
		if st, e := s.OpenStream("1.2.3.4:80"); e == nil {
			st.Write([]byte("hi"))
		}
	}()

	type res struct {
		n   int
		err error
	}
	ch := make(chan res, 1)
	go func() {
		h := make([]byte, 2)
		if _, err := io.ReadFull(b, h); err != nil {
			ch <- res{0, err}
			return
		}
		n := int(be.Uint16(h))
		io.CopyN(io.Discard, b, int64(n)) // drain the record body so the writer completes
		ch <- res{n, nil}
	}()

	select {
	case r := <-ch:
		if r.err != nil {
			t.Fatalf("reading first record: %v", r.err)
		}
		return r.n
	case <-time.After(5 * time.Second):
		t.Fatal("timed out reading first record")
		return 0
	}
}

// The first frame is a SYN (plaintext 14 = hdr 7 + addr 7). Unshaped its record
// is 14+16(tag)=30; shaped it is padded to the 64 bucket -> 64+16=80.
func TestShapingPadsFrames(t *testing.T) {
	if n := firstRecordLen(t, "none"); n != 30 {
		t.Errorf("unshaped SYN record = %d, want 30", n)
	}
	if n := firstRecordLen(t, "pad"); n != 80 {
		t.Errorf("shaped SYN record = %d, want 80 (bucket 64 + tag)", n)
	}
}

func TestShapePadBuckets(t *testing.T) {
	s := &Session{buckets: shapeBuckets}
	cases := map[int]int{10: 64 - 10, 64: 0, 65: 256 - 65, 600: 1280 - 600, 16001: 0}
	for n, want := range cases {
		if got := s.shapePad(n); got != want {
			t.Errorf("shapePad(%d) = %d, want %d", n, got, want)
		}
	}
	if (&Session{}).shapePad(10) != 0 {
		t.Error("no-shaping pad must be 0")
	}
}
