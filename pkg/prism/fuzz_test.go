package prism

import (
	"bytes"
	"net"
	"testing"
	"time"
)

func FuzzDecodeAddr(f *testing.F) {
	for _, s := range []string{"example.com:443", "1.2.3.4:53", "[2001:db8::1]:8443"} {
		b, _ := EncodeAddr(s)
		f.Add(b)
	}
	f.Add([]byte{atypDomain, 200, 'a'})
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, b []byte) {
		hp, err := DecodeAddr(b)
		if err != nil {
			return
		}
		if _, _, err := net.SplitHostPort(hp); err != nil {
			t.Fatalf("DecodeAddr produced unsplittable %q: %v", hp, err)
		}
		SplitAddr(b)
	})
}

func FuzzReadDatagram(f *testing.F) {
	var buf bytes.Buffer
	WriteDatagram(&buf, "8.8.8.8:53", []byte("query"))
	f.Add(buf.Bytes())
	f.Add([]byte{0, 1, 0})
	f.Add([]byte{0xff, 0xff})
	f.Fuzz(func(t *testing.T, b []byte) {
		r := bytes.NewReader(b)
		for {
			hp, payload, err := ReadDatagram(r)
			if err != nil {
				return
			}
			var out bytes.Buffer
			if err := WriteDatagram(&out, hp, payload); err != nil {
				t.Fatalf("re-encoding a decoded datagram failed: %v", err)
			}
		}
	})
}

func FuzzStealAndClientHello(f *testing.F) {
	psk := bytes.Repeat([]byte{7}, keySize)
	creds := []Credential{{PSK: psk}}
	// Deterministic: fuzz workers are separate processes and must agree on it.
	h := fakeHello(120)
	for i := 4; i < len(h); i++ {
		h[i] = byte(i * 7)
	}
	h[4], h[5], h[helloSIDLenOff] = 3, 3, 32
	EmbedStealMarker(h, StealKey(psk), time.Unix(1_800_000_000, 0))
	f.Add(h)
	f.Add([]byte{0x16, 3, 1, 0, 5, 1, 0, 0, 1, 0})
	f.Fuzz(func(t *testing.T, b []byte) {
		now := time.Unix(1_800_000_000, 0)
		got := VerifyStealMarker(b, creds, time.Minute, now)
		if got != nil && !bytes.Equal(b, h) {
			t.Fatalf("forged hello accepted")
		}
		ParseClientHelloSessionID(b)
		ClientHelloRecordLen(b)
		HelloSessionID(b)
	})
}

// FuzzServerHandshakes feeds arbitrary first flights to both responders: they
// must reject without panicking and without writing a single byte back.
func FuzzServerHandshakes(f *testing.F) {
	kp, _ := GenerateServerKeypair()
	psk := bytes.Repeat([]byte{3}, keySize)
	creds := []Credential{{ID: ClientID{1}, PSK: psk}}
	f.Add(bytes.Repeat([]byte{0x55}, clientInitSize))
	f.Add([]byte("GET / HTTP/1.1\r\nHost: a\r\n\r\n"))
	f.Add(append([]byte{0, noiseMsg1Size}, bytes.Repeat([]byte{9}, noiseMsg1Size)...))
	f.Fuzz(func(t *testing.T, b []byte) {
		for _, hs := range []func(rw *recordingRW) error{
			func(rw *recordingRW) error {
				_, _, _, err := ServerHandshake(rw, kp.Private, creds, nil, time.Minute)
				return err
			},
			func(rw *recordingRW) error {
				_, _, _, err := NoiseServerHandshake(rw, kp.Private, creds, nil, time.Minute)
				return err
			},
		} {
			rw := &recordingRW{r: bytes.NewReader(b)}
			if err := hs(rw); err == nil {
				t.Fatal("handshake accepted fuzz input without the PSK")
			}
			if rw.wrote > 0 {
				t.Fatalf("server wrote %d bytes to an unauthenticated peer", rw.wrote)
			}
		}
	})
}

type recordingRW struct {
	r     *bytes.Reader
	wrote int
}

func (r *recordingRW) Read(p []byte) (int, error)  { return r.r.Read(p) }
func (r *recordingRW) Write(p []byte) (int, error) { r.wrote += len(p); return len(p), nil }

// FuzzDispatch drives the frame dispatcher with arbitrary authenticated
// plaintext on both roles.
func FuzzDispatch(f *testing.F) {
	target, _ := EncodeAddr("a.example:1")
	f.Add(append([]byte{cmdSYN, 0, 0, 0, 1, 0, byte(len(target))}, target...))
	f.Add([]byte{cmdData, 0, 0, 0, 1, 0, 3, 'a', 'b', 'c'})
	f.Add([]byte{cmdWnd, 0, 0, 0, 1, 0, 4, 0xff, 0xff, 0xff, 0xff})
	f.Add([]byte{cmdRST, 0, 0, 0, 1, 0, 0})
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) < hdrSize {
			return
		}
		for _, initiator := range []bool{false, true} {
			a, peer := net.Pipe()
			go func() {
				buf := make([]byte, 4096)
				for {
					if _, err := peer.Read(buf); err != nil {
						return
					}
				}
			}()
			s, err := NewSession(a, &Keys{Send: make([]byte, keySize), Recv: make([]byte, keySize)}, initiator)
			if err != nil {
				t.Fatal(err)
			}
			if initiator {
				s.OpenStream("a.example:1")
			}
			go func() {
				for {
					if _, err := s.Accept(); err != nil {
						return
					}
				}
			}()
			for i := 0; i+hdrSize <= len(b); i += hdrSize + 3 {
				s.dispatch(b[i:])
			}
			s.Close()
			peer.Close()
		}
	})
}
