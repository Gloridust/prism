package prism

import (
	"bytes"
	"io"
	"net"
	"testing"
)

func TestWSFramingRoundTrip(t *testing.T) {
	c, s := net.Pipe()
	client := NewWSConn(c, nil, true)
	server := NewWSConn(s, nil, false)
	defer client.Close()
	defer server.Close()

	payloads := [][]byte{
		[]byte("hello"),
		bytes.Repeat([]byte("A"), 200),   // 2-byte length
		bytes.Repeat([]byte("B"), 70000), // 8-byte length
	}

	go func() {
		for _, p := range payloads {
			if _, err := client.Write(p); err != nil {
				t.Errorf("client write: %v", err)
				return
			}
		}
	}()

	for _, want := range payloads {
		got := make([]byte, len(want))
		if _, err := io.ReadFull(server, got); err != nil {
			t.Fatalf("server read: %v", err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("payload mismatch: len want=%d got=%d", len(want), len(got))
		}
	}
}

func TestWSFramingServerToClient(t *testing.T) {
	c, s := net.Pipe()
	client := NewWSConn(c, nil, true)
	server := NewWSConn(s, nil, false)
	defer client.Close()
	defer server.Close()

	msg := []byte("server says hi")
	go func() {
		server.Write(msg)
	}()

	got := make([]byte, len(msg))
	if _, err := io.ReadFull(client, got); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, msg) {
		t.Fatalf("got %q, want %q", got, msg)
	}
}

func TestWSAcceptKey(t *testing.T) {
	got := wsAcceptKey("dGhlIHNhbXBsZSBub25jZQ==")
	want := "Fr1fCRW3++kG4k3CGaMwLHpaYhA="
	if got != want {
		t.Fatalf("wsAcceptKey = %q, want %q", got, want)
	}
	// Verify determinism.
	if wsAcceptKey("dGhlIHNhbXBsZSBub25jZQ==") != got {
		t.Fatal("wsAcceptKey not deterministic")
	}
}
