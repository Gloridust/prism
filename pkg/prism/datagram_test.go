package prism

import (
	"bytes"
	"io"
	"net"
	"testing"
)

func TestDatagramRoundTrip(t *testing.T) {
	cases := []struct {
		addr    string
		payload []byte
	}{
		{"1.2.3.4:53", []byte("dns query")},
		{"example.com:443", bytes.Repeat([]byte{0xAB}, 1200)},
		{"[2606:4700:4700::1111]:853", []byte("doq")},
		{"8.8.8.8:123", nil}, // empty payload (valid)
	}
	var buf bytes.Buffer
	for _, c := range cases {
		if err := WriteDatagram(&buf, c.addr, c.payload); err != nil {
			t.Fatalf("write %s: %v", c.addr, err)
		}
	}
	for _, c := range cases {
		host, pl, err := ReadDatagram(&buf)
		if err != nil {
			t.Fatalf("read %s: %v", c.addr, err)
		}
		// normalise the IPv6 bracket form for comparison
		wantHost, wantPort, _ := net.SplitHostPort(c.addr)
		gotHost, gotPort, _ := net.SplitHostPort(host)
		if net.ParseIP(wantHost) != nil {
			wantHost = net.ParseIP(wantHost).String()
			gotHost = net.ParseIP(gotHost).String()
		}
		if gotHost != wantHost || gotPort != wantPort {
			t.Fatalf("addr: got %s:%s want %s:%s", gotHost, gotPort, wantHost, wantPort)
		}
		if !bytes.Equal(pl, c.payload) {
			t.Fatalf("payload mismatch for %s", c.addr)
		}
	}
	if _, _, err := ReadDatagram(&buf); err != io.EOF {
		t.Fatalf("expected EOF after draining, got %v", err)
	}
}
