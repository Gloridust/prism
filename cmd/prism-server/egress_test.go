package main

import (
	"errors"
	"net"
	"testing"
	"time"
)

func TestIsDisallowedIP(t *testing.T) {
	blocked := []string{
		"127.0.0.1", "::1", // loopback
		"10.0.0.1", "172.16.5.4", "192.168.1.1", "fc00::1", // private / ULA
		"169.254.169.254", "fe80::1", // link-local incl. cloud metadata
		"100.64.0.1", "100.127.255.1", // CGNAT
		"0.0.0.0", "::", // unspecified
		"224.0.0.1", "ff02::1", // multicast
		"0.1.2.3", "192.0.0.8", "198.18.0.1", "240.0.0.1", "255.255.255.255", // reserved
		"64:ff9b::a00:1", "64:ff9b::7f00:1", // NAT64 → 10.0.0.1 / 127.0.0.1
		"2002:c0a8:0101::1", "2002:a9fe:a9fe::1", // 6to4 → 192.168.1.1 / metadata
		"::ffff:10.0.0.1", // v4-mapped private
	}
	for _, s := range blocked {
		if !isDisallowedIP(net.ParseIP(s)) {
			t.Errorf("%s should be blocked", s)
		}
	}
	allowed := []string{"1.1.1.1", "8.8.8.8", "203.0.113.7", "2606:4700:4700::1111",
		"64:ff9b::808:808", "2002:0808:0808::1"}
	for _, s := range allowed {
		if isDisallowedIP(net.ParseIP(s)) {
			t.Errorf("%s should be allowed", s)
		}
	}
	if !isDisallowedIP(nil) {
		t.Error("nil IP must be blocked")
	}
}

// A blocked literal target returns errBlockedTarget before any connect attempt.
func TestSafeDialBlocksPrivateLiterals(t *testing.T) {
	for _, tgt := range []string{"127.0.0.1:80", "169.254.169.254:80", "10.1.2.3:443", "[::1]:22"} {
		_, err := safeDial(tgt, false, time.Second)
		if !errors.Is(err, errBlockedTarget) {
			t.Errorf("safeDial(%q) = %v, want errBlockedTarget", tgt, err)
		}
	}
}

// allowPrivate bypasses the policy and reaches a local listener.
func TestSafeDialAllowPrivateReaches(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		if c, err := ln.Accept(); err == nil {
			c.Close()
		}
	}()
	conn, err := safeDial(ln.Addr().String(), true, 2*time.Second)
	if err != nil {
		t.Fatalf("allowPrivate dial failed: %v", err)
	}
	conn.Close()
}
