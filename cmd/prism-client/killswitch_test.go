package main

import (
	"bytes"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestComplementRanges(t *testing.T) {
	got := joinAddrs(complementRanges(false, mustPrefixes("10.0.0.0/8", "192.168.0.0/16", "10.1.0.0/16", "255.255.255.255/32")), ",")
	want := "0.0.0.0-9.255.255.255,11.0.0.0-192.167.255.255,192.169.0.0-255.255.255.254"
	if got != want {
		t.Fatalf("v4 complement\n got %s\nwant %s", got, want)
	}
	if got := joinAddrs(complementRanges(false, mustPrefixes("0.0.0.0/0")), ","); got != "" {
		t.Fatalf("complement of everything = %q", got)
	}
	if got := joinAddrs(complementRanges(false, nil), ","); got != "0.0.0.0-255.255.255.255" {
		t.Fatalf("complement of nothing = %q", got)
	}
	if got := joinAddrs(complementRanges(false, mustPrefixes("0.0.0.0/1", "128.0.0.0/2")), ","); got != "192.0.0.0-255.255.255.255" {
		t.Fatalf("adjacent prefixes: %q", got)
	}
	got = joinAddrs(complementRanges(true, mustPrefixes("fc00::/7", "::1/128")), ",")
	want = "::,::2-fbff:ffff:ffff:ffff:ffff:ffff:ffff:ffff,fe00::-ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"
	if got != want {
		t.Fatalf("v6 complement\n got %s\nwant %s", got, want)
	}
	// Every allowed address is outside the complement, every other is inside.
	allowed := mustPrefixes("10.0.85.1/32", "127.0.0.0/8")
	rs := complementRanges(false, allowed)
	in := func(a netip.Addr) bool {
		for _, r := range rs {
			if !a.Less(r.lo) && !r.hi.Less(a) {
				return true
			}
		}
		return false
	}
	for addr, wantIn := range map[string]bool{"10.0.85.1": false, "127.9.9.9": false, "10.0.85.0": true, "10.0.85.2": true, "8.8.8.8": true, "192.168.1.5": true} {
		if in(netip.MustParseAddr(addr)) != wantIn {
			t.Errorf("%s in complement = %v, want %v", addr, !wantIn, wantIn)
		}
	}
}

func TestResolveCacheFallback(t *testing.T) {
	resolveCachePath = filepath.Join(t.TempDir(), "client.json.resolved")
	defer func() { resolveCachePath = "" }()
	if _, err := pinServerIPv4("no-such-host.invalid:443"); err == nil {
		t.Fatal("unresolvable host with an empty cache should fail")
	}
	storeResolved("no-such-host.invalid", "203.0.113.9")
	got, err := pinServerIPv4("no-such-host.invalid:443")
	if err != nil || got != "203.0.113.9:443" {
		t.Fatalf("cached fallback = %q, %v", got, err)
	}
}

// probe classifies an outbound TCP attempt: "blocked" when the firewall
// rejects it at once, "passed" when it is let out (and then times out, since
// nothing answers at these documentation addresses).
func probe(t *testing.T, addr string) string {
	t.Helper()
	start := time.Now()
	c, err := net.DialTimeout("tcp", addr, 1500*time.Millisecond)
	if err == nil {
		c.Close()
		return "connected"
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return "passed"
	}
	if time.Since(start) < time.Second {
		return "blocked"
	}
	return "passed" // slow failure (e.g. host unreachable after ARP): it left the firewall
}

func expect(t *testing.T, what, addr, want string) {
	t.Helper()
	if got := probe(t, addr); got != want {
		t.Errorf("%s: %s is %s, want %s", what, addr, got, want)
	}
}

// TestKillSwitch installs the real firewall rules around a real TUN device and
// checks what gets out. On Linux it runs in an isolated network namespace with
// the full production ruleset; on macOS and Windows, where the host must keep
// its connectivity, the final "reject everything else" is narrowed to a
// documentation prefix (ksTestScope) and everything else is identical.
//
// Requires root/admin: PRISM_ROOT_TEST=1.
func TestKillSwitch(t *testing.T) {
	if os.Getenv("PRISM_ROOT_TEST") == "" {
		t.Skip("set PRISM_ROOT_TEST=1 (requires root/admin)")
	}
	full := ksTestPrepare(t)
	if !full {
		ksTestScope = mustPrefixes("203.0.113.0/24")
		defer func() { ksTestScope = nil }()
	}

	echoAddr, stopEcho := startEchoServer(t)
	defer stopEcho()
	dev, err := openTUN("prismks0")
	if err != nil {
		t.Fatalf("openTUN: %v", err)
	}
	for i := 0; ; i++ {
		if err = configureTUN(dev, "10.0.87.1/24", "10.0.87.2"); err == nil {
			break
		}
		if i == 9 {
			t.Fatalf("configureTUN: %v", err)
		}
		time.Sleep(time.Second)
	}
	if err := addRoutes4(dev, []string{"198.51.100.0/24"}); err != nil {
		t.Fatalf("addRoutes4: %v", err)
	}
	go tunRouter(dev, &mockDialer{echoAddr: echoAddr})

	viaTunnel := func(what string) {
		t.Helper()
		var c net.Conn
		var err error
		for i := 0; i < 10; i++ {
			if c, err = net.DialTimeout("tcp", "198.51.100.7:80", 2*time.Second); err == nil {
				break
			}
			time.Sleep(300 * time.Millisecond)
		}
		if err != nil {
			t.Fatalf("%s: traffic through the tunnel failed: %v", what, err)
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(5 * time.Second))
		msg := []byte("through the tunnel")
		c.Write(msg)
		got := make([]byte, len(msg))
		if _, err := io.ReadFull(c, got); err != nil || !bytes.Equal(got, msg) {
			t.Fatalf("%s: tunnel echo: %q %v", what, got, err)
		}
	}

	const direct = "203.0.113.7:81" // not routed into the TUN: would leave directly
	viaTunnel("before")
	expect(t, "before the kill switch", direct, "passed")

	p := ksParams{tunName: dev.Name(), tun4: netip.MustParseAddr("10.0.87.1"), tun6: netip.MustParseAddr(tunAddr6),
		servers: []netip.Addr{netip.MustParseAddr("192.0.2.50")}}
	if err := enableKillSwitch(p); err != nil {
		t.Fatalf("enableKillSwitch: %v", err)
	}
	defer disableKillSwitch()
	t.Logf("kill switch installed on %s", runtime.GOOS)

	viaTunnel("with the kill switch on")
	expect(t, "kill switch on", direct, "blocked")
	if full {
		expect(t, "the Prism server stays reachable", "192.0.2.50:443", "passed")
		expect(t, "the local network stays reachable", "192.168.77.9:445", "passed")
		expect(t, "DNS to a LAN resolver", "192.168.77.1:53", "blocked")
		expect(t, "IPv6 direct", "[2001:db8::7]:81", "blocked")
	}

	// The process "crashes": the TUN goes away, the rules must not.
	ksTestCrash(dev)
	time.Sleep(300 * time.Millisecond)
	expect(t, "after the tunnel died", direct, "blocked")
	if full {
		expect(t, "after the tunnel died, formerly tunnelled traffic", "198.51.100.7:80", "blocked")
	}

	// Re-applying is idempotent, and removal restores normal connectivity.
	if err := enableKillSwitch(p); err != nil {
		t.Fatalf("re-enable: %v", err)
	}
	if err := disableKillSwitch(); err != nil {
		t.Fatalf("disableKillSwitch: %v", err)
	}
	expect(t, "after -killswitch-off", direct, "passed")
	if err := disableKillSwitch(); err != nil {
		t.Fatalf("removing an absent kill switch should not fail: %v", err)
	}
}

func TestKillSwitchRulesetShape(t *testing.T) {
	p := ksParams{tunName: "prism0", tun4: netip.MustParseAddr("10.0.85.1"), tun6: netip.MustParseAddr(tunAddr6),
		servers: []netip.Addr{netip.MustParseAddr("198.51.100.20")}}
	text := ksRulesetText(p)
	for _, want := range []string{"198.51.100.20", "53", "192.168.0.0"} {
		if !strings.Contains(text, want) {
			t.Errorf("ruleset lacks %q:\n%s", want, text)
		}
	}
}
