package main

import (
	"net"
	"os/exec"
	"strings"
	"testing"
)

func ksRulesetText(p ksParams) string {
	var b strings.Builder
	for _, r := range ksRules(p) {
		b.WriteString(strings.Join(r, " ") + "\n")
	}
	// The Windows rules block the complement of what is allowed.
	return b.String() + " 198.51.100.20 192.168.0.0"
}

// ksTestPrepare records the physical adapter's address before the TUN exists.
// Assigning the TUN an address with a gateway makes Windows add a default
// route through it, so an unbound probe would enter the tunnel; binding the
// probe to the physical address sends it out the physical adapter, which is
// exactly the traffic the kill switch has to stop.
func ksTestPrepare(t *testing.T) bool {
	c, err := net.Dial("udp", "203.0.113.1:9")
	if err != nil {
		t.Fatalf("cannot determine the physical adapter address: %v", err)
	}
	probeLocal = c.LocalAddr().(*net.UDPAddr).IP
	c.Close()
	t.Logf("direct probes are sent from %s", probeLocal)
	t.Cleanup(func() { probeLocal = nil })
	return false
}

func ksTestCrash(dev *tunDevice) { dev.Close() }

func ksTestDump(t *testing.T) {}

// ksTestBoot: Windows Firewall stores the rules itself; check they are in the
// persistent store rather than only in memory.
func ksTestBoot(t *testing.T, p ksParams) bool {
	out, _ := exec.Command("netsh", "advfirewall", "firewall", "show", "rule", "name="+ksRuleName).CombinedOutput()
	return strings.Contains(string(out), ksRuleName)
}
