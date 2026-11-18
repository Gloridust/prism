package main

import (
	"os/exec"
	"testing"
)

func ksRulesetText(p ksParams) string { return ksRuleset(p) }

// ksTestPrepare gives the (isolated) namespace a default route over a veth
// pair, so "direct" traffic has somewhere to go and the full ruleset can run.
func ksTestPrepare(t *testing.T) bool {
	t.Helper()
	for _, c := range [][]string{
		{"ip", "link", "set", "lo", "up"},
		{"ip", "link", "add", "ksveth0", "type", "veth", "peer", "name", "ksveth1"},
		{"ip", "addr", "add", "192.0.2.1/24", "dev", "ksveth0"},
		{"ip", "-6", "addr", "add", "2001:db8:ffff::1/64", "dev", "ksveth0", "nodad"},
		{"ip", "link", "set", "ksveth0", "up"},
		{"ip", "link", "set", "ksveth1", "up"},
		// Static neighbours: without them the unanswered ARP/ND for the fake
		// gateway turns into an instant "host unreachable", which would look
		// like a firewall rejection.
		{"ip", "neigh", "add", "192.0.2.254", "lladdr", "02:00:00:00:00:01", "dev", "ksveth0"},
		{"ip", "-6", "neigh", "add", "2001:db8:ffff::fe", "lladdr", "02:00:00:00:00:01", "dev", "ksveth0"},
		{"ip", "route", "add", "default", "via", "192.0.2.254", "dev", "ksveth0"},
		{"ip", "-6", "route", "add", "default", "via", "2001:db8:ffff::fe", "dev", "ksveth0"},
	} {
		if out, err := exec.Command(c[0], c[1:]...).CombinedOutput(); err != nil {
			t.Fatalf("%v: %s: %v (run inside `unshare --net`)", c, out, err)
		}
	}
	t.Cleanup(func() { exec.Command("ip", "link", "del", "ksveth0").Run() })
	return true
}

// ksTestCrash removes the TUN the way a dying process would. Closing the fd
// from inside the test is not enough: the reader goroutine blocked in read(2)
// keeps the device alive, which never happens when the process really exits.
func ksTestCrash(dev *tunDevice) {
	exec.Command("ip", "link", "del", dev.Name()).Run()
	dev.Close()
}

func ksTestDump(t *testing.T) {}
