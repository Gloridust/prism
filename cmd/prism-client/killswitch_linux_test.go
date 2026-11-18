package main

import (
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
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

// ksTestBoot installs boot persistence into a scratch directory, then does
// what the unit does at boot — runs its ExecStart line — and reports whether
// that alone brings the ruleset back.
func ksTestBoot(t *testing.T, p ksParams) (reinstated bool) {
	dir := t.TempDir()
	oldRules, oldUnit, oldCtl := ksBootRules, ksBootUnit, ksSystemctl
	ksBootRules, ksBootUnit = filepath.Join(dir, "killswitch.nft"), filepath.Join(dir, "prism-killswitch.service")
	var calls []string
	ksSystemctl = func(args ...string) error { calls = append(calls, strings.Join(args, " ")); return nil }
	defer func() { ksBootRules, ksBootUnit, ksSystemctl = oldRules, oldUnit, oldCtl }()

	if err := persistKillSwitch(p); err != nil {
		t.Fatalf("persistKillSwitch: %v", err)
	}
	if got := strings.Join(calls, "; "); got != "daemon-reload; enable prism-killswitch.service" {
		t.Errorf("systemctl calls = %q", got)
	}
	unit, _ := os.ReadFile(ksBootUnit)
	if out, err := exec.Command("systemd-analyze", "verify", ksBootUnit).CombinedOutput(); err != nil && strings.Contains(string(out), filepath.Base(ksBootUnit)) {
		t.Errorf("systemd rejects the unit: %s", out)
	}
	var execStart string
	for _, line := range strings.Split(string(unit), "\n") {
		if v, ok := strings.CutPrefix(line, "ExecStart="); ok {
			execStart = v
		}
	}
	if execStart == "" || !strings.Contains(string(unit), "Before=network-pre.target") {
		t.Fatalf("unit lacks ExecStart or early ordering:\n%s", unit)
	}

	// "Reboot": nothing loaded, then the unit's command runs.
	exec.Command("nft", "delete", "table", "inet", ksTable).Run()
	if out, err := exec.Command("sh", "-c", execStart).CombinedOutput(); err != nil {
		t.Fatalf("boot command %q: %s: %v", execStart, out, err)
	}
	out, _ := exec.Command("nft", "list", "table", "inet", ksTable).CombinedOutput()
	reinstated = strings.Contains(string(out), "chain out")

	unpersistKillSwitch()
	if _, err := os.Stat(ksBootUnit); err == nil {
		t.Error("unit file left behind after unpersist")
	}
	return reinstated
}

// The two tests below are the in-machine half of scripts/test-killswitch-reboot.sh,
// which runs them inside a container whose PID 1 is systemd and really
// restarts it in between. They use the production paths and the real systemctl.

func bootTestParams() ksParams {
	return ksParams{tunName: "prism0", tun4: netip.MustParseAddr("10.0.85.1"), tun6: netip.MustParseAddr(tunAddr6),
		servers: []netip.Addr{netip.MustParseAddr("192.0.2.50")}}
}

func TestKillSwitchBootInstall(t *testing.T) {
	if os.Getenv("PRISM_BOOT_TEST") == "" {
		t.Skip("run by scripts/test-killswitch-reboot.sh inside a disposable systemd machine")
	}
	if err := persistKillSwitch(bootTestParams()); err != nil {
		t.Fatalf("persistKillSwitch: %v", err)
	}
}

func TestKillSwitchBootRemove(t *testing.T) {
	if os.Getenv("PRISM_BOOT_TEST") == "" {
		t.Skip("run by scripts/test-killswitch-reboot.sh inside a disposable systemd machine")
	}
	if err := disableKillSwitch(); err != nil {
		t.Fatalf("disableKillSwitch: %v", err)
	}
}
