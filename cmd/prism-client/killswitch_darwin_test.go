package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func ksRulesetText(p ksParams) string { return ksRuleset(p) }

func ksTestPrepare(t *testing.T) bool { return false }

func ksTestCrash(dev *tunDevice) { dev.Close() }

// ksTestDump logs pf's view of the anchor and the interfaces, for diagnosing a
// failure on a machine nobody can log in to.
func ksTestDump(t *testing.T) {
	for _, c := range [][]string{
		{"pfctl", "-a", pfAnchor, "-vsr"},
		{"pfctl", "-si"},
		{"ifconfig", "-l"},
		{"netstat", "-rn", "-f", "inet"},
	} {
		out, _ := exec.Command(c[0], c[1:]...).CombinedOutput()
		t.Logf("$ %v\n%s", c, out)
	}
}

// ksTestBoot installs boot persistence into a scratch directory, lints the
// LaunchDaemon, then runs exactly the command launchd would run at boot and
// reports whether that alone brings the ruleset back.
func ksTestBoot(t *testing.T, p ksParams) (reinstated bool) {
	dir := t.TempDir()
	oldRules, oldPlist := ksBootRules, ksBootPlist
	ksBootRules, ksBootPlist = filepath.Join(dir, "killswitch.pf.conf"), filepath.Join(dir, "com.prism.killswitch.plist")
	defer func() { ksBootRules, ksBootPlist = oldRules, oldPlist }()

	if err := persistKillSwitch(p); err != nil {
		t.Fatalf("persistKillSwitch: %v", err)
	}
	if out, err := exec.Command("plutil", "-lint", ksBootPlist).CombinedOutput(); err != nil {
		t.Fatalf("plutil rejects the LaunchDaemon: %s", out)
	}
	raw, _ := exec.Command("plutil", "-extract", "ProgramArguments.2", "raw", ksBootPlist).Output()
	bootCmd := strings.TrimSpace(string(raw))
	if bootCmd != ksBootCommand() {
		t.Fatalf("plist command = %q, want %q", bootCmd, ksBootCommand())
	}

	// "Reboot": anchor empty, then the daemon's command runs.
	exec.Command("pfctl", "-a", pfAnchor, "-F", "all").Run()
	if out, err := exec.Command("/bin/sh", "-c", bootCmd).CombinedOutput(); err != nil {
		t.Fatalf("boot command: %s: %v", out, err)
	}
	out, _ := exec.Command("pfctl", "-a", pfAnchor, "-sr").CombinedOutput()
	reinstated = strings.Contains(string(out), "block return out quick all")

	unpersistKillSwitch()
	if _, err := os.Stat(ksBootPlist); err == nil {
		t.Error("plist left behind after unpersist")
	}
	return reinstated
}
