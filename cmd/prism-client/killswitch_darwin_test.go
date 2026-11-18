package main

import (
	"os/exec"
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
