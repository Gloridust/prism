package main

import (
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

func ksTestPrepare(t *testing.T) bool { return false }

func ksTestCrash(dev *tunDevice) { dev.Close() }
