//go:build darwin

package main

import (
	"strings"
	"testing"
)

func readDefault(domain, key string) (string, bool) {
	out, err := defaultsCmd("read", domain, key).Output()
	return strings.TrimSpace(string(out)), err == nil
}

// TestChromiumWebRTCDefaults sets and restores the real per-user preference
// for every installed Chromium-family browser.
func TestChromiumWebRTCDefaults(t *testing.T) {
	restore, applied := applyChromiumWebRTC(webrtcDefaultIface)
	if len(applied) == 0 {
		t.Skip("no Chromium-family browser installed")
	}
	t.Logf("applied to %v", applied)
	for _, b := range chromiumBrowsers {
		if !appInstalled(b.app) {
			continue
		}
		if v, ok := readDefault(b.domain, b.key); !ok || v != webrtcDefaultIface {
			t.Fatalf("%s %s = %q,%v", b.name, b.key, v, ok)
		}
	}
	for i := len(restore) - 1; i >= 0; i-- {
		restore[i]()
	}
	for _, b := range chromiumBrowsers {
		if _, ok := readDefault(b.domain, b.key); ok && appInstalled(b.app) {
			t.Fatalf("%s policy left behind", b.name)
		}
	}
}
