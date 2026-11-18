//go:build windows

package main

import (
	"testing"

	"golang.org/x/sys/windows/registry"
)

func readPolicy(t *testing.T, b chromiumBrowser) (string, bool) {
	t.Helper()
	k, err := registry.OpenKey(registry.CURRENT_USER, b.key, registry.QUERY_VALUE)
	if err != nil {
		return "", false
	}
	defer k.Close()
	v, _, err := k.GetStringValue(b.value)
	return v, err == nil
}

// TestChromiumWebRTCRegistry sets and restores the real HKCU policies,
// including putting back a value that was there before.
func TestChromiumWebRTCRegistry(t *testing.T) {
	edge := chromiumBrowsers[1]
	k, _, err := registry.CreateKey(registry.CURRENT_USER, edge.key, registry.SET_VALUE)
	if err != nil {
		t.Fatal(err)
	}
	k.SetStringValue(edge.value, "default")
	k.Close()

	restore, applied := applyChromiumWebRTC(webrtcProxyOnly)
	if len(applied) != len(chromiumBrowsers) {
		t.Fatalf("applied to %v", applied)
	}
	for _, b := range chromiumBrowsers {
		if v, ok := readPolicy(t, b); !ok || v != webrtcProxyOnly {
			t.Fatalf("%s policy = %q,%v", b.name, v, ok)
		}
	}
	for i := len(restore) - 1; i >= 0; i-- {
		restore[i]()
	}
	if v, _ := readPolicy(t, edge); v != "default" {
		t.Fatalf("Edge prior value not restored: %q", v)
	}
	if _, ok := readPolicy(t, chromiumBrowsers[0]); ok {
		t.Fatal("Chrome policy left behind")
	}
	k, _ = registry.OpenKey(registry.CURRENT_USER, edge.key, registry.SET_VALUE)
	k.DeleteValue(edge.value)
	k.Close()
}
