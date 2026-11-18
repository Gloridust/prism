//go:build !darwin && !windows

package main

import (
	"encoding/json"
	"log"
	"os"
	"path/filepath"
)

type chromiumBrowser struct {
	name, installDir, policyDir, key string
}

var chromiumBrowsers = []chromiumBrowser{
	{"Chrome", "/etc/opt/chrome", "/etc/opt/chrome/policies/managed", "WebRtcIPHandling"},
	{"Chromium", "/etc/chromium", "/etc/chromium/policies/managed", "WebRtcIPHandling"},
	{"Edge", "/etc/opt/edge", "/etc/opt/edge/policies/managed", "WebRtcLocalhostIpHandling"},
	{"Brave", "/etc/brave", "/etc/brave/policies/managed", "WebRtcIPHandling"},
}

const linuxPolicyFile = "prism-webrtc.json"

// applyChromiumWebRTC drops a managed-policy JSON next to each installed
// Chromium-family browser. Linux only reads these from /etc, so it needs root
// (which TUN mode already has); otherwise it just explains what to do.
func applyChromiumWebRTC(value string) (restore []func(), applied []string) {
	for _, b := range chromiumBrowsers {
		if _, err := os.Stat(b.installDir); err != nil {
			continue
		}
		path := filepath.Join(b.policyDir, linuxPolicyFile)
		data, _ := json.Marshal(map[string]string{b.key: value})
		err := os.MkdirAll(b.policyDir, 0o755)
		if err == nil {
			err = os.WriteFile(path, data, 0o644)
		}
		if err != nil {
			log.Printf("WebRTC guard: %s needs root to write %s (or set %s=%s in its managed policy)",
				b.name, path, b.key, value)
			continue
		}
		applied = append(applied, b.name)
		restore = append(restore, func() { os.Remove(path) })
	}
	return restore, applied
}
