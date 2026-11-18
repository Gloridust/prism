//go:build !darwin && !windows

package main

import (
	"encoding/json"
	"log"
	"os"
	"os/exec"
	"path/filepath"
)

type chromiumBrowser struct {
	name      string
	binaries  []string // any of these on PATH means the browser is installed
	policyDir string
	key       string
}

var chromiumBrowsers = []chromiumBrowser{
	{"Chrome", []string{"google-chrome", "google-chrome-stable"}, "/etc/opt/chrome/policies/managed", "WebRtcIPHandling"},
	{"Chromium", []string{"chromium", "chromium-browser"}, "/etc/chromium/policies/managed", "WebRtcIPHandling"},
	{"Edge", []string{"microsoft-edge", "microsoft-edge-stable"}, "/etc/opt/edge/policies/managed", "WebRtcLocalhostIpHandling"},
	{"Brave", []string{"brave-browser", "brave"}, "/etc/brave/policies/managed", "WebRtcIPHandling"},
}

func (b chromiumBrowser) installed() bool {
	for _, name := range b.binaries {
		if _, err := exec.LookPath(name); err == nil {
			return true
		}
	}
	return false
}

const linuxPolicyFile = "prism-webrtc.json"

// applyChromiumWebRTC drops a managed-policy JSON next to each installed
// Chromium-family browser. Linux only reads these from /etc, so it needs root
// (which TUN mode already has); otherwise it just explains what to do.
func applyChromiumWebRTC(value string) (restore []func(), applied []string) {
	for _, b := range chromiumBrowsers {
		if !b.installed() {
			continue
		}
		path := filepath.Join(b.policyDir, linuxPolicyFile)
		// Edge documents WebRtcLocalhostIpHandling for Windows and macOS only;
		// on Linux it follows the Chromium policies instead (confirmed with a
		// real Edge). Writing all of them is harmless: a browser ignores the
		// names it does not know.
		data, _ := json.Marshal(map[string]any{
			b.key:              value,
			"WebRtcIPHandling": value,
			"WebRtcIPHandlingUrl": []map[string]string{
				{"url": "*", "handling": value},
			},
		})
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
