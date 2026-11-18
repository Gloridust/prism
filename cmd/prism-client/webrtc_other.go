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
	{"Brave", []string{"brave-browser", "brave"}, "/etc/brave/policies/managed", "WebRtcIPHandling"},
}

// edgeBinaries: Edge has no WebRTC IP-handling policy on Linux (Microsoft
// supports WebRtcLocalhostIpHandling and WebRtcIPHandlingUrl on Windows and
// macOS only, and a real Edge on Linux ignores them and Chromium's
// WebRtcIPHandling alike), so the guard cannot cover it here.
var edgeBinaries = []string{"microsoft-edge", "microsoft-edge-stable"}

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
	if (chromiumBrowser{binaries: edgeBinaries}).installed() {
		log.Printf("WebRTC guard: Microsoft Edge on Linux offers no policy to restrict WebRTC and is NOT protected " +
			"in proxy mode — use TUN mode, or Chrome/Firefox")
	}
	for _, b := range chromiumBrowsers {
		if !b.installed() {
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
