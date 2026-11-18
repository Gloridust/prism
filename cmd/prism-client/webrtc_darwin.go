//go:build darwin

package main

import (
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

type chromiumBrowser struct {
	name, app, domain, key string
}

var chromiumBrowsers = []chromiumBrowser{
	{"Chrome", "Google Chrome.app", "com.google.Chrome", "WebRtcIPHandling"},
	{"Edge", "Microsoft Edge.app", "com.microsoft.Edge", "WebRtcLocalhostIpHandling"},
	{"Brave", "Brave Browser.app", "com.brave.Browser", "WebRtcIPHandling"},
	{"Chromium", "Chromium.app", "org.chromium.Chromium", "WebRtcIPHandling"},
}

// defaultsCmd runs `defaults` as the desktop user so the policy lands in their
// preference domain rather than root's when prism-client runs under sudo.
func defaultsCmd(args ...string) *exec.Cmd {
	if os.Geteuid() == 0 {
		if u := os.Getenv("SUDO_USER"); u != "" {
			return exec.Command("sudo", append([]string{"-u", u, "defaults"}, args...)...)
		}
	}
	return exec.Command("defaults", args...)
}

func appInstalled(app string) bool {
	home, _, _ := targetUser()
	for _, dir := range []string{"/Applications", filepath.Join(home, "Applications")} {
		if _, err := os.Stat(filepath.Join(dir, app)); err == nil {
			return true
		}
	}
	return false
}

// applyChromiumWebRTC sets the user-level WebRTC policy. An MDM configuration
// profile (config/webrtc-policy.mobileconfig) makes it mandatory fleet-wide.
func applyChromiumWebRTC(value string) (restore []func(), applied []string) {
	for _, b := range chromiumBrowsers {
		if !appInstalled(b.app) {
			continue
		}
		out, err := defaultsCmd("read", b.domain, b.key).Output()
		prev, hadPrev := strings.TrimSpace(string(out)), err == nil
		if err := defaultsCmd("write", b.domain, b.key, "-string", value).Run(); err != nil {
			log.Printf("WebRTC guard: %s: %v", b.name, err)
			continue
		}
		applied = append(applied, b.name)
		b := b
		restore = append(restore, func() {
			if hadPrev && !isOurWebRTCValue(prev) {
				defaultsCmd("write", b.domain, b.key, "-string", prev).Run()
			} else {
				defaultsCmd("delete", b.domain, b.key).Run()
			}
		})
	}
	return restore, applied
}
