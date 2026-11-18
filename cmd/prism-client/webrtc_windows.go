//go:build windows

package main

import (
	"log"

	"golang.org/x/sys/windows/registry"
)

type chromiumBrowser struct {
	name, key, value string
}

var chromiumBrowsers = []chromiumBrowser{
	{"Chrome", `Software\Policies\Google\Chrome`, "WebRtcIPHandling"},
	{"Edge", `Software\Policies\Microsoft\Edge`, "WebRtcLocalhostIpHandling"},
	{"Brave", `Software\Policies\BraveSoftware\Brave`, "WebRtcIPHandling"},
}

// applyChromiumWebRTC sets the per-user (HKCU) WebRTC policy. A machine-wide
// HKLM policy (config/webrtc-policy.reg / GPO) takes precedence if present.
func applyChromiumWebRTC(value string) (restore []func(), applied []string) {
	for _, b := range chromiumBrowsers {
		k, _, err := registry.CreateKey(registry.CURRENT_USER, b.key, registry.QUERY_VALUE|registry.SET_VALUE)
		if err != nil {
			log.Printf("WebRTC guard: %s: %v", b.name, err)
			continue
		}
		prev, _, prevErr := k.GetStringValue(b.value)
		if err := k.SetStringValue(b.value, value); err != nil {
			k.Close()
			log.Printf("WebRTC guard: %s: %v", b.name, err)
			continue
		}
		k.Close()
		applied = append(applied, b.name)
		b := b
		restore = append(restore, func() {
			k, err := registry.OpenKey(registry.CURRENT_USER, b.key, registry.SET_VALUE)
			if err != nil {
				return
			}
			defer k.Close()
			if prevErr == nil && !isOurWebRTCValue(prev) {
				k.SetStringValue(b.value, prev)
			} else {
				k.DeleteValue(b.value)
			}
		})
	}
	return restore, applied
}
