package main

import (
	"log"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
)

// WebRTC IP-handling values understood by Chromium-family browsers
// (Chrome/Brave policy WebRtcIPHandling, Edge policy WebRtcLocalhostIpHandling).
const (
	// System-proxy mode: no UDP that bypasses the proxy, so STUN can't reveal
	// the real public IP; WebRTC falls back to TURN-over-TCP through the proxy.
	webrtcProxyOnly = "disable_non_proxied_udp"
	// TUN mode: only the default-route interface (the TUN) is used, so neither
	// the physical LAN address nor a native IPv6 address appears in candidates.
	webrtcDefaultIface = "default_public_interface_only"
)

func webrtcPolicyValue(tun bool) string {
	if tun {
		return webrtcDefaultIface
	}
	return webrtcProxyOnly
}

func isOurWebRTCValue(v string) bool { return v == webrtcProxyOnly || v == webrtcDefaultIface }

// webrtcGuard holds the undo actions for browser policies set while connected.
type webrtcGuard struct {
	mu      sync.Mutex
	restore []func()
	applied []string
}

func applyWebRTCGuard(tun bool) *webrtcGuard {
	value := webrtcPolicyValue(tun)
	g := &webrtcGuard{}
	g.restore, g.applied = applyChromiumWebRTC(value)
	if n := ensureFirefoxWebRTCPrefs(); n > 0 {
		g.applied = append(g.applied, "Firefox("+strconv.Itoa(n)+" profiles)")
	}
	if len(g.applied) > 0 {
		log.Printf("WebRTC guard: %s on %s (restart the browser if it was already open)",
			value, strings.Join(g.applied, ", "))
	} else {
		log.Printf("WebRTC guard: no supported browser found to configure")
	}
	if !tun {
		log.Printf("WebRTC guard: system-proxy mode only covers Chrome/Edge/Brave/Firefox; " +
			"Safari and native apps (Zoom, Teams, WeChat) send UDP directly — use TUN mode for full protection")
	}
	return g
}

func (g *webrtcGuard) Remove() {
	if g == nil {
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	for i := len(g.restore) - 1; i >= 0; i-- {
		g.restore[i]()
	}
	g.restore = nil
}

func (g *webrtcGuard) Applied() []string {
	if g == nil {
		return nil
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	return append([]string(nil), g.applied...)
}

// targetUser is the desktop user whose browsers we configure: when elevated
// through sudo (needed for TUN), that is SUDO_USER, not root.
func targetUser() (home string, uid, gid int) {
	uid, gid = -1, -1
	if os.Geteuid() == 0 {
		if name := os.Getenv("SUDO_USER"); name != "" {
			if u, err := user.Lookup(name); err == nil {
				uid, _ = strconv.Atoi(u.Uid)
				gid, _ = strconv.Atoi(u.Gid)
				return u.HomeDir, uid, gid
			}
		}
	}
	home, _ = os.UserHomeDir()
	return home, uid, gid
}

const (
	firefoxBlockStart = "// >>> prism-client WebRTC guard >>>"
	firefoxBlockEnd   = "// <<< prism-client WebRTC guard <<<"
)

// These prefs are left in place on disconnect: proxy_only_if_behind_proxy is a
// no-op without a proxy and default_address_only only drops non-default
// interfaces, so neither breaks WebRTC when Prism is off.
var firefoxBlock = firefoxBlockStart + "\n" +
	`user_pref("media.peerconnection.ice.proxy_only_if_behind_proxy", true);` + "\n" +
	`user_pref("media.peerconnection.ice.default_address_only", true);` + "\n" +
	firefoxBlockEnd + "\n"

func firefoxProfileRoots(home string) []string {
	switch runtime.GOOS {
	case "darwin":
		return []string{filepath.Join(home, "Library", "Application Support", "Firefox", "Profiles")}
	case "windows":
		appData := os.Getenv("APPDATA")
		if appData == "" {
			appData = filepath.Join(home, "AppData", "Roaming")
		}
		return []string{filepath.Join(appData, "Mozilla", "Firefox", "Profiles")}
	default:
		return []string{
			filepath.Join(home, ".mozilla", "firefox"),
			filepath.Join(home, "snap", "firefox", "common", ".mozilla", "firefox"),
			filepath.Join(home, ".var", "app", "org.mozilla.firefox", ".mozilla", "firefox"),
		}
	}
}

// ensureFirefoxWebRTCPrefs writes the guard block into user.js of every
// Firefox profile (a dir holding prefs.js) and returns how many it covers.
func ensureFirefoxWebRTCPrefs() int {
	home, uid, gid := targetUser()
	if home == "" {
		return 0
	}
	n := 0
	for _, root := range firefoxProfileRoots(home) {
		prefs, _ := filepath.Glob(filepath.Join(root, "*", "prefs.js"))
		for _, p := range prefs {
			if err := writeFirefoxBlock(filepath.Join(filepath.Dir(p), "user.js"), uid, gid); err != nil {
				log.Printf("WebRTC guard: firefox %s: %v", filepath.Dir(p), err)
				continue
			}
			n++
		}
	}
	return n
}

func writeFirefoxBlock(path string, uid, gid int) error {
	old, err := os.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	updated := upsertFirefoxBlock(string(old))
	if updated == string(old) {
		return nil
	}
	if err := os.WriteFile(path, []byte(updated), 0o644); err != nil {
		return err
	}
	if uid >= 0 {
		_ = os.Lchown(path, uid, gid)
	}
	return nil
}

// upsertFirefoxBlock replaces an existing guard block or appends one, leaving
// every other line of the user's user.js untouched.
func upsertFirefoxBlock(s string) string {
	if i := strings.Index(s, firefoxBlockStart); i >= 0 {
		if j := strings.Index(s[i:], firefoxBlockEnd); j >= 0 {
			end := i + j + len(firefoxBlockEnd)
			if end < len(s) && s[end] == '\n' {
				end++
			}
			return s[:i] + firefoxBlock + s[end:]
		}
	}
	if s != "" && !strings.HasSuffix(s, "\n") {
		s += "\n"
	}
	return s + firefoxBlock
}
