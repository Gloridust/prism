package main

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestWebRTCPolicyValue(t *testing.T) {
	if got := webrtcPolicyValue(false); got != "disable_non_proxied_udp" {
		t.Fatalf("proxy mode = %q", got)
	}
	if got := webrtcPolicyValue(true); got != "default_public_interface_only" {
		t.Fatalf("tun mode = %q", got)
	}
}

func TestUpsertFirefoxBlock(t *testing.T) {
	user := `user_pref("browser.startup.page", 3);` + "\n"

	once := upsertFirefoxBlock(user)
	if !strings.HasPrefix(once, user) {
		t.Fatal("existing user prefs were not preserved")
	}
	for _, want := range []string{
		`"media.peerconnection.ice.proxy_only_if_behind_proxy", true`,
		`"media.peerconnection.ice.default_address_only", true`,
	} {
		if !strings.Contains(once, want) {
			t.Fatalf("missing %s", want)
		}
	}
	if twice := upsertFirefoxBlock(once); twice != once {
		t.Fatalf("not idempotent:\n%s", twice)
	}

	stale := user + firefoxBlockStart + "\nuser_pref(\"old\", 1);\n" + firefoxBlockEnd + "\n" + `user_pref("after", 1);` + "\n"
	fixed := upsertFirefoxBlock(stale)
	if strings.Contains(fixed, `"old"`) || !strings.Contains(fixed, `user_pref("after", 1);`) {
		t.Fatalf("stale block not replaced in place:\n%s", fixed)
	}
	if strings.Count(fixed, firefoxBlockStart) != 1 {
		t.Fatal("duplicate guard block")
	}

	if got := upsertFirefoxBlock(`user_pref("x", 1);`); !strings.Contains(got, "1);\n"+firefoxBlockStart) {
		t.Fatalf("missing newline before appended block: %q", got)
	}
}

func TestEnsureFirefoxWebRTCPrefs(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("profile layout under a temp HOME is exercised on linux")
	}
	if os.Geteuid() == 0 {
		t.Setenv("SUDO_USER", "")
	}
	home := t.TempDir()
	t.Setenv("HOME", home)
	prof := filepath.Join(home, ".mozilla", "firefox", "abcd.default-release")
	os.MkdirAll(prof, 0o755)
	os.WriteFile(filepath.Join(prof, "prefs.js"), []byte("// prefs\n"), 0o644)
	os.MkdirAll(filepath.Join(home, ".mozilla", "firefox", "Crash Reports"), 0o755)

	if n := ensureFirefoxWebRTCPrefs(); n != 1 {
		t.Fatalf("configured %d profiles, want 1", n)
	}
	data, err := os.ReadFile(filepath.Join(prof, "user.js"))
	if err != nil || !strings.Contains(string(data), "proxy_only_if_behind_proxy") {
		t.Fatalf("user.js not written: %v %q", err, data)
	}
	if n := ensureFirefoxWebRTCPrefs(); n != 1 {
		t.Fatalf("second run configured %d", n)
	}
	again, _ := os.ReadFile(filepath.Join(prof, "user.js"))
	if string(again) != string(data) {
		t.Fatal("second run changed user.js")
	}
}
