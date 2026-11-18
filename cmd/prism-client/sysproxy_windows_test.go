//go:build windows

package main

import (
	"os"
	"os/exec"
	"strings"
	"testing"

	"golang.org/x/sys/windows/registry"
)

func inetSettings(t *testing.T) (enabled uint64, server string) {
	t.Helper()
	k, err := registry.OpenKey(registry.CURRENT_USER, `Software\Microsoft\Windows\CurrentVersion\Internet Settings`, registry.QUERY_VALUE)
	if err != nil {
		t.Fatal(err)
	}
	defer k.Close()
	enabled, _, _ = k.GetIntegerValue("ProxyEnable")
	server, _, _ = k.GetStringValue("ProxyServer")
	return
}

// TestSystemProxyAndDNSRoundTrip changes the real Windows proxy and DNS
// settings the way Connect/Disconnect do and reads them back from the system.
//
// Requires admin and PRISM_SYSCFG_TEST=1 (it briefly repoints the machine).
func TestSystemProxyAndDNSRoundTrip(t *testing.T) {
	if os.Getenv("PRISM_SYSCFG_TEST") == "" {
		t.Skip("set PRISM_SYSCFG_TEST=1 (modifies system proxy and DNS settings)")
	}
	setSystemProxy("127.0.0.1:18081", "127.0.0.1:18080")
	if on, srv := inetSettings(t); on != 1 || srv != "127.0.0.1:18081" {
		t.Errorf("after connect: ProxyEnable=%d ProxyServer=%q", on, srv)
	}
	clearSystemProxy()
	if on, _ := inetSettings(t); on != 0 {
		t.Errorf("after disconnect: ProxyEnable=%d, want 0", on)
	}

	ifaces := activeInterfaces()
	t.Logf("active interfaces: %q", ifaces)
	showDNS := func(iface string) string {
		out, _ := exec.Command("netsh", "interface", "ipv4", "show", "dnsservers", "name="+iface).CombinedOutput()
		return string(out)
	}
	setSystemDNS("127.0.0.1:53")
	applied := 0
	for _, iface := range ifaces {
		if strings.Contains(showDNS(iface), "127.0.0.1") {
			applied++
		}
	}
	clearSystemDNS()
	if applied == 0 {
		t.Errorf("system DNS was not pointed at 127.0.0.1 on any of %q", ifaces)
	}
	for _, iface := range ifaces {
		if out := showDNS(iface); strings.Contains(out, "127.0.0.1") {
			t.Errorf("%s: DNS still 127.0.0.1 after disconnect:\n%s", iface, out)
		}
	}
}
