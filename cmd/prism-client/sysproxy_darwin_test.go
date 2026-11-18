//go:build darwin

package main

import (
	"os"
	"os/exec"
	"reflect"
	"strings"
	"testing"
)

func networksetupGet(t *testing.T, args ...string) string {
	t.Helper()
	out, err := exec.Command("networksetup", args...).CombinedOutput()
	if err != nil {
		t.Fatalf("networksetup %v: %s: %v", args, out, err)
	}
	return string(out)
}

// TestSystemProxyAndDNSRoundTrip changes the real macOS network settings the
// way Connect/Disconnect do and reads them back from the system.
//
// Requires root and PRISM_SYSCFG_TEST=1 (it briefly repoints the machine).
func TestSystemProxyAndDNSRoundTrip(t *testing.T) {
	if os.Getenv("PRISM_SYSCFG_TEST") == "" {
		t.Skip("set PRISM_SYSCFG_TEST=1 (modifies system proxy and DNS settings)")
	}
	svcs := networkServices()
	if len(svcs) == 0 {
		t.Skip("no network services")
	}
	before := map[string][]string{}
	for _, svc := range svcs {
		before[svc] = currentDNS(svc)
	}

	setSystemProxy("127.0.0.1:18081", "127.0.0.1:18080")
	setSystemDNS("127.0.0.1:53")
	var failed bool
	for _, svc := range svcs {
		web := networksetupGet(t, "-getwebproxy", svc)
		sec := networksetupGet(t, "-getsecurewebproxy", svc)
		socks := networksetupGet(t, "-getsocksfirewallproxy", svc)
		for name, out := range map[string]string{"web": web, "secure web": sec} {
			if !strings.Contains(out, "Enabled: Yes") || !strings.Contains(out, "Port: 18081") {
				t.Errorf("%s: %s proxy not applied:\n%s", svc, name, out)
				failed = true
			}
		}
		if !strings.Contains(socks, "Enabled: Yes") || !strings.Contains(socks, "Port: 18080") {
			t.Errorf("%s: SOCKS proxy not applied:\n%s", svc, socks)
			failed = true
		}
		if got := currentDNS(svc); !reflect.DeepEqual(got, []string{"127.0.0.1"}) {
			t.Errorf("%s: DNS = %v, want [127.0.0.1]", svc, got)
			failed = true
		}
	}

	clearSystemProxy()
	clearSystemDNS()
	for _, svc := range svcs {
		for _, kind := range []string{"-getwebproxy", "-getsecurewebproxy", "-getsocksfirewallproxy"} {
			if out := networksetupGet(t, kind, svc); !strings.Contains(out, "Enabled: No") {
				t.Errorf("%s: %s still enabled after disconnect:\n%s", svc, kind, out)
			}
		}
		if got := currentDNS(svc); !reflect.DeepEqual(got, before[svc]) {
			t.Errorf("%s: DNS after disconnect = %v, want the original %v", svc, got, before[svc])
		}
	}
	if !failed {
		t.Logf("verified on %d network service(s): %v", len(svcs), svcs)
	}
}
