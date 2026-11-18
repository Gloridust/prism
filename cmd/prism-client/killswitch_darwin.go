package main

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"
)

// The rules go in an anchor under com.apple/*, which the stock /etc/pf.conf
// already evaluates, so the system ruleset itself is never rewritten.
const (
	pfAnchor    = "com.apple/250.PrismKillSwitch"
	pfTokenFile = "/var/run/prism-killswitch.pftoken"
)

func ksRuleset(p ksParams) string {
	var b strings.Builder
	// Loopback and tunnel traffic are matched both by interface and by
	// address: pf does not always attribute a packet to the interface a rule
	// names (loopback delivery of local addresses, scoped routes), and a
	// packet missed here would hit the final block.
	b.WriteString("pass out quick on lo0 all\n")
	b.WriteString("pass out quick inet to 127.0.0.0/8\n")
	b.WriteString("pass out quick inet6 to ::1\n")
	fmt.Fprintf(&b, "pass out quick on %s all\n", p.tunName)
	if p.tun4.IsValid() {
		fmt.Fprintf(&b, "pass out quick inet from %s to any\n", p.tun4)
		fmt.Fprintf(&b, "pass out quick inet to %s\n", p.tun4)
	}
	if p.tun6.IsValid() {
		fmt.Fprintf(&b, "pass out quick inet6 from %s to any\n", p.tun6)
		fmt.Fprintf(&b, "pass out quick inet6 to %s\n", p.tun6)
	}
	if len(p.servers) > 0 {
		fmt.Fprintf(&b, "pass out quick inet to { %s }\n", joinAddrs(p.servers, ", "))
	}
	if ksTestKeep443 {
		b.WriteString("pass out quick proto tcp to any port 443\n")
	}
	b.WriteString("block return out quick proto { tcp, udp } to any port 53\n")
	fmt.Fprintf(&b, "pass out quick inet to { %s }\n", joinAddrs(ksLocal4, ", "))
	fmt.Fprintf(&b, "pass out quick inet6 to { %s }\n", joinAddrs(ksLocal6, ", "))
	b.WriteString("block return out quick all\n")
	return b.String()
}

var pfTokenRE = regexp.MustCompile(`Token : (\d+)`)

func enableKillSwitch(p ksParams) error {
	main, _ := exec.Command("pfctl", "-sr").CombinedOutput()
	if !bytes.Contains(main, []byte(`anchor "com.apple/*"`)) {
		return fmt.Errorf("pf's main ruleset does not evaluate the com.apple/* anchor (custom /etc/pf.conf?); cannot install the kill switch")
	}
	cmd := exec.Command("pfctl", "-a", pfAnchor, "-f", "-")
	cmd.Stdin = strings.NewReader(ksRuleset(p))
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("pfctl: %s: %w", bytes.TrimSpace(out), err)
	}
	// -E enables pf with a reference we release again on disable.
	out, err := exec.Command("pfctl", "-E").CombinedOutput()
	if err != nil {
		return fmt.Errorf("pfctl -E: %s: %w", bytes.TrimSpace(out), err)
	}
	if m := pfTokenRE.FindSubmatch(out); m != nil {
		releasePFToken()
		os.WriteFile(pfTokenFile, m[1], 0o600)
	}
	return nil
}

func releasePFToken() {
	if tok, err := os.ReadFile(pfTokenFile); err == nil {
		exec.Command("pfctl", "-X", strings.TrimSpace(string(tok))).Run()
		os.Remove(pfTokenFile)
	}
}

func disableKillSwitch() error {
	out, err := exec.Command("pfctl", "-a", pfAnchor, "-F", "all").CombinedOutput()
	releasePFToken()
	if err != nil {
		return fmt.Errorf("pfctl: %s: %w", bytes.TrimSpace(out), err)
	}
	return nil
}
