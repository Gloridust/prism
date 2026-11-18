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
	// Every pass rule is stateless and matches any TCP flags. pf's default
	// (match the SYN, pass the rest by state) breaks here: on loopback both
	// directions of a connection are "out" packets, so the returning SYN-ACK
	// matches neither the state nor a SYN-only rule; and connections that
	// were already open when the rules load have no state at all. Either
	// would fall through to the final block and be reset.
	pass := func(format string, args ...any) {
		fmt.Fprintf(&b, "pass out quick "+format+" flags any no state\n", args...)
	}
	// Loopback and tunnel traffic are matched by interface and by address, so
	// a packet pf attributes to another interface is still let through.
	pass("on lo0 all")
	pass("inet from any to 127.0.0.0/8")
	pass("inet6 from any to ::1")
	pass("on %s all", p.tunName)
	if p.tun4.IsValid() {
		pass("inet from %s to any", p.tun4)
		pass("inet from any to %s", p.tun4)
	}
	if p.tun6.IsValid() {
		pass("inet6 from %s to any", p.tun6)
		pass("inet6 from any to %s", p.tun6)
	}
	if len(p.servers) > 0 {
		pass("inet from any to { %s }", joinAddrs(p.servers, ", "))
	}
	if ksTestKeep443 {
		pass("proto tcp from any to any port 443")
	}
	b.WriteString("block return out quick proto { tcp, udp } to any port 53\n")
	pass("inet from any to { %s }", joinAddrs(ksLocal4, ", "))
	pass("inet6 from any to { %s }", joinAddrs(ksLocal6, ", "))
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
