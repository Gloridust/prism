package main

import (
	"bytes"
	"fmt"
	"net/netip"
	"os/exec"
)

const ksRuleName = "PrismKillSwitch"

// Windows Firewall block rules outrank allow rules, so "allow only X" is
// written as "block the complement of X". Each rule is limited to local
// addresses other than the tunnel's (and loopback): traffic sourced from the
// TUN address passes, everything a physical adapter would send is blocked.
// The rules are stored by the firewall service and survive a reboot.
func ksRules(p ksParams) [][]string {
	base := []string{"advfirewall", "firewall", "add", "rule", "name=" + ksRuleName, "dir=out", "action=block"}
	rule := func(extra ...string) []string { return append(append([]string{}, base...), extra...) }

	local4 := "localip=" + joinAddrs(complementRanges(false, append(hostPrefixes(p.tun4), netip.MustParsePrefix("127.0.0.0/8"))), ",")
	local6 := "localip=" + joinAddrs(complementRanges(true, hostPrefixes(p.tun6, netip.IPv6Loopback())), ",")

	allow4 := append(append([]netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}, ksLocal4...), hostPrefixes(p.servers...)...)
	allow6 := append([]netip.Prefix{netip.PrefixFrom(netip.IPv6Loopback(), 128)}, ksLocal6...)
	remote4 := "remoteip=" + joinAddrs(complementRanges(false, allow4), ",")
	remote6 := "remoteip=" + joinAddrs(complementRanges(true, allow6), ",")

	out := [][]string{
		rule(local4, "protocol=UDP", "remoteport=53"),
		rule(local4, "protocol=TCP", "remoteport=53"),
		rule(local6, "protocol=UDP", "remoteport=53"),
		rule(local6, "protocol=TCP", "remoteport=53"),
	}
	if ksTestKeep443 {
		// Same remote set, but per protocol so TCP 443 can be left out.
		for _, fam := range [][2]string{{local4, remote4}, {local6, remote6}} {
			out = append(out,
				rule(fam[0], fam[1], "protocol=TCP", "remoteport=1-442,444-65535"),
				rule(fam[0], fam[1], "protocol=UDP"))
		}
		return out
	}
	return append(out, rule(local4, remote4), rule(local6, remote6))
}

func enableKillSwitch(p ksParams) error {
	disableKillSwitch()
	for _, args := range ksRules(p) {
		if out, err := exec.Command("netsh", args...).CombinedOutput(); err != nil {
			disableKillSwitch()
			return fmt.Errorf("netsh advfirewall: %s: %w (the kill switch needs Windows Firewall enabled)", bytes.TrimSpace(out), err)
		}
	}
	return nil
}

func disableKillSwitch() error {
	// netsh exits non-zero when no rule matched, which is fine.
	exec.Command("netsh", "advfirewall", "firewall", "delete", "rule", "name="+ksRuleName).Run()
	return nil
}
