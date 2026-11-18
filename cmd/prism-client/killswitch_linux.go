package main

import (
	"bytes"
	"fmt"
	"os/exec"
	"strings"
)

const ksTable = "prism_killswitch"

// ksRuleset renders the nftables table. The whole file is applied atomically,
// replacing any table left by a previous run.
func ksRuleset(p ksParams) string {
	var b strings.Builder
	fmt.Fprintf(&b, "table inet %s {}\ndelete table inet %s\ntable inet %s {\n\tchain out {\n", ksTable, ksTable, ksTable)
	b.WriteString("\t\ttype filter hook output priority 0; policy accept;\n")
	b.WriteString("\t\toifname \"lo\" accept\n")
	fmt.Fprintf(&b, "\t\toifname %q accept\n", p.tunName)
	if len(p.servers) > 0 {
		fmt.Fprintf(&b, "\t\tip daddr { %s } accept\n", joinAddrs(p.servers, ", "))
	}
	reject := func(match string) {
		fmt.Fprintf(&b, "\t\t%smeta l4proto tcp reject with tcp reset\n", match)
		fmt.Fprintf(&b, "\t\t%sreject with icmpx type admin-prohibited\n", match)
	}
	if ksTestScope != nil {
		v4, v6 := splitFamilies(ksTestScope)
		if len(v4) > 0 {
			reject(fmt.Sprintf("ip daddr { %s } ", joinAddrs(v4, ", ")))
		}
		if len(v6) > 0 {
			reject(fmt.Sprintf("ip6 daddr { %s } ", joinAddrs(v6, ", ")))
		}
	} else {
		reject("meta l4proto { tcp, udp } th dport 53 ")
		fmt.Fprintf(&b, "\t\tip daddr { %s } accept\n", joinAddrs(ksLocal4, ", "))
		fmt.Fprintf(&b, "\t\tip6 daddr { %s } accept\n", joinAddrs(ksLocal6, ", "))
		reject("")
	}
	b.WriteString("\t}\n}\n")
	return b.String()
}

func enableKillSwitch(p ksParams) error {
	cmd := exec.Command("nft", "-f", "-")
	cmd.Stdin = strings.NewReader(ksRuleset(p))
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("nft: %s: %w (the kill switch needs nftables)", bytes.TrimSpace(out), err)
	}
	return nil
}

func disableKillSwitch() error {
	out, err := exec.Command("nft", "delete", "table", "inet", ksTable).CombinedOutput()
	if err != nil && !bytes.Contains(out, []byte("No such file")) {
		return fmt.Errorf("nft: %s: %w", bytes.TrimSpace(out), err)
	}
	return nil
}
