package main

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
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
	if ksTestKeep443 {
		b.WriteString("\t\ttcp dport 443 accept\n")
	}
	reject("meta l4proto { tcp, udp } th dport 53 ")
	fmt.Fprintf(&b, "\t\tip daddr { %s } accept\n", joinAddrs(ksLocal4, ", "))
	fmt.Fprintf(&b, "\t\tip6 daddr { %s } accept\n", joinAddrs(ksLocal6, ", "))
	reject("")
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

// Boot persistence: a oneshot unit loads the saved ruleset before the network
// comes up, so the machine is already cut off from direct access when it boots
// and stays that way until prism-client brings the tunnel up.
var (
	ksBootRules = "/etc/prism/killswitch.nft"
	ksBootUnit  = "/etc/systemd/system/prism-killswitch.service"
	ksSystemctl = func(args ...string) error {
		out, err := exec.Command("systemctl", args...).CombinedOutput()
		if err != nil {
			return fmt.Errorf("systemctl %v: %s: %w", args, bytes.TrimSpace(out), err)
		}
		return nil
	}
)

func ksUnitText(nft string) string {
	return `[Unit]
Description=Prism kill switch (no direct traffic until the tunnel is up)
DefaultDependencies=no
# The distribution's own nftables.service starts with "flush ruleset"; load
# after it so it cannot wipe the kill switch.
After=nftables.service
Before=network-pre.target
Wants=network-pre.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=` + nft + ` -f ` + ksBootRules + `

[Install]
WantedBy=sysinit.target
`
}

// persistKillSwitch makes the kill switch come back at every boot.
func persistKillSwitch(p ksParams) error {
	nft, err := exec.LookPath("nft")
	if err != nil {
		return fmt.Errorf("nft not found: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(ksBootRules), 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(ksBootRules, []byte(ksRuleset(p)), 0o600); err != nil {
		return err
	}
	if err := os.WriteFile(ksBootUnit, []byte(ksUnitText(nft)), 0o644); err != nil {
		return err
	}
	if err := ksSystemctl("daemon-reload"); err != nil {
		return err
	}
	return ksSystemctl("enable", filepath.Base(ksBootUnit))
}

func unpersistKillSwitch() {
	if _, err := os.Stat(ksBootUnit); err == nil {
		ksSystemctl("disable", filepath.Base(ksBootUnit))
		os.Remove(ksBootUnit)
		ksSystemctl("daemon-reload")
	}
	os.Remove(ksBootRules)
}

func disableKillSwitch() error {
	unpersistKillSwitch()
	out, err := exec.Command("nft", "delete", "table", "inet", ksTable).CombinedOutput()
	if err != nil && !bytes.Contains(out, []byte("No such file")) {
		return fmt.Errorf("nft: %s: %w", bytes.TrimSpace(out), err)
	}
	return nil
}
