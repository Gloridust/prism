//go:build !darwin && !windows

package main

import "log"

// On Linux/OpenWrt there is no single system-proxy knob we should touch: the
// router routes traffic into the SOCKS inbound via Nikki/Mihomo, and desktop
// Linux users typically set the proxy in their DE. These are no-ops.
func setSystemProxy(httpAddr, socksAddr string) error {
	log.Printf("note: automatic system proxy not supported on this OS; "+
		"point apps at SOCKS %s or HTTP %s, or route via Nikki", socksAddr, httpAddr)
	return nil
}

func clearSystemProxy() error { return nil }

func setSystemDNS(dnsAddr string) error {
	log.Printf("note: automatic DNS config not supported on this OS; set DNS to %s manually or use TUN mode", dnsAddr)
	return nil
}

func clearSystemDNS() error { return nil }
