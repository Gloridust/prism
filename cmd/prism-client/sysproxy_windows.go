//go:build windows

package main

import (
	"log"
	"net"
	"os/exec"
	"strings"
)

const regKey = `HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings`

// WinINET is HTTP-proxy oriented, so Windows routes the system proxy at the
// HTTP proxy port. Apps that read WinINET settings (Edge, Chrome, most) pick
// this up after the refresh call below.
func setSystemProxy(httpAddr, socksAddr string) error {
	run("reg", "add", regKey, "/v", "ProxyEnable", "/t", "REG_DWORD", "/d", "1", "/f")
	run("reg", "add", regKey, "/v", "ProxyServer", "/t", "REG_SZ", "/d", httpAddr, "/f")
	refreshWinINet()
	log.Printf("system proxy set (HTTP %s)", httpAddr)
	return nil
}

func clearSystemProxy() error {
	run("reg", "add", regKey, "/v", "ProxyEnable", "/t", "REG_DWORD", "/d", "0", "/f")
	refreshWinINet()
	log.Printf("system proxy cleared")
	return nil
}

// refreshWinINet notifies running apps that proxy settings changed, so they
// take effect without a reboot (INTERNET_OPTION_SETTINGS_CHANGED=39, REFRESH=37).
func refreshWinINet() {
	script := `$sig='[DllImport("wininet.dll",SetLastError=true)] public static extern bool InternetSetOption(IntPtr h,int o,IntPtr b,int l);';` +
		`$t=Add-Type -MemberDefinition $sig -Name W -Namespace N -PassThru;` +
		`[void]$t::InternetSetOption([IntPtr]::Zero,39,[IntPtr]::Zero,0);` +
		`[void]$t::InternetSetOption([IntPtr]::Zero,37,[IntPtr]::Zero,0)`
	run("powershell", "-NoProfile", "-NonInteractive", "-Command", script)
}

func setSystemDNS(dnsAddr string) error {
	host, _, _ := net.SplitHostPort(dnsAddr)
	for _, iface := range activeInterfaces() {
		// validate=no: netsh would otherwise probe the resolver and fail while
		// our DNS proxy is still starting.
		run("netsh", "interface", "ipv4", "set", "dnsservers", "name="+iface, "source=static", "address="+host, "validate=no")
	}
	log.Printf("system DNS set to %s", host)
	return nil
}

func clearSystemDNS() error {
	for _, iface := range activeInterfaces() {
		run("netsh", "interface", "ipv4", "set", "dnsservers", "name="+iface, "source=dhcp")
	}
	log.Printf("system DNS restored to DHCP defaults")
	return nil
}

// activeInterfaces lists the adapters whose DNS must point at the local proxy:
// every one that is up and has an IPv4 address, except loopback and the Prism
// TUN. It uses the OS interface table rather than parsing netsh's localized,
// column-formatted output.
func activeInterfaces() []string {
	ifs, err := net.Interfaces()
	if err != nil {
		return nil
	}
	var names []string
	for _, ifc := range ifs {
		if ifc.Flags&net.FlagUp == 0 || ifc.Flags&net.FlagLoopback != 0 || strings.HasPrefix(strings.ToLower(ifc.Name), "prism") {
			continue
		}
		addrs, _ := ifc.Addrs()
		for _, a := range addrs {
			if ipn, ok := a.(*net.IPNet); ok && ipn.IP.To4() != nil && !ipn.IP.IsLinkLocalUnicast() {
				names = append(names, ifc.Name)
				break
			}
		}
	}
	return names
}

func run(name string, args ...string) {
	if err := exec.Command(name, args...).Run(); err != nil {
		log.Printf("warn: %s: %v", name, err)
	}
}
