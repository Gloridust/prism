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
	ifaces := activeInterfaces()
	for _, iface := range ifaces {
		run("netsh", "interface", "ip", "set", "dns", "name="+iface, "source=static", "addr="+host)
	}
	refreshWinINet()
	log.Printf("system DNS set to %s", host)
	return nil
}

func clearSystemDNS() error {
	ifaces := activeInterfaces()
	for _, iface := range ifaces {
		run("netsh", "interface", "ip", "set", "dns", "name="+iface, "source=dhcp")
	}
	refreshWinINet()
	log.Printf("system DNS restored to DHCP defaults")
	return nil
}

func activeInterfaces() []string {
	out, err := exec.Command("netsh", "interface", "show", "interface").Output()
	if err != nil {
		return []string{"Wi-Fi", "Ethernet"}
	}
	var ifaces []string
	for _, line := range strings.Split(string(out), "\n") {
		if strings.Contains(line, "Connected") && !strings.Contains(line, "Dedicated") {
			fields := strings.Fields(line)
			if len(fields) >= 4 {
				ifaces = append(ifaces, strings.Join(fields[3:], " "))
			}
		}
	}
	if len(ifaces) == 0 {
		return []string{"Wi-Fi", "Ethernet"}
	}
	return ifaces
}

func run(name string, args ...string) {
	if err := exec.Command(name, args...).Run(); err != nil {
		log.Printf("warn: %s: %v", name, err)
	}
}
