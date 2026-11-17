//go:build darwin

package main

import (
	"log"
	"net"
	"os/exec"
	"strings"
)

func networkServices() []string {
	out, err := exec.Command("networksetup", "-listallnetworkservices").Output()
	if err != nil {
		return nil
	}
	var svcs []string
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "*") || strings.HasPrefix(line, "An asterisk") {
			continue
		}
		svcs = append(svcs, line)
	}
	return svcs
}

func setSystemProxy(httpAddr, socksAddr string) error {
	hh, hp, _ := net.SplitHostPort(httpAddr)
	sh, sp, _ := net.SplitHostPort(socksAddr)
	for _, svc := range networkServices() {
		run("networksetup", "-setsocksfirewallproxy", svc, sh, sp)
		run("networksetup", "-setsocksfirewallproxystate", svc, "on")
		run("networksetup", "-setwebproxy", svc, hh, hp)
		run("networksetup", "-setwebproxystate", svc, "on")
		run("networksetup", "-setsecurewebproxy", svc, hh, hp)
		run("networksetup", "-setsecurewebproxystate", svc, "on")
	}
	log.Printf("system proxy set (SOCKS %s, HTTP %s)", socksAddr, httpAddr)
	return nil
}

func clearSystemProxy() error {
	for _, svc := range networkServices() {
		run("networksetup", "-setsocksfirewallproxystate", svc, "off")
		run("networksetup", "-setwebproxystate", svc, "off")
		run("networksetup", "-setsecurewebproxystate", svc, "off")
	}
	log.Printf("system proxy cleared")
	return nil
}

func setSystemDNS(dnsAddr string) error {
	host, _, _ := net.SplitHostPort(dnsAddr)
	for _, svc := range networkServices() {
		run("networksetup", "-setdnsservers", svc, host)
	}
	log.Printf("system DNS set to %s", host)
	return nil
}

func clearSystemDNS() error {
	for _, svc := range networkServices() {
		run("networksetup", "-setdnsservers", svc, "empty")
	}
	log.Printf("system DNS restored to DHCP defaults")
	return nil
}

func run(name string, args ...string) {
	if err := exec.Command(name, args...).Run(); err != nil {
		log.Printf("warn: %s %s: %v", name, strings.Join(args, " "), err)
	}
}
