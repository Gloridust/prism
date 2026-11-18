package main

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

const tunMTU = 1500

type tunDevice struct {
	fd   int
	name string
}

func openTUN(name string) (*tunDevice, error) {
	fd, err := syscall.Open("/dev/net/tun", syscall.O_RDWR|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("open /dev/net/tun: %w", err)
	}

	type ifReq struct {
		name  [16]byte
		flags uint16
		_     [22]byte
	}

	const (
		iffTun  = 0x0001
		iffNoPi = 0x1000
	)

	var req ifReq
	copy(req.name[:], name)
	req.flags = iffTun | iffNoPi

	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), unix.TUNSETIFF, uintptr(unsafe.Pointer(&req)))
	if errno != 0 {
		syscall.Close(fd)
		return nil, fmt.Errorf("TUNSETIFF: %w", errno)
	}

	actualName := string(req.name[:])
	for i, b := range actualName {
		if b == 0 {
			actualName = actualName[:i]
			break
		}
	}

	return &tunDevice{fd: fd, name: actualName}, nil
}

func (t *tunDevice) Read(buf []byte) (int, error) {
	n, err := syscall.Read(t.fd, buf)
	if n <= 0 && err != nil {
		return 0, err
	}
	return n, nil
}

func (t *tunDevice) Write(buf []byte) (int, error) {
	return syscall.Write(t.fd, buf)
}

func (t *tunDevice) Close() error {
	return syscall.Close(t.fd)
}

func (t *tunDevice) Name() string { return t.name }

func configureTUN(dev *tunDevice, addr, _ string) error {
	ip, _, err := net.ParseCIDR(addr)
	if err != nil {
		ip = net.ParseIP(addr)
		if ip == nil {
			return fmt.Errorf("invalid TUN address: %s", addr)
		}
	}
	cmds := [][]string{
		{"ip", "addr", "add", addr, "dev", dev.Name()},
		{"ip", "link", "set", dev.Name(), "up"},
		{"ip", "link", "set", dev.Name(), "mtu", strconv.Itoa(tunMTU)},
	}
	for _, cmd := range cmds {
		if out, err := exec.Command(cmd[0], cmd[1:]...).CombinedOutput(); err != nil {
			return fmt.Errorf("%s: %s: %w", cmd[0], out, err)
		}
	}
	_ = ip
	return nil
}

func runAll(cmds [][]string) error {
	for _, cmd := range cmds {
		if out, err := exec.Command(cmd[0], cmd[1:]...).CombinedOutput(); err != nil {
			return fmt.Errorf("%v: %s: %w", cmd, out, err)
		}
	}
	return nil
}

func addDefaultRoute(dev *tunDevice, serverHost, origGateway string) error {
	if err := runAll([][]string{{"ip", "route", "add", serverHost + "/32", "via", origGateway}}); err != nil {
		return err
	}
	return addRoutes4(dev, ipv4CaptureRoutes)
}

func addRoutes4(dev *tunDevice, prefixes []string) error {
	var cmds [][]string
	for _, p := range prefixes {
		cmds = append(cmds, []string{"ip", "route", "add", p, "dev", dev.Name()})
	}
	return runAll(cmds)
}

func addIPv6Capture(dev *tunDevice) error { return addRoutes6(dev, ipv6CaptureRoutes) }

// addRoutes6 gives the TUN an IPv6 address and routes prefixes into it.
func addRoutes6(dev *tunDevice, prefixes []string) error {
	_ = os.WriteFile("/proc/sys/net/ipv6/conf/"+dev.Name()+"/disable_ipv6", []byte("0"), 0o644)
	cmds := [][]string{
		{"ip", "-6", "addr", "add", fmt.Sprintf("%s/%d", tunAddr6, tunPrefix6), "dev", dev.Name(), "nodad"},
	}
	for _, p := range prefixes {
		cmds = append(cmds, []string{"ip", "-6", "route", "add", p, "dev", dev.Name()})
	}
	return runAll(cmds)
}

func removeDefaultRoute(dev *tunDevice, serverHost, _ string) {
	for _, p := range ipv4CaptureRoutes {
		exec.Command("ip", "route", "del", p, "dev", dev.Name()).Run()
	}
	for _, p := range ipv6CaptureRoutes {
		exec.Command("ip", "-6", "route", "del", p, "dev", dev.Name()).Run()
	}
	exec.Command("ip", "route", "del", serverHost+"/32").Run()
}

// addHostRoute sends traffic for one more server directly out the LAN gateway.
func addHostRoute(host, gw string) error {
	return runAll([][]string{{"ip", "route", "add", host + "/32", "via", gw}})
}

func delHostRoute(host, gw string) { exec.Command("ip", "route", "del", host+"/32").Run() }
