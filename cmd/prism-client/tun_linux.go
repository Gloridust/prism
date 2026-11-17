package main

import (
	"fmt"
	"net"
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
		iffTun = 0x0001
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

func addDefaultRoute(dev *tunDevice, serverHost, origGateway string) error {
	cmds := [][]string{
		{"ip", "route", "add", serverHost + "/32", "via", origGateway},
		{"ip", "route", "add", "0.0.0.0/1", "dev", dev.Name()},
		{"ip", "route", "add", "128.0.0.0/1", "dev", dev.Name()},
	}
	for _, cmd := range cmds {
		if out, err := exec.Command(cmd[0], cmd[1:]...).CombinedOutput(); err != nil {
			return fmt.Errorf("%s: %s: %w", cmd[0], out, err)
		}
	}
	return nil
}

func removeDefaultRoute(serverHost, _ string) {
	exec.Command("ip", "route", "del", "0.0.0.0/1").Run()
	exec.Command("ip", "route", "del", "128.0.0.0/1").Run()
	exec.Command("ip", "route", "del", serverHost+"/32").Run()
}
