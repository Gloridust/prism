package main

import (
	"fmt"
	"net"
	"os/exec"
	"strconv"
	"syscall"
	"unsafe"
)

const tunMTU = 1500

type tunDevice struct {
	fd   int
	name string
	rbuf []byte // persistent read buffer (avoids alloc per packet)
}

func openTUN(_ string) (*tunDevice, error) {
	fd, err := syscall.Socket(syscall.AF_SYSTEM, syscall.SOCK_DGRAM, 2) // SYSPROTO_CONTROL
	if err != nil {
		return nil, fmt.Errorf("socket: %w", err)
	}

	type ctlInfo struct {
		id   uint32
		name [96]byte
	}
	const ctlIOCGInfo = 0xc0644e03
	var info ctlInfo
	copy(info.name[:], "com.apple.net.utun_control")
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), ctlIOCGInfo, uintptr(unsafe.Pointer(&info)))
	if errno != 0 {
		syscall.Close(fd)
		return nil, fmt.Errorf("CTLIOCGINFO: %w", errno)
	}

	type sockaddrCtl struct {
		len    uint8
		family uint8
		ss     uint16
		id     uint32
		unit   uint32
		_      [5]uint32
	}
	sc := sockaddrCtl{
		len:    uint8(unsafe.Sizeof(sockaddrCtl{})),
		family: syscall.AF_SYSTEM,
		ss:     2, // SYSPROTO_CONTROL
		id:     info.id,
		unit:   0, // auto-assign
	}
	_, _, errno = syscall.Syscall(syscall.SYS_CONNECT, uintptr(fd), uintptr(unsafe.Pointer(&sc)), uintptr(sc.len))
	if errno != 0 {
		syscall.Close(fd)
		return nil, fmt.Errorf("connect utun: %w", errno)
	}

	var ifname [16]byte
	ifnameLen := uint32(len(ifname))
	_, _, errno = syscall.Syscall6(syscall.SYS_GETSOCKOPT, uintptr(fd),
		2, 2, // SYSPROTO_CONTROL, UTUN_OPT_IFNAME
		uintptr(unsafe.Pointer(&ifname[0])),
		uintptr(unsafe.Pointer(&ifnameLen)),
		0)
	if errno != 0 {
		syscall.Close(fd)
		return nil, fmt.Errorf("getsockopt UTUN_OPT_IFNAME: %w", errno)
	}
	n := ifnameLen
	for n > 0 && ifname[n-1] == 0 {
		n--
	}
	return &tunDevice{fd: fd, name: string(ifname[:n]), rbuf: make([]byte, tunMTU+4)}, nil
}

// Read returns a raw IPv4 packet with the macOS utun 4-byte AF header stripped.
func (t *tunDevice) Read(buf []byte) (int, error) {
	n, err := syscall.Read(t.fd, t.rbuf)
	if n <= 4 {
		if err != nil {
			return 0, err
		}
		return 0, nil
	}
	return copy(buf, t.rbuf[4:n]), nil
}

// Write prepends the macOS utun 4-byte address-family header and writes a raw
// IPv4 or IPv6 packet to the TUN device.
func (t *tunDevice) Write(buf []byte) (int, error) {
	if len(buf) == 0 {
		return 0, nil
	}
	af := byte(syscall.AF_INET)
	if buf[0]>>4 == 6 {
		af = syscall.AF_INET6
	}
	wbuf := make([]byte, 4+len(buf))
	wbuf[0], wbuf[1], wbuf[2], wbuf[3] = 0, 0, 0, af
	copy(wbuf[4:], buf)
	n, err := syscall.Write(t.fd, wbuf)
	if n > 4 {
		return n - 4, err
	}
	return 0, err
}

func (t *tunDevice) Close() error {
	return syscall.Close(t.fd)
}

func (t *tunDevice) Name() string { return t.name }

func configureTUN(dev *tunDevice, addr, peerAddr string) error {
	ip, _, err := net.ParseCIDR(addr)
	if err != nil {
		ip = net.ParseIP(addr)
		if ip == nil {
			return fmt.Errorf("invalid TUN address: %s", addr)
		}
	}
	cmds := [][]string{
		{"ifconfig", dev.Name(), "inet", ip.String(), peerAddr, "up"},
		{"ifconfig", dev.Name(), "mtu", strconv.Itoa(tunMTU)},
	}
	for _, cmd := range cmds {
		if out, err := exec.Command(cmd[0], cmd[1:]...).CombinedOutput(); err != nil {
			return fmt.Errorf("%s: %s: %w", cmd[0], out, err)
		}
	}
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
	if err := runAll([][]string{{"route", "-n", "add", "-host", serverHost, origGateway}}); err != nil {
		return err
	}
	return addRoutes4(dev, ipv4CaptureRoutes)
}

func addRoutes4(dev *tunDevice, prefixes []string) error {
	var cmds [][]string
	for _, p := range prefixes {
		cmds = append(cmds, []string{"route", "-n", "add", "-net", p, "-interface", dev.Name()})
	}
	return runAll(cmds)
}

func addIPv6Capture(dev *tunDevice) error { return addRoutes6(dev, ipv6CaptureRoutes) }

// addRoutes6 gives the utun an IPv6 address and routes prefixes into it.
func addRoutes6(dev *tunDevice, prefixes []string) error {
	cmds := [][]string{
		{"ifconfig", dev.Name(), "inet6", fmt.Sprintf("%s/%d", tunAddr6, tunPrefix6), "alias"},
	}
	for _, p := range prefixes {
		cmds = append(cmds, []string{"route", "-n", "add", "-inet6", p, "-interface", dev.Name()})
	}
	return runAll(cmds)
}

func removeDefaultRoute(dev *tunDevice, serverHost, origGateway string) {
	for _, p := range ipv4CaptureRoutes {
		exec.Command("route", "-n", "delete", "-net", p, "-interface", dev.Name()).Run()
	}
	for _, p := range ipv6CaptureRoutes {
		exec.Command("route", "-n", "delete", "-inet6", p, "-interface", dev.Name()).Run()
	}
	exec.Command("route", "-n", "delete", "-host", serverHost, origGateway).Run()
}

// addHostRoute sends traffic for one more server directly out the LAN gateway.
func addHostRoute(host, gw string) error {
	return runAll([][]string{{"route", "-n", "add", "-host", host, gw}})
}

func delHostRoute(host, gw string) { exec.Command("route", "-n", "delete", "-host", host, gw).Run() }
