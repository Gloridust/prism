package main

import (
	"fmt"
	"io"
	"log"
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

	ifName := "utun" + strconv.Itoa(int(sc.unit-1))
	return &tunDevice{fd: fd, name: ifName}, nil
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

func configureTUN(dev *tunDevice, addr, peerAddr string) error {
	cmds := [][]string{
		{"ifconfig", dev.Name(), "inet", addr, peerAddr, "up"},
		{"ifconfig", dev.Name(), "mtu", strconv.Itoa(tunMTU)},
	}
	for _, cmd := range cmds {
		if out, err := exec.Command(cmd[0], cmd[1:]...).CombinedOutput(); err != nil {
			return fmt.Errorf("%s: %s: %w", cmd[0], out, err)
		}
	}
	return nil
}

func addDefaultRoute(dev *tunDevice, serverHost, origGateway string) error {
	cmds := [][]string{
		{"route", "add", "-host", serverHost, origGateway},
		{"route", "add", "-net", "0.0.0.0/1", "-interface", dev.Name()},
		{"route", "add", "-net", "128.0.0.0/1", "-interface", dev.Name()},
	}
	for _, cmd := range cmds {
		if out, err := exec.Command(cmd[0], cmd[1:]...).CombinedOutput(); err != nil {
			return fmt.Errorf("%s: %s: %w", cmd[0], out, err)
		}
	}
	return nil
}

func removeDefaultRoute(serverHost, origGateway string) {
	exec.Command("route", "delete", "-net", "0.0.0.0/1").Run()
	exec.Command("route", "delete", "-net", "128.0.0.0/1").Run()
	exec.Command("route", "delete", "-host", serverHost, origGateway).Run()
}

func tunRouter(dev *tunDevice, dialer *Dialer) {
	buf := make([]byte, tunMTU+4)
	for {
		n, err := dev.Read(buf)
		if err != nil {
			if err == io.EOF {
				return
			}
			log.Printf("tun read: %v", err)
			return
		}
		// macOS utun prepends a 4-byte protocol family header.
		if n < 24 {
			continue
		}
		pkt := buf[4:n] // skip 4-byte AF header
		if pkt[0]>>4 != 4 {
			continue
		}
		ihl := int(pkt[0]&0x0f) * 4
		proto := pkt[9]
		dstIP := net.IP(pkt[16:20])

		switch proto {
		case 6:
			if len(pkt) < ihl+4 {
				continue
			}
			dstPort := int(pkt[ihl+2])<<8 | int(pkt[ihl+3])
			target := net.JoinHostPort(dstIP.String(), strconv.Itoa(dstPort))
			go func(t string) {
				st, err := dialer.Open(t)
				if err != nil {
					return
				}
				defer st.Close()
				io.Copy(st, st)
			}(target)
		case 17:
		}
	}
}
