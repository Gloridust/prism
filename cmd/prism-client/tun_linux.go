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
		tunSetIff = 0x400454ca
		iffTun    = 0x0001
		iffNoPi   = 0x1000
	)

	var req ifReq
	copy(req.name[:], name)
	req.flags = iffTun | iffNoPi

	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), tunSetIff, uintptr(unsafe.Pointer(&req)))
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
		if n < 20 {
			continue
		}
		pkt := buf[:n]
		if pkt[0]>>4 != 4 {
			continue
		}
		ihl := int(pkt[0]&0x0f) * 4
		proto := pkt[9]
		dstIP := net.IP(pkt[16:20])

		switch proto {
		case 6: // TCP
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
		case 17: // UDP — handled via UDP relay
		}
	}
}
