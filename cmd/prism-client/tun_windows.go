package main

import (
	"fmt"
	"io"
	"log"
	"net"
	"os/exec"
	"strconv"
	"sync"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

const tunMTU = 1500

var (
	wintunDLL                      = windows.NewLazyDLL("wintun.dll")
	procWintunCreateAdapter        = wintunDLL.NewProc("WintunCreateAdapter")
	procWintunCloseAdapter         = wintunDLL.NewProc("WintunCloseAdapter")
	procWintunStartSession         = wintunDLL.NewProc("WintunStartSession")
	procWintunEndSession           = wintunDLL.NewProc("WintunEndSession")
	procWintunGetReadWaitEvent     = wintunDLL.NewProc("WintunGetReadWaitEvent")
	procWintunReceivePacket        = wintunDLL.NewProc("WintunReceivePacket")
	procWintunReleaseReceivePacket = wintunDLL.NewProc("WintunReleaseReceivePacket")
	procWintunAllocateSendPacket   = wintunDLL.NewProc("WintunAllocateSendPacket")
	procWintunSendPacket           = wintunDLL.NewProc("WintunSendPacket")
)

type tunDevice struct {
	name     string
	adapter  uintptr
	session  uintptr
	readWait windows.Handle
	tunGW    string // TUN gateway IP for routing
	closed   chan struct{}
	closeOnce sync.Once
}

func openTUN(name string) (*tunDevice, error) {
	if err := wintunDLL.Load(); err != nil {
		return nil, fmt.Errorf("wintun.dll not found: %w (download from https://www.wintun.net)", err)
	}
	if name == "" {
		name = "Prism"
	}

	nameUTF16, _ := windows.UTF16PtrFromString(name)
	typeUTF16, _ := windows.UTF16PtrFromString("Prism")

	adapter, _, err := procWintunCreateAdapter.Call(
		uintptr(unsafe.Pointer(nameUTF16)),
		uintptr(unsafe.Pointer(typeUTF16)),
		0,
	)
	if adapter == 0 {
		return nil, fmt.Errorf("WintunCreateAdapter: %w", err)
	}

	// 8 MiB ring buffer (must be power of 2, range 128 KiB – 64 MiB).
	session, _, err := procWintunStartSession.Call(adapter, 0x800000)
	if session == 0 {
		procWintunCloseAdapter.Call(adapter)
		return nil, fmt.Errorf("WintunStartSession: %w", err)
	}

	readWait, _, _ := procWintunGetReadWaitEvent.Call(session)

	return &tunDevice{
		name:     name,
		adapter:  adapter,
		session:  session,
		readWait: windows.Handle(readWait),
		closed:   make(chan struct{}),
	}, nil
}

func (t *tunDevice) Read(buf []byte) (int, error) {
	for {
		select {
		case <-t.closed:
			return 0, io.EOF
		default:
		}

		var packetSize uint32
		packet, _, err := procWintunReceivePacket.Call(
			t.session,
			uintptr(unsafe.Pointer(&packetSize)),
		)
		if packet == 0 {
			if errno, ok := err.(syscall.Errno); ok && errno == 259 {
				// ERROR_NO_MORE_ITEMS — wait for the read event.
				windows.WaitForSingleObject(t.readWait, 1000)
				continue
			}
			return 0, fmt.Errorf("WintunReceivePacket: %w", err)
		}

		n := copy(buf, unsafe.Slice((*byte)(unsafe.Pointer(packet)), packetSize))
		procWintunReleaseReceivePacket.Call(t.session, packet)
		return n, nil
	}
}

func (t *tunDevice) Write(buf []byte) (int, error) {
	select {
	case <-t.closed:
		return 0, io.EOF
	default:
	}

	n := len(buf)
	packet, _, err := procWintunAllocateSendPacket.Call(t.session, uintptr(n))
	if packet == 0 {
		return 0, fmt.Errorf("WintunAllocateSendPacket: %w", err)
	}
	copy(unsafe.Slice((*byte)(unsafe.Pointer(packet)), n), buf)
	procWintunSendPacket.Call(t.session, packet)
	return n, nil
}

func (t *tunDevice) Close() error {
	t.closeOnce.Do(func() {
		close(t.closed)
		if t.session != 0 {
			procWintunEndSession.Call(t.session)
		}
		if t.adapter != 0 {
			procWintunCloseAdapter.Call(t.adapter)
		}
	})
	return nil
}

func (t *tunDevice) Name() string { return t.name }

func configureTUN(dev *tunDevice, addr, gateway string) error {
	ip, ipNet, err := net.ParseCIDR(addr)
	if err != nil {
		return fmt.Errorf("TUN address must be CIDR (e.g. 10.0.85.1/24): %w", err)
	}
	mask := net.IP(ipNet.Mask).String()
	dev.tunGW = gateway

	cmds := [][]string{
		{"netsh", "interface", "ip", "set", "address", dev.Name(), "static", ip.String(), mask, gateway},
		{"netsh", "interface", "ipv4", "set", "subinterface", dev.Name(), fmt.Sprintf("mtu=%d", tunMTU)},
	}
	for _, cmd := range cmds {
		if out, err := exec.Command(cmd[0], cmd[1:]...).CombinedOutput(); err != nil {
			return fmt.Errorf("%v: %s: %w", cmd, out, err)
		}
	}
	return nil
}

func addDefaultRoute(dev *tunDevice, serverHost, origGateway string) error {
	cmds := [][]string{
		{"route", "add", serverHost, "mask", "255.255.255.255", origGateway},
		{"route", "add", "0.0.0.0", "mask", "128.0.0.0", dev.tunGW, "metric", "5"},
		{"route", "add", "128.0.0.0", "mask", "128.0.0.0", dev.tunGW, "metric", "5"},
	}
	for _, cmd := range cmds {
		if out, err := exec.Command(cmd[0], cmd[1:]...).CombinedOutput(); err != nil {
			return fmt.Errorf("%v: %s: %w", cmd, out, err)
		}
	}
	return nil
}

func removeDefaultRoute(serverHost, _ string) {
	exec.Command("route", "delete", "0.0.0.0", "mask", "128.0.0.0").Run()
	exec.Command("route", "delete", "128.0.0.0", "mask", "128.0.0.0").Run()
	exec.Command("route", "delete", serverHost).Run()
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
