package main

import (
	"fmt"
	"io"
	"net"
	"os/exec"
	"sync"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wintun"
)

const tunMTU = 1500

type tunDevice struct {
	name      string
	adapter   *wintun.Adapter
	session   wintun.Session
	tunGW     string // TUN gateway IP for routing
	closed    chan struct{}
	closeOnce sync.Once
}

func openTUN(name string) (*tunDevice, error) {
	if name == "" {
		name = "Prism"
	}

	adapter, err := wintun.CreateAdapter(name, "Prism", nil)
	if err != nil {
		return nil, fmt.Errorf("WintunCreateAdapter: %w (download wintun.dll from https://www.wintun.net)", err)
	}

	session, err := adapter.StartSession(0x800000) // 8 MiB ring
	if err != nil {
		adapter.Close()
		return nil, fmt.Errorf("WintunStartSession: %w", err)
	}

	return &tunDevice{
		name:    name,
		adapter: adapter,
		session: session,
		closed:  make(chan struct{}),
	}, nil
}

func (t *tunDevice) Read(buf []byte) (int, error) {
	for {
		select {
		case <-t.closed:
			return 0, io.EOF
		default:
		}

		pkt, err := t.session.ReceivePacket()
		if err != nil {
			// ERROR_NO_MORE_ITEMS (259) — wait for data.
			windows.WaitForSingleObject(t.session.ReadWaitEvent(), 1000)
			continue
		}
		n := copy(buf, pkt)
		t.session.ReleaseReceivePacket(pkt)
		return n, nil
	}
}

func (t *tunDevice) Write(buf []byte) (int, error) {
	select {
	case <-t.closed:
		return 0, io.EOF
	default:
	}

	pkt, err := t.session.AllocateSendPacket(len(buf))
	if err != nil {
		return 0, fmt.Errorf("AllocateSendPacket: %w", err)
	}
	copy(pkt, buf)
	t.session.SendPacket(pkt)
	return len(buf), nil
}

func (t *tunDevice) Close() error {
	t.closeOnce.Do(func() {
		close(t.closed)
		t.session.End()
		t.adapter.Close()
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

func runAll(cmds [][]string) error {
	for _, cmd := range cmds {
		if out, err := exec.Command(cmd[0], cmd[1:]...).CombinedOutput(); err != nil {
			return fmt.Errorf("%v: %s: %w", cmd, out, err)
		}
	}
	return nil
}

func addDefaultRoute(dev *tunDevice, serverHost, origGateway string) error {
	if err := runAll([][]string{{"route", "add", serverHost, "mask", "255.255.255.255", origGateway}}); err != nil {
		return err
	}
	return addRoutes4(dev, ipv4CaptureRoutes)
}

// Routes are on-link and store=active so nothing outlives the adapter.
func addRoutes4(dev *tunDevice, prefixes []string) error {
	var cmds [][]string
	for _, p := range prefixes {
		cmds = append(cmds, []string{"netsh", "interface", "ipv4", "add", "route",
			"prefix=" + p, "interface=" + dev.Name(), "metric=5", "store=active"})
	}
	return runAll(cmds)
}

func addIPv6Capture(dev *tunDevice) error { return addRoutes6(dev, ipv6CaptureRoutes) }

func addRoutes6(dev *tunDevice, prefixes []string) error {
	cmds := [][]string{
		{"netsh", "interface", "ipv6", "add", "address", "interface=" + dev.Name(),
			fmt.Sprintf("address=%s/%d", tunAddr6, tunPrefix6), "store=active"},
	}
	for _, p := range prefixes {
		cmds = append(cmds, []string{"netsh", "interface", "ipv6", "add", "route",
			"prefix=" + p, "interface=" + dev.Name(), "metric=5", "store=active"})
	}
	return runAll(cmds)
}

func removeDefaultRoute(dev *tunDevice, serverHost, _ string) {
	for _, p := range ipv4CaptureRoutes {
		exec.Command("netsh", "interface", "ipv4", "delete", "route", "prefix="+p, "interface="+dev.Name()).Run()
	}
	for _, p := range ipv6CaptureRoutes {
		exec.Command("netsh", "interface", "ipv6", "delete", "route", "prefix="+p, "interface="+dev.Name()).Run()
	}
	exec.Command("route", "delete", serverHost).Run()
}

// addHostRoute sends traffic for one more server directly out the LAN gateway.
func addHostRoute(host, gw string) error {
	return runAll([][]string{{"route", "add", host, "mask", "255.255.255.255", gw}})
}

func delHostRoute(host, gw string) { exec.Command("route", "delete", host).Run() }
