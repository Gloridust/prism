package main

import (
	"bytes"
	"io"
	"net"
	"os"
	"os/exec"
	"runtime"
	"testing"
	"time"
)

// TestTUNCapturesIPv4AndIPv6 runs the production TUN setup on a real OS TUN
// device and proves that both IPv4 and IPv6, TCP and UDP (a STUN probe), are
// routed by the kernel into the tunnel. It uses documentation prefixes so it
// never disturbs the host's real routing.
//
// Requires root/admin: PRISM_ROOT_TEST=1.
func TestTUNCapturesIPv4AndIPv6(t *testing.T) {
	if os.Getenv("PRISM_ROOT_TEST") == "" {
		t.Skip("set PRISM_ROOT_TEST=1 (requires root/admin for a TUN device)")
	}
	if runtime.GOOS == "linux" {
		exec.Command("ip", "link", "set", "lo", "up").Run()
	}

	echoAddr, stopEcho := startEchoServer(t)
	defer stopEcho()

	dev, err := openTUN("prismcap0")
	if err != nil {
		t.Fatalf("openTUN: %v", err)
	}
	defer dev.Close()

	for i := 0; ; i++ {
		if err = configureTUN(dev, "10.0.86.1/24", "10.0.86.2"); err == nil {
			break
		}
		if i == 9 {
			t.Fatalf("configureTUN: %v", err)
		}
		time.Sleep(time.Second)
	}
	if err := addRoutes4(dev, []string{"198.51.100.0/24"}); err != nil {
		t.Fatalf("addRoutes4: %v", err)
	}
	if err := addRoutes6(dev, []string{"2001:db8::/32"}); err != nil {
		t.Fatalf("addRoutes6: %v", err)
	}
	t.Logf("TUN %s up with IPv4 + IPv6 routes", dev.Name())

	dialer := &mockDialer{echoAddr: echoAddr}
	go tunRouter(dev, dialer)

	for _, dst := range []string{"198.51.100.7", "2001:db8::7"} {
		t.Run("tcp-"+dst, func(t *testing.T) {
			target := net.JoinHostPort(dst, "80")
			var conn net.Conn
			var err error
			for i := 0; i < 10; i++ {
				if conn, err = net.DialTimeout("tcp", target, 2*time.Second); err == nil {
					break
				}
				time.Sleep(500 * time.Millisecond)
			}
			if err != nil {
				t.Fatalf("dial %s through TUN: %v", target, err)
			}
			defer conn.Close()
			conn.SetDeadline(time.Now().Add(5 * time.Second))
			msg := []byte("captured by prism tun")
			conn.Write(msg)
			got := make([]byte, len(msg))
			if _, err := io.ReadFull(conn, got); err != nil || !bytes.Equal(got, msg) {
				t.Fatalf("echo: %q %v", got, err)
			}
			waitForTarget(t, dialer.getTargets, target)
		})

		t.Run("udp-stun-"+dst, func(t *testing.T) {
			target := net.JoinHostPort(dst, "3478")
			conn, err := net.Dial("udp", target)
			if err != nil {
				t.Fatalf("udp dial %s: %v", target, err)
			}
			defer conn.Close()
			req := stunBindingRequest()
			buf := make([]byte, 2048)
			for i := 0; i < 10; i++ {
				conn.Write(req)
				conn.SetReadDeadline(time.Now().Add(time.Second))
				n, err := conn.Read(buf)
				if err == nil {
					if !bytes.Equal(buf[:n], req) {
						t.Fatalf("stun echo mismatch")
					}
					waitForTarget(t, dialer.getUDPTargets, target)
					return
				}
			}
			t.Fatalf("STUN probe to %s never came back through the TUN", target)
		})
	}
}
