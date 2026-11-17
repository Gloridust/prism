//go:build linux

package e2e

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"syscall"
	"testing"
	"unsafe"

	"golang.org/x/sys/unix"
)

// TestLinuxTUNDevice verifies that the real Linux TUN device works:
//  1. Opens /dev/net/tun via TUNSETIFF
//  2. Configures the interface with an IP address
//  3. Sends a ping (ICMP echo) through the TUN device
//  4. Reads the packet back from the TUN fd
//
// Requires root (CAP_NET_ADMIN). Set PRISM_ROOT_TEST=1 to run.
func TestLinuxTUNDevice(t *testing.T) {
	if os.Getenv("PRISM_ROOT_TEST") == "" {
		t.Skip("set PRISM_ROOT_TEST=1 to run TUN device test (requires root)")
	}
	if os.Getuid() != 0 {
		t.Skip("must run as root for TUN device test")
	}

	// Open /dev/net/tun.
	fd, err := syscall.Open("/dev/net/tun", syscall.O_RDWR|syscall.O_CLOEXEC, 0)
	if err != nil {
		t.Fatalf("open /dev/net/tun: %v", err)
	}
	defer syscall.Close(fd)

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
	copy(req.name[:], "prismtest")
	req.flags = iffTun | iffNoPi
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), tunSetIff, uintptr(unsafe.Pointer(&req)))
	if errno != 0 {
		t.Fatalf("TUNSETIFF: %v", errno)
	}

	devName := "prismtest"
	for i, b := range req.name {
		if b == 0 {
			devName = string(req.name[:i])
			break
		}
	}
	t.Logf("step 1: opened TUN device %q", devName)

	// Configure the interface.
	cmds := [][]string{
		{"ip", "addr", "add", "10.99.99.1/24", "dev", devName},
		{"ip", "link", "set", devName, "up"},
		{"ip", "link", "set", devName, "mtu", "1500"},
	}
	for _, cmd := range cmds {
		if out, err := exec.Command(cmd[0], cmd[1:]...).CombinedOutput(); err != nil {
			t.Fatalf("%s: %s: %v", cmd[0], out, err)
		}
	}
	t.Logf("step 2: configured %s with 10.99.99.1/24", devName)

	// Send a ping to 10.99.99.2 — this will generate an ICMP echo request
	// that arrives on the TUN fd.
	go func() {
		exec.Command("ping", "-c", "1", "-W", "2", "10.99.99.2").Run()
	}()

	// Read from the TUN device — we should get the ICMP packet.
	buf := make([]byte, 1500)
	syscall.SetNonblock(fd, false)

	// Set a read deadline via poll.
	pfd := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
	n, err := unix.Poll(pfd, 3000) // 3 second timeout
	if err != nil {
		t.Fatalf("poll: %v", err)
	}
	if n == 0 {
		t.Fatal("timeout waiting for packet on TUN device")
	}

	nRead, err := syscall.Read(fd, buf)
	if err != nil {
		t.Fatalf("read TUN: %v", err)
	}
	if nRead < 20 {
		t.Fatalf("packet too short: %d bytes", nRead)
	}

	// Verify it's an IPv4 packet.
	version := buf[0] >> 4
	if version != 4 {
		t.Fatalf("expected IPv4 (version 4), got %d", version)
	}

	proto := buf[9]
	srcIP := net.IP(buf[12:16])
	dstIP := net.IP(buf[16:20])
	t.Logf("step 3: read %d-byte packet from TUN: IPv4 proto=%d src=%s dst=%s",
		nRead, proto, srcIP, dstIP)

	if proto != 1 { // ICMP
		t.Logf("warning: expected ICMP (proto 1), got proto %d", proto)
	}
	if dstIP.String() != "10.99.99.2" {
		t.Fatalf("expected dst 10.99.99.2, got %s", dstIP)
	}

	// Write a reply back (swap src/dst) to prove the write path works.
	reply := make([]byte, nRead)
	copy(reply, buf[:nRead])
	copy(reply[12:16], dstIP.To4())
	copy(reply[16:20], srcIP.To4())
	// Fix IP checksum (zero it, recompute).
	reply[10], reply[11] = 0, 0
	var csum uint32
	ihl := int(reply[0]&0x0f) * 4
	for i := 0; i < ihl-1; i += 2 {
		csum += uint32(reply[i])<<8 | uint32(reply[i+1])
	}
	for csum>>16 != 0 {
		csum = (csum & 0xffff) + (csum >> 16)
	}
	reply[10] = byte(^csum >> 8)
	reply[11] = byte(^csum)

	nWritten, err := syscall.Write(fd, reply)
	if err != nil {
		t.Fatalf("write TUN: %v", err)
	}
	t.Logf("step 4: wrote %d-byte reply to TUN (swapped src/dst)", nWritten)

	// Clean up.
	exec.Command("ip", "link", "del", devName).Run()

	t.Log("Linux TUN device verified: open → configure → read raw IP packet → write reply")
	fmt.Fprintf(os.Stderr, "\n  Real /dev/net/tun device test passed.\n")
}
