//go:build linux

package e2e

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"github.com/sagernet/gvisor/pkg/buffer"
	"github.com/sagernet/gvisor/pkg/tcpip"
	"github.com/sagernet/gvisor/pkg/tcpip/adapters/gonet"
	"github.com/sagernet/gvisor/pkg/tcpip/header"
	"github.com/sagernet/gvisor/pkg/tcpip/link/channel"
	"github.com/sagernet/gvisor/pkg/tcpip/network/ipv4"
	"github.com/sagernet/gvisor/pkg/tcpip/stack"
	"github.com/sagernet/gvisor/pkg/tcpip/transport/tcp"
	"github.com/sagernet/gvisor/pkg/tcpip/transport/udp"
	"github.com/sagernet/gvisor/pkg/waiter"

	utls "github.com/refraction-networking/utls"
	"golang.org/x/sys/unix"

	"github.com/gloridust/prism/pkg/prism"
)

const (
	iffTun  = 0x0001
	iffNoPi = 0x1000
	testMTU = 1500
)

type ifReq struct {
	name  [16]byte
	flags uint16
	_     [22]byte
}

// realTUN wraps a Linux /dev/net/tun file descriptor.
type realTUN struct {
	fd   int
	name string
}

func openRealTUN(t *testing.T, name string) *realTUN {
	t.Helper()
	fd, err := syscall.Open("/dev/net/tun", syscall.O_RDWR|syscall.O_CLOEXEC, 0)
	if err != nil {
		t.Fatalf("open /dev/net/tun: %v", err)
	}
	var req ifReq
	copy(req.name[:], name)
	req.flags = iffTun | iffNoPi
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), unix.TUNSETIFF, uintptr(unsafe.Pointer(&req)))
	if errno != 0 {
		syscall.Close(fd)
		t.Fatalf("TUNSETIFF: %v", errno)
	}
	devName := name
	for i, b := range req.name {
		if b == 0 {
			devName = string(req.name[:i])
			break
		}
	}
	return &realTUN{fd: fd, name: devName}
}

func (t *realTUN) Read(buf []byte) (int, error) {
	return syscall.Read(t.fd, buf)
}

func (t *realTUN) Write(buf []byte) (int, error) {
	return syscall.Write(t.fd, buf)
}

func (t *realTUN) Close() { syscall.Close(t.fd) }

func configureRealTUN(t *testing.T, dev *realTUN, addr string) {
	t.Helper()
	cmds := [][]string{
		{"ip", "addr", "add", addr, "dev", dev.name},
		{"ip", "link", "set", dev.name, "up"},
		{"ip", "link", "set", dev.name, "mtu", fmt.Sprintf("%d", testMTU)},
	}
	for _, cmd := range cmds {
		if out, err := exec.Command(cmd[0], cmd[1:]...).CombinedOutput(); err != nil {
			t.Fatalf("%s: %s: %v", cmd[0], out, err)
		}
	}
}

// tunRouterReal runs the gVisor netstack on a real TUN device fd, relaying
// TCP connections through a real Prism session. This is the same logic as
// cmd/prism-client/tun_stack.go's tunRouter, using the real TUN fd.
func tunRouterReal(dev *realTUN, sess *prism.Session, done chan struct{}) {
	ep := channel.New(512, testMTU, "")

	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol},
	})

	const nicID tcpip.NICID = 1
	if tcpErr := s.CreateNIC(nicID, ep); tcpErr != nil {
		return
	}
	s.SetRouteTable([]tcpip.Route{{Destination: header.IPv4EmptySubnet, NIC: nicID}})
	s.SetPromiscuousMode(nicID, true)
	s.SetSpoofing(nicID, true)

	tcpFwd := tcp.NewForwarder(s, 0, 4096, func(r *tcp.ForwarderRequest) {
		id := r.ID()
		var wq waiter.Queue
		endpoint, tcpErr := r.CreateEndpoint(&wq)
		if tcpErr != nil {
			r.Complete(true)
			return
		}
		r.Complete(false)
		conn := gonet.NewTCPConn(&wq, endpoint)

		target := net.JoinHostPort(id.LocalAddress.String(), itoa(id.LocalPort))
		go func() {
			defer conn.Close()
			st, err := sess.OpenStream(target)
			if err != nil {
				return
			}
			defer st.Close()
			ch := make(chan struct{}, 2)
			go func() { io.Copy(st, conn); st.CloseWrite(); ch <- struct{}{} }()
			go func() { io.Copy(conn, st); ch <- struct{}{} }()
			<-ch
			<-ch
		}()
	})
	s.SetTransportProtocolHandler(tcp.ProtocolNumber, tcpFwd.HandlePacket)

	// TUN fd → gVisor netstack.
	go func() {
		buf := make([]byte, testMTU)
		for {
			n, err := dev.Read(buf)
			if err != nil {
				return
			}
			if n == 0 {
				continue
			}
			pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
				Payload: buffer.MakeWithData(buf[:n]),
			})
			ep.InjectInbound(header.IPv4ProtocolNumber, pkt)
			pkt.DecRef()
		}
	}()

	// gVisor netstack → TUN fd.
	ctx := context.Background()
	go func() {
		for {
			pkt := ep.ReadContext(ctx)
			if pkt == nil {
				return
			}
			data := pkt.ToView().AsSlice()
			dev.Write(data)
			pkt.DecRef()
		}
	}()

	<-done
	s.Close()
}

// TestLinuxTUNDevice verifies that the real Linux TUN device works:
//  1. Opens /dev/net/tun via TUNSETIFF
//  2. Configures the interface with an IP address
//  3. Sends a ping (ICMP echo) through the TUN device
//  4. Reads the packet back from the TUN fd
//
// Requires CAP_NET_ADMIN. Run via: unshare --net --map-root-user go test ...
func TestLinuxTUNDevice(t *testing.T) {
	if os.Getenv("PRISM_ROOT_TEST") == "" {
		t.Skip("set PRISM_ROOT_TEST=1 to run TUN device test (requires CAP_NET_ADMIN)")
	}

	dev := openRealTUN(t, "prismtest")
	defer dev.Close()
	t.Logf("step 1: opened TUN device %q", dev.name)

	configureRealTUN(t, dev, "10.99.99.1/24")
	t.Logf("step 2: configured %s with 10.99.99.1/24", dev.name)

	go func() {
		exec.Command("ping", "-c", "1", "-W", "2", "10.99.99.2").Run()
	}()

	buf := make([]byte, 1500)
	pfd := []unix.PollFd{{Fd: int32(dev.fd), Events: unix.POLLIN}}
	n, err := unix.Poll(pfd, 3000)
	if err != nil {
		t.Fatalf("poll: %v", err)
	}
	if n == 0 {
		t.Fatal("timeout waiting for packet on TUN device")
	}

	nRead, err := syscall.Read(dev.fd, buf)
	if err != nil || nRead < 20 {
		t.Fatalf("read TUN: n=%d err=%v", nRead, err)
	}

	version := buf[0] >> 4
	for attempt := 0; version != 4 && attempt < 5; attempt++ {
		pfd[0].Events = unix.POLLIN
		n, err = unix.Poll(pfd, 2000)
		if err != nil || n == 0 {
			break
		}
		nRead, err = syscall.Read(dev.fd, buf)
		if err != nil || nRead < 20 {
			break
		}
		version = buf[0] >> 4
	}
	if version != 4 {
		t.Fatalf("never received an IPv4 packet (last version=%d)", version)
	}

	srcIP := net.IP(buf[12:16])
	dstIP := net.IP(buf[16:20])
	t.Logf("step 3: read %d-byte IPv4 packet from TUN: proto=%d src=%s dst=%s",
		nRead, buf[9], srcIP, dstIP)

	if dstIP.String() != "10.99.99.2" {
		t.Fatalf("expected dst 10.99.99.2, got %s", dstIP)
	}

	reply := make([]byte, nRead)
	copy(reply, buf[:nRead])
	copy(reply[12:16], dstIP.To4())
	copy(reply[16:20], srcIP.To4())
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

	nWritten, err := syscall.Write(dev.fd, reply)
	if err != nil {
		t.Fatalf("write TUN: %v", err)
	}
	t.Logf("step 4: wrote %d-byte reply to TUN", nWritten)

	exec.Command("ip", "link", "del", dev.name).Run()
	t.Log("Linux TUN device verified: open → configure → read raw IP → write reply")
}

// TestRealTUNWithRealPrism is the ultimate end-to-end proof: a real Linux
// /dev/net/tun device feeds raw IP packets into the gVisor netstack, which
// relays TCP through a real Prism session (real uTLS handshake, real Prism
// handshake, real AEAD encryption) to a real Prism echo server. A standard
// net.Dial from the host routes through the kernel's TUN interface, through
// the entire Prism protocol stack, and back.
//
// Run via: unshare --net --map-root-user go test -v -run TestRealTUNWithRealPrism ./test/
func TestRealTUNWithRealPrism(t *testing.T) {
	if os.Getenv("PRISM_ROOT_TEST") == "" {
		t.Skip("set PRISM_ROOT_TEST=1 (requires CAP_NET_ADMIN)")
	}

	// Bring up loopback (unshare namespace starts with lo down).
	if out, err := exec.Command("ip", "link", "set", "lo", "up").CombinedOutput(); err != nil {
		t.Fatalf("ip link set lo up: %s: %v", out, err)
	}

	// --- Step 1: Start a real Prism echo server on loopback. ---
	kp, err := prism.GenerateServerKeypair()
	if err != nil {
		t.Fatal(err)
	}
	psk, err := prism.NewPSK()
	if err != nil {
		t.Fatal(err)
	}
	cred := prism.Credential{ID: prism.ClientID{0xDE, 0xAD, 0xBE, 0xEF}, PSK: psk}
	serverAEADs, _ := prism.AEADFactoriesByName([]string{prism.CipherAES256GCM})

	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{selfSignedCert(t)},
		MinVersion:   tls.VersionTLS12,
		NextProtos:   []string{"http/1.1"},
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go serveCarrier(conn, tlsCfg, kp.Private, []prism.Credential{cred}, serverAEADs)
		}
	}()
	t.Logf("step 1: Prism echo server listening on %s", ln.Addr())

	// --- Step 2: Establish a real Prism session (real uTLS + Prism handshake). ---
	raw, err := net.DialTimeout("tcp", ln.Addr().String(), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	uconn := utls.UClient(raw, &utls.Config{
		ServerName:         "localhost",
		InsecureSkipVerify: true,
		MinVersion:         utls.VersionTLS12,
		NextProtos:         []string{"http/1.1"},
	}, utls.HelloChrome_Auto)
	_ = uconn.SetDeadline(time.Now().Add(10 * time.Second))
	if err := uconn.Handshake(); err != nil {
		t.Fatalf("uTLS handshake: %v", err)
	}
	keys, err := prism.ClientHandshake(uconn, kp.Public, cred, prism.NewAEAD)
	if err != nil {
		t.Fatalf("Prism handshake: %v", err)
	}
	_ = uconn.SetDeadline(time.Time{})
	sess, err := prism.NewSession(uconn, keys, true)
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()
	t.Logf("step 2: Prism session established (uTLS Chrome + AES-256-GCM)")

	// --- Step 3: Open a real /dev/net/tun and configure it. ---
	dev := openRealTUN(t, "prism0")
	defer dev.Close()
	configureRealTUN(t, dev, "10.0.85.1/24")
	t.Logf("step 3: real TUN device %q up with 10.0.85.1/24", dev.name)

	// --- Step 4: Run the gVisor netstack on the real TUN fd. ---
	routerDone := make(chan struct{})
	go tunRouterReal(dev, sess, routerDone)
	defer close(routerDone)
	t.Log("step 4: gVisor netstack tunRouter running on real TUN fd")

	// Give the router a moment to start.
	time.Sleep(50 * time.Millisecond)

	// --- Step 5: Dial a TCP connection THROUGH the real TUN device. ---
	// Traffic to 10.0.85.0/24 routes through the TUN interface. The kernel
	// delivers the raw IP packets to the TUN fd. gVisor reassembles them
	// into a TCP connection. The TCP forwarder opens a Prism stream. The
	// echo server echoes back. Data returns through gVisor → TUN fd → kernel.
	conn, err := net.DialTimeout("tcp", "10.0.85.2:8080", 5*time.Second)
	if err != nil {
		t.Fatalf("dial through TUN: %v", err)
	}
	defer conn.Close()
	t.Log("step 5: TCP connection established through real TUN device")

	// --- Step 6: Send payload and verify echo. ---
	payload := bytes.Repeat([]byte("REAL-TUN-PRISM!"), 500) // 7.5 KB
	conn.SetDeadline(time.Now().Add(10 * time.Second))

	go func() {
		conn.Write(payload)
		conn.(*net.TCPConn).CloseWrite()
	}()

	got, err := io.ReadAll(conn)
	if err != nil {
		t.Fatalf("read echo: %v", err)
	}

	if !bytes.Equal(got, payload) {
		t.Fatalf("echo mismatch: got %d bytes, want %d", len(got), len(payload))
	}

	t.Logf("step 6: %d bytes echoed through real TUN → gVisor → real Prism → echo server → back", len(payload))
	t.Log("FULL PIPELINE VERIFIED: real /dev/net/tun → kernel routing → gVisor netstack → real Prism session (uTLS + AEAD) → echo server → data round-tripped")
	fmt.Fprintf(os.Stderr, "\n  Real TUN + real Prism end-to-end test passed.\n")
}
