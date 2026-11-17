//go:build darwin

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
	"strconv"
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

	"github.com/gloridust/prism/pkg/prism"
)

const darwinMTU = 1500

type darwinTUN struct {
	fd   int
	name string
	rbuf []byte
}

func openDarwinTUN(t *testing.T) *darwinTUN {
	t.Helper()
	fd, err := syscall.Socket(syscall.AF_SYSTEM, syscall.SOCK_DGRAM, 2)
	if err != nil {
		t.Fatalf("socket AF_SYSTEM: %v", err)
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
		t.Fatalf("CTLIOCGINFO: %v", errno)
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
		ss:     2,
		id:     info.id,
		unit:   0,
	}
	_, _, errno = syscall.Syscall(syscall.SYS_CONNECT, uintptr(fd), uintptr(unsafe.Pointer(&sc)), uintptr(sc.len))
	if errno != 0 {
		syscall.Close(fd)
		t.Fatalf("connect utun: %v", errno)
	}

	name := "utun" + strconv.Itoa(int(sc.unit-1))
	return &darwinTUN{fd: fd, name: name, rbuf: make([]byte, darwinMTU+4)}
}

func (t *darwinTUN) Read(buf []byte) (int, error) {
	n, err := syscall.Read(t.fd, t.rbuf)
	if n <= 4 {
		if err != nil {
			return 0, err
		}
		return 0, nil
	}
	return copy(buf, t.rbuf[4:n]), nil
}

func (t *darwinTUN) Write(buf []byte) (int, error) {
	wbuf := make([]byte, 4+len(buf))
	wbuf[0], wbuf[1], wbuf[2], wbuf[3] = 0, 0, 0, syscall.AF_INET
	copy(wbuf[4:], buf)
	n, err := syscall.Write(t.fd, wbuf)
	if n > 4 {
		return n - 4, err
	}
	return 0, err
}

func (t *darwinTUN) Close() { syscall.Close(t.fd) }

func configureDarwinTUN(t *testing.T, dev *darwinTUN, local, peer string) {
	t.Helper()
	cmds := [][]string{
		{"ifconfig", dev.name, "inet", local, peer, "up"},
		{"ifconfig", dev.name, "mtu", strconv.Itoa(darwinMTU)},
	}
	for _, cmd := range cmds {
		if out, err := exec.Command(cmd[0], cmd[1:]...).CombinedOutput(); err != nil {
			t.Fatalf("%s: %s: %v", cmd[0], out, err)
		}
	}
}

// TestDarwinUTunDevice verifies the real macOS utun device:
//  1. Opens utun via SYSPROTO_CONTROL + CTLIOCGINFO
//  2. Configures the interface with ifconfig
//  3. Sends a ping through the utun device
//  4. Reads the ICMP packet (with AF header stripped)
//  5. Writes a reply back
//
// Requires root. Run via: sudo go test -v -run TestDarwinUTunDevice ./test/
func TestDarwinUTunDevice(t *testing.T) {
	if os.Getenv("PRISM_ROOT_TEST") == "" {
		t.Skip("set PRISM_ROOT_TEST=1 (requires root for utun)")
	}

	dev := openDarwinTUN(t)
	defer dev.Close()
	t.Logf("step 1: opened utun device %q", dev.name)

	configureDarwinTUN(t, dev, "10.99.99.1", "10.99.99.2")
	t.Logf("step 2: configured %s: 10.99.99.1 → 10.99.99.2", dev.name)

	go exec.Command("ping", "-c", "1", "-W", "2", "10.99.99.2").Run()

	buf := make([]byte, darwinMTU)
	deadline := time.After(5 * time.Second)
	var n int
	var err error
	for {
		select {
		case <-deadline:
			t.Fatal("timeout waiting for packet on utun")
		default:
		}
		syscall.SetNonblock(dev.fd, true)
		n, err = dev.Read(buf)
		syscall.SetNonblock(dev.fd, false)
		if n > 0 && buf[0]>>4 == 4 {
			break
		}
		if err != nil && n == 0 {
			time.Sleep(10 * time.Millisecond)
			continue
		}
	}

	srcIP := net.IP(buf[12:16])
	dstIP := net.IP(buf[16:20])
	t.Logf("step 3: read %d-byte IPv4 packet: proto=%d src=%s dst=%s", n, buf[9], srcIP, dstIP)

	if dstIP.String() != "10.99.99.2" {
		t.Fatalf("expected dst 10.99.99.2, got %s", dstIP)
	}

	reply := make([]byte, n)
	copy(reply, buf[:n])
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

	nw, err := dev.Write(reply)
	if err != nil {
		t.Fatalf("write utun: %v", err)
	}
	t.Logf("step 4: wrote %d-byte reply to utun", nw)
	t.Log("macOS utun device verified: open → configure → read raw IP → write reply")
}

// tunRouterDarwin runs the gVisor netstack on a real macOS utun device,
// relaying TCP through a real Prism session.
func tunRouterDarwin(dev *darwinTUN, sess *prism.Session, done chan struct{}) {
	ep := channel.New(512, darwinMTU, "")

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

	go func() {
		buf := make([]byte, darwinMTU)
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

// TestDarwinUTunWithRealPrism is the macOS end-to-end proof: a real utun
// device feeds raw IP packets into the gVisor netstack, which relays TCP
// through a real Prism session to a real Prism echo server.
//
// Run via: sudo PRISM_ROOT_TEST=1 go test -v -run TestDarwinUTunWithRealPrism ./test/
func TestDarwinUTunWithRealPrism(t *testing.T) {
	if os.Getenv("PRISM_ROOT_TEST") == "" {
		t.Skip("set PRISM_ROOT_TEST=1 (requires root for utun)")
	}

	kp, err := prism.GenerateServerKeypair()
	if err != nil {
		t.Fatal(err)
	}
	psk, err := prism.NewPSK()
	if err != nil {
		t.Fatal(err)
	}
	cred := prism.Credential{ID: prism.ClientID{0xDA, 0x4E}, PSK: psk}
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
	t.Logf("step 1: Prism echo server on %s", ln.Addr())

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
	t.Log("step 2: Prism session established (uTLS Chrome + AES-256-GCM)")

	dev := openDarwinTUN(t)
	defer dev.Close()
	configureDarwinTUN(t, dev, "10.0.85.1", "10.0.85.2")
	t.Logf("step 3: real utun device %q up with 10.0.85.1 → 10.0.85.2", dev.name)

	routerDone := make(chan struct{})
	go tunRouterDarwin(dev, sess, routerDone)
	defer close(routerDone)
	t.Log("step 4: gVisor netstack tunRouter running on real utun fd")

	time.Sleep(50 * time.Millisecond)

	conn, err := net.DialTimeout("tcp", "10.0.85.2:8080", 5*time.Second)
	if err != nil {
		t.Fatalf("dial through utun: %v", err)
	}
	defer conn.Close()
	t.Log("step 5: TCP connection established through real utun device")

	payload := bytes.Repeat([]byte("DARWIN-UTUN-PRISM!"), 400)
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

	t.Logf("step 6: %d bytes echoed through real utun → gVisor → real Prism → echo → back", len(payload))
	t.Log("FULL PIPELINE VERIFIED: real macOS utun → kernel routing → gVisor netstack → real Prism session (uTLS + AEAD) → echo")
	fmt.Fprintf(os.Stderr, "\n  Real macOS utun + real Prism end-to-end test passed.\n")
}
