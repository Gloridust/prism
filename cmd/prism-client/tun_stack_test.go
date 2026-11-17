package main

import (
	"context"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/gvisor/pkg/buffer"
	"github.com/sagernet/gvisor/pkg/tcpip"
	"github.com/sagernet/gvisor/pkg/tcpip/adapters/gonet"
	"github.com/sagernet/gvisor/pkg/tcpip/header"
	"github.com/sagernet/gvisor/pkg/tcpip/link/channel"
	"github.com/sagernet/gvisor/pkg/tcpip/network/ipv4"
	"github.com/sagernet/gvisor/pkg/tcpip/stack"
	"github.com/sagernet/gvisor/pkg/tcpip/transport/tcp"
	"github.com/sagernet/gvisor/pkg/tcpip/transport/udp"
)

// pipeTUN bridges two gVisor channel endpoints via an in-memory pipe, acting
// as a mock TUN device. Packets written by the router stack appear on
// Read(); packets written by Write() are injected into the router stack.
type pipeTUN struct {
	// rx: router stack writes here → client stack reads
	// tx: client stack writes here → router stack reads
	rx     chan []byte
	tx     chan []byte
	closed chan struct{}
	once   sync.Once
}

func newPipeTUN() *pipeTUN {
	return &pipeTUN{
		rx:     make(chan []byte, 256),
		tx:     make(chan []byte, 256),
		closed: make(chan struct{}),
	}
}

// Read is called by the tunRouter goroutine to get packets destined for the
// router's gVisor stack. The client stack pumps these in via pumpToRouter.
func (p *pipeTUN) Read(buf []byte) (int, error) {
	select {
	case pkt := <-p.tx:
		return copy(buf, pkt), nil
	case <-p.closed:
		return 0, io.EOF
	}
}

// Write is called by the tunRouter goroutine when the router stack emits a
// packet (e.g. SYN-ACK). The client stack reads these via pumpFromRouter.
func (p *pipeTUN) Write(buf []byte) (int, error) {
	select {
	case <-p.closed:
		return 0, io.EOF
	default:
	}
	cpy := make([]byte, len(buf))
	copy(cpy, buf)
	select {
	case p.rx <- cpy:
	case <-p.closed:
		return 0, io.EOF
	}
	return len(buf), nil
}

func (p *pipeTUN) Close() { p.once.Do(func() { close(p.closed) }) }

// mockStream wraps a net.Conn to satisfy proxyStream.
type mockStream struct{ net.Conn }

func (ms *mockStream) CloseWrite() error {
	if tc, ok := ms.Conn.(*net.TCPConn); ok {
		return tc.CloseWrite()
	}
	return ms.Close()
}

// mockDialer records dialed targets and connects to a local echo server.
type mockDialer struct {
	echoAddr string
	mu       sync.Mutex
	targets  []string
}

func (md *mockDialer) Open(target string) (proxyStream, error) {
	md.mu.Lock()
	md.targets = append(md.targets, target)
	md.mu.Unlock()

	conn, err := net.DialTimeout("tcp", md.echoAddr, 2*time.Second)
	if err != nil {
		return nil, err
	}
	return &mockStream{Conn: conn}, nil
}

func (md *mockDialer) OpenUDP() (proxyStream, error) {
	conn, err := net.DialTimeout("tcp", md.echoAddr, 2*time.Second)
	if err != nil {
		return nil, err
	}
	return &mockStream{Conn: conn}, nil
}

func (md *mockDialer) getTargets() []string {
	md.mu.Lock()
	defer md.mu.Unlock()
	out := make([]string, len(md.targets))
	copy(out, md.targets)
	return out
}

// startEchoServer starts a TCP server that echoes back everything it receives.
func startEchoServer(t *testing.T) (addr string, stop func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				io.Copy(c, c)
			}()
		}
	}()

	return ln.Addr().String(), func() {
		ln.Close()
		<-done
	}
}

// makeClientStack creates a gVisor userspace TCP/IP stack that acts as the
// "application" side — it generates real TCP packets that flow through the
// pipeTUN into the router's stack. Two pump goroutines bridge the client
// stack's channel endpoint to the pipeTUN.
func makeClientStack(t *testing.T, tun *pipeTUN) *stack.Stack {
	t.Helper()

	ep := channel.New(256, tunMTU, "")

	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol},
	})

	const nicID tcpip.NICID = 1
	if err := s.CreateNIC(nicID, ep); err != nil {
		t.Fatalf("client stack: CreateNIC: %s", err)
	}

	clientAddr := tcpip.AddrFrom4([4]byte{10, 0, 85, 2})
	protoAddr := tcpip.ProtocolAddress{
		Protocol:          ipv4.ProtocolNumber,
		AddressWithPrefix: tcpip.AddressWithPrefix{Address: clientAddr, PrefixLen: 24},
	}
	if err := s.AddProtocolAddress(nicID, protoAddr, stack.AddressProperties{}); err != nil {
		t.Fatalf("client stack: AddProtocolAddress: %s", err)
	}

	s.SetRouteTable([]tcpip.Route{{
		Destination: header.IPv4EmptySubnet,
		NIC:         nicID,
	}})

	// Pump: client stack → pipeTUN (router reads these).
	go func() {
		ctx := context.Background()
		for {
			pkt := ep.ReadContext(ctx)
			if pkt == nil {
				return
			}
			data := pkt.ToView().AsSlice()
			cpy := make([]byte, len(data))
			copy(cpy, data)
			pkt.DecRef()

			select {
			case tun.tx <- cpy:
			case <-tun.closed:
				return
			}
		}
	}()

	// Pump: pipeTUN → client stack (router sends these).
	go func() {
		buf := make([]byte, tunMTU)
		for {
			var n int
			select {
			case pkt := <-tun.rx:
				n = copy(buf, pkt)
			case <-tun.closed:
				return
			}
			if n == 0 {
				continue
			}
			pb := stack.NewPacketBuffer(stack.PacketBufferOptions{
				Payload: buffer.MakeWithData(buf[:n]),
			})
			ep.InjectInbound(header.IPv4ProtocolNumber, pb)
			pb.DecRef()
		}
	}()

	return s
}

// TestTunRouterTCPRelay is the end-to-end proof that the gVisor-based TUN
// router works: a client stack generates TCP traffic through a mock TUN, the
// tunRouter processes the raw IP packets, calls dialer.Open, and data flows
// through to a real echo server and back.
func TestTunRouterTCPRelay(t *testing.T) {
	echoAddr, stopEcho := startEchoServer(t)
	defer stopEcho()

	tun := newPipeTUN()
	dialer := &mockDialer{echoAddr: echoAddr}

	go tunRouter(tun, dialer)
	defer tun.Close()

	clientStack := makeClientStack(t, tun)
	defer clientStack.Close()

	// Connect from the client stack to an arbitrary destination IP:port.
	// The router's stack is in promiscuous mode, so it accepts any destination.
	dstAddr := tcpip.FullAddress{
		Addr: tcpip.AddrFrom4([4]byte{93, 184, 216, 34}),
		Port: 80,
	}
	conn, err := gonet.DialTCPWithBind(
		context.Background(),
		clientStack,
		tcpip.FullAddress{Addr: tcpip.AddrFrom4([4]byte{10, 0, 85, 2}), Port: 0},
		dstAddr,
		ipv4.ProtocolNumber,
	)
	if err != nil {
		t.Fatalf("client DialTCP: %v", err)
	}
	defer conn.Close()

	// Verify dialer.Open was called with the correct target.
	deadline := time.After(5 * time.Second)
	for {
		targets := dialer.getTargets()
		if len(targets) > 0 {
			expected := "93.184.216.34:80"
			if targets[0] != expected {
				t.Fatalf("dialer target = %q, want %q", targets[0], expected)
			}
			break
		}
		select {
		case <-deadline:
			t.Fatal("timeout waiting for dialer.Open to be called")
		case <-time.After(50 * time.Millisecond):
		}
	}

	// Send data through the tunnel and verify the echo server echoes it back.
	payload := []byte("Hello from TUN netstack!")
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("write: %v", err)
	}

	buf := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read echo: %v", err)
	}

	if string(buf) != string(payload) {
		t.Fatalf("echo mismatch: got %q, want %q", buf, payload)
	}

	t.Log("TUN netstack end-to-end TCP relay verified: client → TUN → gVisor → dialer → echo server → back")
}

// TestTunRouterAddrHelpers tests the address conversion helpers.
func TestTunRouterAddrHelpers(t *testing.T) {
	tests := []struct {
		n    uint16
		want string
	}{
		{0, "0"},
		{1, "1"},
		{80, "80"},
		{443, "443"},
		{8080, "8080"},
		{65535, "65535"},
	}
	for _, tt := range tests {
		if got := itoa(tt.n); got != tt.want {
			t.Errorf("itoa(%d) = %q, want %q", tt.n, got, tt.want)
		}
	}
}
