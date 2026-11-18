package main

import (
	"bytes"
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
	"github.com/sagernet/gvisor/pkg/tcpip/network/ipv6"
	"github.com/sagernet/gvisor/pkg/tcpip/stack"
	"github.com/sagernet/gvisor/pkg/tcpip/transport/tcp"
	"github.com/sagernet/gvisor/pkg/tcpip/transport/udp"

	"github.com/gloridust/prism/pkg/prism"
)

var (
	clientAddr4 = tcpip.AddrFrom4([4]byte{10, 0, 85, 2})
	clientAddr6 = tcpip.AddrFrom16([16]byte{0xfd, 0x50, 0x72, 0x69, 0x73, 0x6d, 15: 2})
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
	echoAddr   string
	mu         sync.Mutex
	targets    []string
	udpTargets []string
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

// OpenUDP behaves like the server's UDP egress: it parses framed datagrams
// (rejecting anything unframed) and echoes each back framed with its address.
func (md *mockDialer) OpenUDP() (proxyStream, error) {
	cli, srv := net.Pipe()
	go func() {
		defer srv.Close()
		for {
			addr, data, err := prism.ReadDatagram(srv)
			if err != nil {
				return
			}
			md.mu.Lock()
			md.udpTargets = append(md.udpTargets, addr)
			md.mu.Unlock()
			if err := prism.WriteDatagram(srv, addr, data); err != nil {
				return
			}
		}
	}()
	return &mockStream{Conn: cli}, nil
}

func (md *mockDialer) getTargets() []string {
	md.mu.Lock()
	defer md.mu.Unlock()
	out := make([]string, len(md.targets))
	copy(out, md.targets)
	return out
}

func (md *mockDialer) getUDPTargets() []string {
	md.mu.Lock()
	defer md.mu.Unlock()
	return append([]string(nil), md.udpTargets...)
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
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol},
	})

	const nicID tcpip.NICID = 1
	if err := s.CreateNIC(nicID, ep); err != nil {
		t.Fatalf("client stack: CreateNIC: %s", err)
	}

	for _, pa := range []tcpip.ProtocolAddress{
		{Protocol: ipv4.ProtocolNumber, AddressWithPrefix: tcpip.AddressWithPrefix{Address: clientAddr4, PrefixLen: 24}},
		{Protocol: ipv6.ProtocolNumber, AddressWithPrefix: tcpip.AddressWithPrefix{Address: clientAddr6, PrefixLen: 64}},
	} {
		if err := s.AddProtocolAddress(nicID, pa, stack.AddressProperties{}); err != nil {
			t.Fatalf("client stack: AddProtocolAddress: %s", err)
		}
	}

	s.SetRouteTable([]tcpip.Route{
		{Destination: header.IPv4EmptySubnet, NIC: nicID},
		{Destination: header.IPv6EmptySubnet, NIC: nicID},
	})

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
			proto := header.IPv4ProtocolNumber
			if buf[0]>>4 == 6 {
				proto = header.IPv6ProtocolNumber
			}
			pb := stack.NewPacketBuffer(stack.PacketBufferOptions{
				Payload: buffer.MakeWithData(buf[:n]),
			})
			ep.InjectInbound(proto, pb)
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

func waitForTarget(t *testing.T, get func() []string, want string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		for _, got := range get() {
			if got == want {
				return
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("target %q never reached the dialer; saw %v", want, get())
}

func udpRoundTrip(t *testing.T, s *stack.Stack, local, remote tcpip.FullAddress, proto tcpip.NetworkProtocolNumber, payload []byte) {
	t.Helper()
	conn, err := gonet.DialUDP(s, &local, &remote, proto)
	if err != nil {
		t.Fatalf("DialUDP: %v", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("udp write: %v", err)
	}
	buf := make([]byte, 2048)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("udp read (datagram did not come back through the tunnel): %v", err)
	}
	if !bytes.Equal(buf[:n], payload) {
		t.Fatalf("udp echo mismatch: got %x want %x", buf[:n], payload)
	}
}

// stunBindingRequest is a minimal RFC 5389 Binding Request, the packet a
// browser sends to discover its public (server-reflexive) WebRTC candidate.
func stunBindingRequest() []byte {
	b := []byte{0x00, 0x01, 0x00, 0x00, 0x21, 0x12, 0xa4, 0x42}
	return append(b, bytes.Repeat([]byte{0x5a}, 12)...)
}

// TestTunRouterUDPFramedSTUN proves a STUN probe entering the TUN leaves as a
// properly framed Prism datagram addressed to the STUN server, and the reply
// makes it back — i.e. WebRTC reflexive discovery happens via the exit node.
func TestTunRouterUDPFramedSTUN(t *testing.T) {
	tun := newPipeTUN()
	dialer := &mockDialer{}
	go tunRouter(tun, dialer)
	defer tun.Close()
	cs := makeClientStack(t, tun)
	defer cs.Close()

	udpRoundTrip(t, cs,
		tcpip.FullAddress{Addr: clientAddr4},
		tcpip.FullAddress{Addr: tcpip.AddrFrom4([4]byte{74, 125, 250, 129}), Port: 19302},
		ipv4.ProtocolNumber, stunBindingRequest())
	waitForTarget(t, dialer.getUDPTargets, "74.125.250.129:19302")
}

// TestTunRouterIPv6 proves IPv6 TCP and UDP are carried through the tunnel
// rather than dropped or left to bypass it.
func TestTunRouterIPv6(t *testing.T) {
	echoAddr, stopEcho := startEchoServer(t)
	defer stopEcho()

	tun := newPipeTUN()
	dialer := &mockDialer{echoAddr: echoAddr}
	go tunRouter(tun, dialer)
	defer tun.Close()
	cs := makeClientStack(t, tun)
	defer cs.Close()

	dst6 := tcpip.AddrFrom16([16]byte{0x20, 0x01, 0x0d, 0xb8, 15: 0x07})

	t.Run("tcp", func(t *testing.T) {
		conn, err := gonet.DialTCPWithBind(context.Background(), cs,
			tcpip.FullAddress{Addr: clientAddr6},
			tcpip.FullAddress{Addr: dst6, Port: 443}, ipv6.ProtocolNumber)
		if err != nil {
			t.Fatalf("DialTCP v6: %v", err)
		}
		defer conn.Close()
		waitForTarget(t, dialer.getTargets, "[2001:db8::7]:443")
		conn.SetDeadline(time.Now().Add(5 * time.Second))
		msg := []byte("ipv6 through prism")
		conn.Write(msg)
		got := make([]byte, len(msg))
		if _, err := io.ReadFull(conn, got); err != nil || !bytes.Equal(got, msg) {
			t.Fatalf("v6 tcp echo: %q %v", got, err)
		}
	})

	t.Run("udp-stun", func(t *testing.T) {
		udpRoundTrip(t, cs,
			tcpip.FullAddress{Addr: clientAddr6},
			tcpip.FullAddress{Addr: dst6, Port: 3478},
			ipv6.ProtocolNumber, stunBindingRequest())
		waitForTarget(t, dialer.getUDPTargets, "[2001:db8::7]:3478")
	})
}

func TestTunRouterUDPIdleTimeout(t *testing.T) {
	old := tunUDPIdle
	tunUDPIdle = 200 * time.Millisecond
	defer func() { tunUDPIdle = old }()

	local, peer := net.Pipe()
	defer peer.Close()
	done := make(chan struct{})
	go func() { relayUDP(local, &mockDialer{}, "192.0.2.1:53"); close(done) }()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("idle UDP flow was never torn down")
	}
}
