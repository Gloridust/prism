package e2e

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/tls"
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
	"github.com/sagernet/gvisor/pkg/waiter"

	utls "github.com/refraction-networking/utls"

	"github.com/gloridust/prism/pkg/prism"
)

// pipeTUN bridges two gVisor stacks via in-memory channels, simulating a TUN
// device without needing root or a real network interface.
type pipeTUN struct {
	tx     chan []byte // client → router
	rx     chan []byte // router → client
	closed chan struct{}
	once   sync.Once
}

func newPipeTUN() *pipeTUN {
	return &pipeTUN{
		tx:     make(chan []byte, 256),
		rx:     make(chan []byte, 256),
		closed: make(chan struct{}),
	}
}

func (p *pipeTUN) Read(buf []byte) (int, error) {
	select {
	case pkt := <-p.tx:
		return copy(buf, pkt), nil
	case <-p.closed:
		return 0, io.EOF
	}
}

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

const tunMTU = 1500

// prismDialer wraps a real Prism session to satisfy the router's proxyDialer
// interface (Open returns a proxyStream, OpenUDP returns a proxyStream).
type prismDialer struct {
	sess *prism.Session
}

type prismStreamWrap struct {
	*prism.Stream
}

func (d *prismDialer) open(target string) (*prism.Stream, error) {
	return d.sess.OpenStream(target)
}

// tunRouterWithPrism recreates the core logic of tunRouter from tun_stack.go
// but with a real Prism session as the dialer. This is the same code path the
// production binary uses, just with an in-memory TUN.
func tunRouterWithPrism(tun *pipeTUN, sess *prism.Session) {
	ep := channel.New(512, tunMTU, "")

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
			done := make(chan struct{}, 2)
			go func() { io.Copy(st, conn); st.CloseWrite(); done <- struct{}{} }()
			go func() { io.Copy(conn, st); done <- struct{}{} }()
			<-done
			<-done
		}()
	})
	s.SetTransportProtocolHandler(tcp.ProtocolNumber, tcpFwd.HandlePacket)

	go func() {
		buf := make([]byte, tunMTU)
		for {
			n, err := tun.Read(buf)
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
	for {
		pkt := ep.ReadContext(ctx)
		if pkt == nil {
			return
		}
		data := pkt.ToView().AsSlice()
		tun.Write(data)
		pkt.DecRef()
	}
}

func itoa(n uint16) string {
	if n == 0 {
		return "0"
	}
	buf := [5]byte{}
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}

// makeClientStack creates a gVisor stack that generates real TCP packets,
// pumped through the pipeTUN to the router stack.
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
	s.SetRouteTable([]tcpip.Route{{Destination: header.IPv4EmptySubnet, NIC: nicID}})

	// Pump: client stack → pipeTUN → router
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

	// Pump: router → pipeTUN → client stack
	go func() {
		for {
			select {
			case pkt := <-tun.rx:
				pb := stack.NewPacketBuffer(stack.PacketBufferOptions{
					Payload: buffer.MakeWithData(pkt),
				})
				ep.InjectInbound(header.IPv4ProtocolNumber, pb)
				pb.DecRef()
			case <-tun.closed:
				return
			}
		}
	}()

	return s
}

// connectPrismSession establishes a real uTLS + Prism handshake to a local
// Prism server and returns a Session.
func connectPrismSession(t *testing.T, addr string, pubKey *ecdh.PublicKey, cred prism.Credential) *prism.Session {
	t.Helper()
	raw, err := net.DialTimeout("tcp", addr, 5*time.Second)
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
	keys, err := prism.ClientHandshake(uconn, pubKey, cred, prism.NewAEAD)
	if err != nil {
		t.Fatalf("prism handshake: %v", err)
	}
	_ = uconn.SetDeadline(time.Time{})
	sess, err := prism.NewSession(uconn, keys, true)
	if err != nil {
		t.Fatal(err)
	}
	return sess
}

// TestTunNetstackWithRealPrism proves the full pipeline: a client gVisor stack
// generates real TCP packets → pipeTUN → router gVisor stack → real Prism
// session → real Prism server (echo) → data comes back all the way.
func TestTunNetstackWithRealPrism(t *testing.T) {
	kp, err := prism.GenerateServerKeypair()
	if err != nil {
		t.Fatal(err)
	}
	psk, err := prism.NewPSK()
	if err != nil {
		t.Fatal(err)
	}
	cred := prism.Credential{ID: prism.ClientID{0xAA, 0xBB, 0xCC, 0xDD}, PSK: psk}
	serverAEADs, _ := prism.AEADFactoriesByName([]string{prism.CipherAES256GCM})

	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{selfSignedCert(t)},
		MinVersion:   tls.VersionTLS12,
		NextProtos:   []string{"http/1.1"},
	}

	// Start a real Prism echo server.
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

	// Establish a real Prism session.
	sess := connectPrismSession(t, ln.Addr().String(), kp.Public, cred)
	defer sess.Close()

	// Wire up the TUN pipeline with the real Prism session.
	tun := newPipeTUN()
	defer tun.Close()
	go tunRouterWithPrism(tun, sess)

	// Create a client-side gVisor stack that generates real TCP traffic.
	clientStack := makeClientStack(t, tun)
	defer clientStack.Close()

	// Connect through the TUN to an arbitrary destination. The router stack
	// is in promiscuous mode, so it accepts any IP. The forwarder opens a
	// Prism stream to that target, which the echo server echoes back.
	dstAddr := tcpip.FullAddress{
		Addr: tcpip.AddrFrom4([4]byte{93, 184, 216, 34}),
		Port: 443,
	}
	conn, err := gonet.DialTCPWithBind(
		context.Background(),
		clientStack,
		tcpip.FullAddress{Addr: tcpip.AddrFrom4([4]byte{10, 0, 85, 2}), Port: 0},
		dstAddr,
		ipv4.ProtocolNumber,
	)
	if err != nil {
		t.Fatalf("DialTCP through TUN: %v", err)
	}
	defer conn.Close()

	// Send a payload through the full pipeline and verify echo.
	payload := bytes.Repeat([]byte("TUN-PRISM-"), 1000) // 10 KB
	conn.SetDeadline(time.Now().Add(10 * time.Second))

	go func() {
		conn.Write(payload)
		conn.CloseWrite()
	}()

	got, err := io.ReadAll(conn)
	if err != nil {
		t.Fatalf("read echo through TUN+Prism: %v", err)
	}

	if !bytes.Equal(got, payload) {
		t.Fatalf("TUN+Prism echo mismatch: got %d bytes, want %d", len(got), len(payload))
	}

	t.Logf("TUN+Prism e2e verified: 10 KB payload echoed through client gVisor → TUN → router gVisor → real Prism server → back")
}
