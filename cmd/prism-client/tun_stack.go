package main

import (
	"context"
	"io"
	"log"
	"net"
	"net/netip"
	"sync/atomic"
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
	"github.com/sagernet/gvisor/pkg/waiter"

	"github.com/gloridust/prism/pkg/prism"
)

const channelSize = 512

// tunUDPIdle ends a TUN UDP flow after this long with no traffic either way,
// matching the server's per-association idle timeout.
var tunUDPIdle = 60 * time.Second

// ULA used on the TUN interface so the OS will source IPv6 traffic from it.
// Every IPv6 destination is then routed into the tunnel (::/1 + 8000::/1), so
// no IPv6 packet — e.g. a WebRTC STUN probe — can leave on the physical link.
const (
	tunAddr6   = "fd50:7269:736d::1"
	tunPrefix6 = 64
)

var (
	ipv4CaptureRoutes = []string{"0.0.0.0/1", "128.0.0.0/1"}
	ipv6CaptureRoutes = []string{"::/1", "8000::/1"}
)

type tunDev interface {
	Read([]byte) (int, error)
	Write([]byte) (int, error)
}

type proxyStream interface {
	io.ReadWriteCloser
	CloseWrite() error
}

type proxyDialer interface {
	Open(target string) (proxyStream, error)
	OpenUDP() (proxyStream, error)
}

type realDialerAdapter struct{ d *Dialer }

func (a *realDialerAdapter) Open(target string) (proxyStream, error) { return a.d.Open(target) }
func (a *realDialerAdapter) OpenUDP() (proxyStream, error)           { return a.d.OpenUDP() }

func tunRouter(dev tunDev, dialer proxyDialer) {
	ep := channel.New(channelSize, uint32(tunMTU), "")

	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol},
	})

	const nicID tcpip.NICID = 1
	if err := s.CreateNIC(nicID, ep); err != nil {
		log.Fatalf("tun stack: CreateNIC: %s", err)
	}

	s.SetRouteTable([]tcpip.Route{
		{Destination: header.IPv4EmptySubnet, NIC: nicID},
		{Destination: header.IPv6EmptySubnet, NIC: nicID},
	})
	s.SetPromiscuousMode(nicID, true)
	s.SetSpoofing(nicID, true)

	tcpFwd := tcp.NewForwarder(s, 0, 4096, func(r *tcp.ForwarderRequest) {
		id := r.ID()
		var wq waiter.Queue
		ep, tcpErr := r.CreateEndpoint(&wq)
		if tcpErr != nil {
			r.Complete(true)
			return
		}
		r.Complete(false)
		conn := gonet.NewTCPConn(&wq, ep)
		go relayTCP(conn, dialer, net.JoinHostPort(addrString(id.LocalAddress), itoa(id.LocalPort)))
	})
	s.SetTransportProtocolHandler(tcp.ProtocolNumber, tcpFwd.HandlePacket)

	udpFwd := udp.NewForwarder(s, func(r *udp.ForwarderRequest) bool {
		id := r.ID()
		var wq waiter.Queue
		ep, udpErr := r.CreateEndpoint(&wq)
		if udpErr != nil {
			return false
		}
		conn := gonet.NewUDPConn(&wq, ep)
		go relayUDP(conn, dialer, net.JoinHostPort(addrString(id.LocalAddress), itoa(id.LocalPort)))
		return true
	})
	s.SetTransportProtocolHandler(udp.ProtocolNumber, udpFwd.HandlePacket)

	go func() {
		buf := make([]byte, tunMTU)
		for {
			n, err := dev.Read(buf)
			if err != nil {
				if err != io.EOF {
					log.Printf("tun read: %v", err)
				}
				return
			}
			if n == 0 {
				continue
			}
			var proto tcpip.NetworkProtocolNumber
			switch buf[0] >> 4 {
			case 4:
				proto = header.IPv4ProtocolNumber
			case 6:
				proto = header.IPv6ProtocolNumber
			default:
				continue
			}
			pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
				Payload: buffer.MakeWithData(buf[:n]),
			})
			ep.InjectInbound(proto, pkt)
			pkt.DecRef()
		}
	}()

	ctx := context.Background()
	for {
		pkt := ep.ReadContext(ctx)
		if pkt == nil {
			return
		}
		dev.Write(pkt.ToView().AsSlice())
		pkt.DecRef()
	}
}

func relayTCP(local net.Conn, dialer proxyDialer, target string) {
	defer local.Close()

	st, err := dialer.Open(target)
	if err != nil {
		return
	}
	defer st.Close()

	done := make(chan struct{}, 2)
	go func() {
		io.Copy(st, local)
		st.CloseWrite()
		done <- struct{}{}
	}()
	go func() {
		io.Copy(local, st)
		done <- struct{}{}
	}()
	<-done
	<-done
}

// relayUDP carries one TUN UDP flow over a Prism UDP-relay stream. Each
// datagram is framed with its destination (prism.WriteDatagram), which is what
// the server's UDP egress expects; replies come back framed the same way.
func relayUDP(local net.Conn, dialer proxyDialer, target string) {
	defer local.Close()

	st, err := dialer.OpenUDP()
	if err != nil {
		return
	}
	defer st.Close()

	var last atomic.Int64
	touch := func() { last.Store(time.Now().UnixNano()) }
	touch()

	go func() {
		defer local.Close()
		for {
			_, data, err := prism.ReadDatagram(st)
			if err != nil {
				return
			}
			touch()
			if _, err := local.Write(data); err != nil {
				return
			}
		}
	}()

	buf := make([]byte, 65535)
	for {
		_ = local.SetReadDeadline(time.Now().Add(tunUDPIdle))
		n, err := local.Read(buf)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() &&
				time.Since(time.Unix(0, last.Load())) < tunUDPIdle {
				continue
			}
			return
		}
		touch()
		if err := prism.WriteDatagram(st, target, buf[:n]); err != nil {
			return
		}
	}
}

func addrString(a tcpip.Address) string {
	addr, _ := netip.AddrFromSlice(a.AsSlice())
	return addr.Unmap().String()
}

// hostHasGlobalIPv6 reports whether any physical interface (other than skip)
// holds a globally routable IPv6 address, i.e. whether IPv6 traffic could leave
// the machine outside the tunnel.
func hostHasGlobalIPv6(skip string) bool {
	ifaces, err := net.Interfaces()
	if err != nil {
		return true
	}
	ula := netip.MustParsePrefix("fc00::/7")
	for _, ifc := range ifaces {
		if ifc.Name == skip || ifc.Flags&net.FlagUp == 0 || ifc.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, _ := ifc.Addrs()
		for _, a := range addrs {
			ipn, ok := a.(*net.IPNet)
			if !ok || ipn.IP.To4() != nil || !ipn.IP.IsGlobalUnicast() {
				continue
			}
			if ip, ok := netip.AddrFromSlice(ipn.IP); ok && !ula.Contains(ip) {
				return true
			}
		}
	}
	return false
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
