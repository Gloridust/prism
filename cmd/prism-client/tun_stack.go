package main

import (
	"context"
	"io"
	"log"
	"net"
	"net/netip"

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
)

const channelSize = 512

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
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol},
	})

	const nicID tcpip.NICID = 1
	if err := s.CreateNIC(nicID, ep); err != nil {
		log.Fatalf("tun stack: CreateNIC: %s", err)
	}

	// Route all traffic through our NIC.
	s.SetRouteTable([]tcpip.Route{{
		Destination: header.IPv4EmptySubnet,
		NIC:         nicID,
	}})
	s.SetPromiscuousMode(nicID, true)
	s.SetSpoofing(nicID, true)

	// TCP forwarder: for each inbound connection, open a Prism stream and relay.
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

		target := net.JoinHostPort(
			addrFrom4(id.LocalAddress),
			itoa(id.LocalPort),
		)
		go relayTCP(conn, dialer, target)
	})
	s.SetTransportProtocolHandler(tcp.ProtocolNumber, tcpFwd.HandlePacket)

	// UDP forwarder: for each inbound datagram, relay through Prism's UDP channel.
	udpFwd := udp.NewForwarder(s, func(r *udp.ForwarderRequest) bool {
		id := r.ID()
		var wq waiter.Queue
		ep, udpErr := r.CreateEndpoint(&wq)
		if udpErr != nil {
			return false
		}
		conn := gonet.NewUDPConn(&wq, ep)

		target := net.JoinHostPort(
			addrFrom4(id.LocalAddress),
			itoa(id.LocalPort),
		)
		go relayUDP(conn, dialer, target)
		return true
	})
	s.SetTransportProtocolHandler(udp.ProtocolNumber, udpFwd.HandlePacket)

	// Read goroutine: TUN device → netstack.
	go func() {
		buf := make([]byte, tunMTU)
		for {
			n, err := dev.Read(buf)
			if err != nil {
				if err == io.EOF {
					return
				}
				log.Printf("tun read: %v", err)
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

	// Write loop: netstack → TUN device.
	ctx := context.Background()
	for {
		pkt := ep.ReadContext(ctx)
		if pkt == nil {
			return
		}
		pktData := pkt.ToView().AsSlice()
		dev.Write(pktData)
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

func relayUDP(local net.Conn, dialer proxyDialer, target string) {
	defer local.Close()

	st, err := dialer.OpenUDP()
	if err != nil {
		return
	}
	defer st.Close()

	done := make(chan struct{}, 2)
	go func() {
		io.Copy(st, local)
		done <- struct{}{}
	}()
	go func() {
		io.Copy(local, st)
		done <- struct{}{}
	}()
	<-done
}

func addrFrom4(a tcpip.Address) string {
	addr, _ := netip.AddrFromSlice(a.AsSlice())
	return addr.String()
}

func itoa(n uint16) string {
	// Avoid importing strconv for a trivial conversion.
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
