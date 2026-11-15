package main

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"

	"github.com/gloridust/prism/pkg/prism"
)

// serveSOCKS runs a minimal SOCKS5 server (no-auth) supporting CONNECT (TCP)
// and UDP ASSOCIATE (UDP). This is the inbound Nikki/Mihomo routes into on the
// router, and also serves desktop apps set to use a SOCKS proxy. UDP ASSOCIATE
// is what lets QUIC/DNS/real-time media go through the egress instead of being
// dropped.
func serveSOCKS(ln net.Listener, d *Dialer) {
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		go handleSOCKS(c, d)
	}
}

func handleSOCKS(c net.Conn, d *Dialer) {
	defer c.Close()
	if err := socksNegotiate(c); err != nil {
		return
	}
	cmd, host, port, err := socksReadRequest(c)
	if err != nil {
		return
	}
	switch cmd {
	case 0x01: // CONNECT
		handleConnect(c, d, net.JoinHostPort(host, strconv.Itoa(int(port))))
	case 0x03: // UDP ASSOCIATE
		handleUDPAssociate(c, d)
	default:
		c.Write([]byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0}) // command not supported
	}
}

// socksNegotiate performs the method-selection step (no auth).
func socksNegotiate(c net.Conn) error {
	buf := make([]byte, 262)
	if _, err := io.ReadFull(c, buf[:2]); err != nil {
		return err
	}
	if buf[0] != 0x05 {
		return fmt.Errorf("not socks5")
	}
	n := int(buf[1])
	if _, err := io.ReadFull(c, buf[:n]); err != nil {
		return err
	}
	_, err := c.Write([]byte{0x05, 0x00})
	return err
}

// socksReadRequest reads the request header and returns cmd + target address.
func socksReadRequest(c net.Conn) (cmd byte, host string, port uint16, err error) {
	buf := make([]byte, 262)
	if _, err = io.ReadFull(c, buf[:4]); err != nil {
		return
	}
	cmd = buf[1]
	switch buf[3] {
	case 0x01:
		if _, err = io.ReadFull(c, buf[:4]); err != nil {
			return
		}
		host = net.IP(buf[:4]).String()
	case 0x04:
		if _, err = io.ReadFull(c, buf[:16]); err != nil {
			return
		}
		host = net.IP(buf[:16]).String()
	case 0x03:
		if _, err = io.ReadFull(c, buf[:1]); err != nil {
			return
		}
		l := int(buf[0])
		if _, err = io.ReadFull(c, buf[:l]); err != nil {
			return
		}
		host = string(buf[:l])
	default:
		err = fmt.Errorf("bad atyp")
		return
	}
	if _, err = io.ReadFull(c, buf[:2]); err != nil {
		return
	}
	port = binary.BigEndian.Uint16(buf[:2])
	return
}

// handleConnect tunnels a CONNECT request to the egress via a TCP stream.
func handleConnect(c net.Conn, d *Dialer, target string) {
	st, err := d.Open(target)
	if err != nil {
		c.Write([]byte{0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0}) // connection refused
		return
	}
	defer st.Close()
	c.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}) // success, BND 0.0.0.0:0
	relayConn(c, st)
}

// handleUDPAssociate binds a local UDP relay socket, tells the client to send
// its datagrams there, and bridges them to the egress over a UDP-relay stream.
// The TCP control connection stays open for the association's lifetime; when it
// closes, the association is torn down.
func handleUDPAssociate(c net.Conn, d *Dialer) {
	uconn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		c.Write([]byte{0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	defer uconn.Close()

	bnd := uconn.LocalAddr().(*net.UDPAddr)
	reply := []byte{0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 0}
	binary.BigEndian.PutUint16(reply[8:], uint16(bnd.Port))
	if _, err := c.Write(reply); err != nil {
		return
	}

	st, err := d.OpenUDP()
	if err != nil {
		return
	}
	defer st.Close()

	var mu sync.Mutex
	var clientAddr *net.UDPAddr // learned from the first datagram the app sends

	// app UDP -> egress stream
	go func() {
		defer st.Close()
		defer c.Close()
		buf := make([]byte, 65535)
		for {
			n, src, err := uconn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			mu.Lock()
			clientAddr = src
			mu.Unlock()
			// SOCKS5 UDP request: [RSV(2)][FRAG(1)][addr][data]
			if n < 3 || buf[2] != 0 { // drop fragmented datagrams (FRAG != 0)
				continue
			}
			hostport, data, err := prism.SplitAddr(buf[3:n])
			if err != nil {
				continue
			}
			if err := prism.WriteDatagram(st, hostport, data); err != nil {
				return
			}
		}
	}()

	// egress stream -> app UDP
	go func() {
		defer uconn.Close()
		defer c.Close()
		for {
			hostport, data, err := prism.ReadDatagram(st)
			if err != nil {
				return
			}
			mu.Lock()
			dst := clientAddr
			mu.Unlock()
			if dst == nil {
				continue
			}
			addr, err := prism.EncodeAddr(hostport)
			if err != nil {
				continue
			}
			pkt := make([]byte, 3+len(addr)+len(data))
			copy(pkt[3+len(addr):], data)
			copy(pkt[3:], addr)
			uconn.WriteToUDP(pkt, dst)
		}
	}()

	// Hold the association open until the client closes the TCP control conn.
	io.Copy(io.Discard, c)
}

// relayConn bridges a local client connection and a Prism stream, propagating
// half-close so uploads/downloads finish cleanly.
func relayConn(local net.Conn, st *prism.Stream) {
	done := make(chan struct{}, 2)
	go func() {
		io.Copy(st, local)
		st.CloseWrite()
		done <- struct{}{}
	}()
	go func() {
		io.Copy(local, st)
		if tc, ok := local.(*net.TCPConn); ok {
			tc.CloseWrite()
		}
		done <- struct{}{}
	}()
	<-done
	<-done
}
