package main

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"

	"github.com/gloridust/prism/pkg/prism"
)

// serveSOCKS runs a minimal SOCKS5 server (no-auth, CONNECT) that tunnels each
// accepted connection to Singapore via the Dialer. This is the inbound Nikki /
// Mihomo routes into on the router, and also serves desktop apps set to use a
// SOCKS proxy.
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
	target, err := socksHandshake(c)
	if err != nil {
		return
	}
	st, err := d.Open(target)
	if err != nil {
		// 0x05 = connection refused (closest generic failure).
		c.Write([]byte{0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	defer st.Close()
	// success reply, BND.ADDR 0.0.0.0:0
	c.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
	relayConn(c, st)
}

func socksHandshake(c net.Conn) (string, error) {
	buf := make([]byte, 262)
	// greeting: VER NMETHODS METHODS...
	if _, err := io.ReadFull(c, buf[:2]); err != nil {
		return "", err
	}
	if buf[0] != 0x05 {
		return "", fmt.Errorf("not socks5")
	}
	n := int(buf[1])
	if _, err := io.ReadFull(c, buf[:n]); err != nil {
		return "", err
	}
	// select no-auth
	if _, err := c.Write([]byte{0x05, 0x00}); err != nil {
		return "", err
	}
	// request: VER CMD RSV ATYP
	if _, err := io.ReadFull(c, buf[:4]); err != nil {
		return "", err
	}
	if buf[1] != 0x01 { // CONNECT only
		c.Write([]byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return "", fmt.Errorf("unsupported command %d", buf[1])
	}
	atyp := buf[3]
	var host string
	switch atyp {
	case 0x01: // IPv4
		if _, err := io.ReadFull(c, buf[:4]); err != nil {
			return "", err
		}
		host = net.IP(buf[:4]).String()
	case 0x04: // IPv6
		if _, err := io.ReadFull(c, buf[:16]); err != nil {
			return "", err
		}
		host = net.IP(buf[:16]).String()
	case 0x03: // domain
		if _, err := io.ReadFull(c, buf[:1]); err != nil {
			return "", err
		}
		l := int(buf[0])
		if _, err := io.ReadFull(c, buf[:l]); err != nil {
			return "", err
		}
		host = string(buf[:l])
	default:
		return "", fmt.Errorf("bad atyp")
	}
	if _, err := io.ReadFull(c, buf[:2]); err != nil {
		return "", err
	}
	port := binary.BigEndian.Uint16(buf[:2])
	return net.JoinHostPort(host, strconv.Itoa(int(port))), nil
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
