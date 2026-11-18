package main

import (
	"context"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/gloridust/prism/pkg/prism"
)

// udpIdleTimeout tears down a UDP association after this long with no reply
// traffic from any target, bounding how many idle UDP sockets the egress holds.
const udpIdleTimeout = 60 * time.Second

// maxUDPTargets bounds the per-association resolved-target cache.
const maxUDPTargets = 256

// handleUDP relays a UDP-association stream: each datagram read from the stream
// is sent to its (policy-checked) target over a shared UDP socket, and every
// reply is framed back onto the stream tagged with its source address. The same
// egress address policy as TCP applies (no private/loopback/metadata unless
// allow_private).
func (s *server) handleUDP(st *prism.Stream, m *meter) {
	uconn, err := net.ListenUDP("udp", nil)
	if err != nil {
		return
	}
	defer uconn.Close()

	var mu sync.Mutex
	resolved := make(map[string]*net.UDPAddr) // target hostport -> vetted UDP addr

	// stream -> target UDP
	go func() {
		defer uconn.Close()
		for {
			hostport, data, err := prism.ReadDatagram(st)
			if err != nil {
				return
			}
			mu.Lock()
			ua := resolved[hostport]
			mu.Unlock()
			if ua == nil {
				ua, err = s.resolveUDPTarget(hostport)
				if err != nil {
					continue // blocked or unresolvable target: drop this datagram
				}
				mu.Lock()
				if len(resolved) >= maxUDPTargets {
					clear(resolved) // bound memory; entries are only a cache
				}
				resolved[hostport] = ua
				mu.Unlock()
			}
			if !m.add(int64(len(data)), 0) {
				return
			}
			_ = uconn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			uconn.WriteToUDP(data, ua)
		}
	}()

	// target UDP -> stream (replies), with an idle timeout
	buf := make([]byte, 65535)
	for {
		_ = uconn.SetReadDeadline(time.Now().Add(udpIdleTimeout))
		n, from, err := uconn.ReadFromUDP(buf)
		if err != nil {
			return // timeout or closed -> end the association
		}
		if !m.add(0, int64(n)) {
			return
		}
		if err := prism.WriteDatagram(st, from.String(), buf[:n]); err != nil {
			return
		}
	}
}

// resolveUDPTarget resolves hostport and returns a vetted UDP address, applying
// the egress policy (unless allow_private). Like safeDial, it resolves once and
// returns a concrete IP so no later re-resolution can swap in a private host.
func (s *server) resolveUDPTarget(hostport string) (*net.UDPAddr, error) {
	host, portStr, err := net.SplitHostPort(hostport)
	if err != nil {
		return nil, err
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return nil, err
	}
	if s.allowPrivate {
		ua, err := net.ResolveUDPAddr("udp", hostport)
		return ua, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, err
	}
	for _, ia := range ips {
		if isDisallowedIP(ia.IP) {
			continue
		}
		return &net.UDPAddr{IP: ia.IP, Port: port}, nil
	}
	return nil, errBlockedTarget
}
