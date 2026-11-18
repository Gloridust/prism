package main

import (
	"log"
	"net"
	"sync"
	"time"

	"github.com/gloridust/prism/pkg/prism"
)

// dnsProxy intercepts local DNS queries and forwards them through the Prism
// tunnel, preventing DNS leaks when applications resolve names directly instead
// of going through SOCKS5. It listens on a local UDP address (typically
// 127.0.0.1:53) and relays each query as a raw DNS packet over a Prism UDP
// stream to the configured upstream DNS server on the exit node.
type dnsProxy struct {
	dialer   *Dialer
	upstream string // "1.1.1.1:53" etc.
	conn     *net.UDPConn
	tcp      net.Listener // DNS-over-TCP (truncated answers, large records)

	mu      sync.Mutex
	stopped bool
}

func newDNSProxy(d *Dialer, listen, upstream string) (*dnsProxy, error) {
	addr, err := net.ResolveUDPAddr("udp", listen)
	if err != nil {
		return nil, err
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return nil, err
	}
	if upstream == "" {
		upstream = "1.1.1.1:53"
	}
	// Resolvers retry over TCP when a UDP answer is truncated; without this
	// listener those lookups would fail (or fall back to a leaking resolver).
	tcp, err := net.Listen("tcp", conn.LocalAddr().String())
	if err != nil {
		conn.Close()
		return nil, err
	}
	return &dnsProxy{dialer: d, upstream: upstream, conn: conn, tcp: tcp}, nil
}

func (dp *dnsProxy) serveTCP() {
	for {
		c, err := dp.tcp.Accept()
		if err != nil {
			return
		}
		go func() {
			defer c.Close()
			st, err := dp.dialer.Open(dp.upstream)
			if err != nil {
				return
			}
			defer st.Close()
			c.SetDeadline(time.Now().Add(30 * time.Second))
			relayConn(c, st)
		}()
	}
}

func (dp *dnsProxy) Addr() net.Addr { return dp.conn.LocalAddr() }

func (dp *dnsProxy) Serve() {
	go dp.serveTCP()
	buf := make([]byte, 4096)
	for {
		n, clientAddr, err := dp.conn.ReadFromUDP(buf)
		if err != nil {
			dp.mu.Lock()
			stopped := dp.stopped
			dp.mu.Unlock()
			if stopped {
				return
			}
			continue
		}
		if n < 12 { // too short for a DNS header
			continue
		}
		query := make([]byte, n)
		copy(query, buf[:n])
		go dp.resolve(query, clientAddr)
	}
}

func (dp *dnsProxy) resolve(query []byte, clientAddr *net.UDPAddr) {
	st, err := dp.dialer.OpenUDP()
	if err != nil {
		log.Printf("dns proxy: open UDP stream: %v", err)
		return
	}
	defer st.Close()

	if err := prism.WriteDatagram(st, dp.upstream, query); err != nil {
		return
	}

	type result struct {
		data []byte
		err  error
	}
	ch := make(chan result, 1)
	go func() {
		_, reply, err := prism.ReadDatagram(st)
		ch <- result{reply, err}
	}()

	select {
	case r := <-ch:
		if r.err != nil {
			return
		}
		dp.conn.WriteToUDP(r.data, clientAddr)
	case <-time.After(5 * time.Second):
		return
	}
}

func (dp *dnsProxy) Close() error {
	dp.mu.Lock()
	dp.stopped = true
	dp.mu.Unlock()
	dp.tcp.Close()
	return dp.conn.Close()
}
