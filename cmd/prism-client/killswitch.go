package main

import (
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"os"
	"sort"
	"strings"
)

// Kill switch (TUN mode): firewall rules that reject every outbound packet
// that is not going through the tunnel. They live in the OS firewall, not in
// this process, so if prism-client is killed or crashes the machine stays cut
// off from the internet instead of silently falling back to a direct
// connection that would expose the real IP. A clean shutdown, or
// `prism-client -killswitch-off`, removes them.
//
// Allowed while it is on: loopback, the TUN interface, the Prism server(s),
// and the local network (so the gateway, printers and file shares keep
// working). DNS to anything but loopback and the tunnel is rejected even on
// the local network — otherwise the LAN resolver would leak every lookup.

type ksParams struct {
	tunName    string
	tun4, tun6 netip.Addr
	servers    []netip.Addr
}

func mustPrefixes(ss ...string) []netip.Prefix {
	out := make([]netip.Prefix, len(ss))
	for i, s := range ss {
		out[i] = netip.MustParsePrefix(s)
	}
	return out
}

var (
	ksLocal4 = mustPrefixes("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16", "224.0.0.0/4", "255.255.255.255/32")
	ksLocal6 = mustPrefixes("fe80::/10", "fc00::/7", "ff00::/8")

	// ksTestScope, when set, narrows "reject everything else" to these
	// prefixes (and skips the DNS rule) so the rules can be exercised on a
	// machine that must keep its real connectivity. Tests only.
	ksTestScope []netip.Prefix
)

func ksParamsFor(dev *tunDevice, cfg *ClientConfig) (ksParams, error) {
	p := ksParams{tunName: dev.Name(), tun6: netip.MustParseAddr(tunAddr6)}
	pfx, err := netip.ParsePrefix(cfg.TUN.Address)
	if err != nil {
		return p, err
	}
	p.tun4 = pfx.Addr()
	for _, s := range append([]string{cfg.Server}, backupServers(cfg)...) {
		host, _, _ := net.SplitHostPort(s)
		a, err := netip.ParseAddr(host)
		if err != nil {
			return p, fmt.Errorf("kill switch needs resolved server addresses, got %q", host)
		}
		p.servers = append(p.servers, a)
	}
	return p, nil
}

func backupServers(cfg *ClientConfig) []string {
	var out []string
	for _, b := range cfg.Backups {
		out = append(out, b.Server)
	}
	return out
}

func joinAddrs[T fmt.Stringer](xs []T, sep string) string {
	ss := make([]string, len(xs))
	for i, x := range xs {
		ss[i] = x.String()
	}
	return strings.Join(ss, sep)
}

func splitFamilies(ps []netip.Prefix) (v4, v6 []netip.Prefix) {
	for _, p := range ps {
		if p.Addr().Is4() {
			v4 = append(v4, p)
		} else {
			v6 = append(v6, p)
		}
	}
	return
}

// addrRange is an inclusive address range.
type addrRange struct{ lo, hi netip.Addr }

func (r addrRange) String() string {
	if r.lo == r.hi {
		return r.lo.String()
	}
	return r.lo.String() + "-" + r.hi.String()
}

func lastAddr(p netip.Prefix) netip.Addr {
	b := p.Masked().Addr().AsSlice()
	for i := p.Bits(); i < len(b)*8; i++ {
		b[i/8] |= 1 << (7 - i%8)
	}
	a, _ := netip.AddrFromSlice(b)
	return a
}

// complementRanges returns every address of one family NOT covered by
// allowed, as inclusive ranges. Used where a firewall can only express
// "block these" (block rules outrank allow rules on Windows).
func complementRanges(v6 bool, allowed []netip.Prefix) []addrRange {
	lo, hi := netip.MustParseAddr("0.0.0.0"), netip.MustParseAddr("255.255.255.255")
	if v6 {
		lo, hi = netip.MustParseAddr("::"), netip.MustParseAddr("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff")
	}
	var rs []addrRange
	for _, p := range allowed {
		if p.Addr().Is6() == v6 {
			rs = append(rs, addrRange{p.Masked().Addr(), lastAddr(p)})
		}
	}
	sort.Slice(rs, func(i, j int) bool { return rs[i].lo.Less(rs[j].lo) })

	var out []addrRange
	cur, done := lo, false
	for _, r := range rs {
		if done {
			break
		}
		if cur.Less(r.lo) {
			out = append(out, addrRange{cur, r.lo.Prev()})
		}
		if !r.hi.Less(cur) {
			if r.hi == hi {
				done = true
			} else {
				cur = r.hi.Next()
			}
		}
	}
	if !done {
		out = append(out, addrRange{cur, hi})
	}
	return out
}

func hostPrefixes(addrs ...netip.Addr) []netip.Prefix {
	var out []netip.Prefix
	for _, a := range addrs {
		if a.IsValid() {
			out = append(out, netip.PrefixFrom(a, a.BitLen()))
		}
	}
	return out
}

// --- resolved-server cache ---

// resolveCachePath remembers the servers' resolved addresses. With the kill
// switch left on by a crash, DNS is blocked, so the next start could not
// resolve the server name without it.
var resolveCachePath string

func loadResolveCache() map[string]string {
	m := map[string]string{}
	if resolveCachePath != "" {
		if raw, err := os.ReadFile(resolveCachePath); err == nil {
			json.Unmarshal(raw, &m)
		}
	}
	return m
}

func storeResolved(host, ip string) {
	if resolveCachePath == "" {
		return
	}
	m := loadResolveCache()
	if m[host] == ip {
		return
	}
	m[host] = ip
	raw, _ := json.Marshal(m)
	// Best effort: the cache only matters after an unclean exit.
	_ = os.WriteFile(resolveCachePath, raw, 0o600)
}
