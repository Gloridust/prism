package main

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"time"
)

// errBlockedTarget is returned when a target resolves only to addresses the
// egress policy forbids. It is distinct so the caller can log it specifically.
var errBlockedTarget = errors.New("prism: target resolves only to blocked (private/loopback/link-local) addresses")

// isDisallowedIP reports whether ip must NOT be an egress target under the
// default policy. Without this, any credentialed client could make the egress
// box connect to its own loopback, the office/cloud internal network, or the
// cloud metadata endpoint (169.254.169.254) — the classic proxy SSRF. Blocked:
// loopback, private (RFC1918 + IPv6 ULA), link-local (which includes the
// metadata IP), CGNAT (100.64/10), multicast and the unspecified address.
// Public addresses return false.
func isDisallowedIP(ip net.IP) bool {
	if ip == nil {
		return true
	}
	if ip4 := ip.To4(); ip4 != nil {
		ip = ip4
	} else if a, ok := netip.AddrFromSlice(ip); ok {
		// IPv6 forms that embed an IPv4 destination (NAT64, 6to4) are judged
		// by that IPv4 address, or they would tunnel around the policy.
		b := a.As16()
		switch {
		case nat64Prefix.Contains(a):
			return isDisallowedIP(net.IP(b[12:16]))
		case sixToFourPrefix.Contains(a):
			return isDisallowedIP(net.IP(b[2:6]))
		}
	}
	if a, ok := netip.AddrFromSlice(ip); ok {
		for _, p := range reservedPrefixes {
			if p.Contains(a) {
				return true
			}
		}
	}
	return ip.IsLoopback() || ip.IsPrivate() ||
		ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsMulticast() || ip.IsUnspecified() || isCGNAT(ip)
}

var (
	nat64Prefix     = netip.MustParsePrefix("64:ff9b::/96")
	sixToFourPrefix = netip.MustParsePrefix("2002::/16")
	// Special-purpose blocks the stdlib predicates above do not cover.
	reservedPrefixes = []netip.Prefix{
		netip.MustParsePrefix("0.0.0.0/8"),     // "this network"
		netip.MustParsePrefix("192.0.0.0/24"),  // IETF protocol assignments
		netip.MustParsePrefix("198.18.0.0/15"), // benchmarking
		netip.MustParsePrefix("240.0.0.0/4"),   // reserved + limited broadcast
	}
)

// isCGNAT reports whether ip is in 100.64.0.0/10 (RFC 6598 carrier-grade NAT),
// which commonly fronts an operator's internal network.
func isCGNAT(ip net.IP) bool {
	ip4 := ip.To4()
	return ip4 != nil && ip4[0] == 100 && ip4[1]&0xc0 == 64
}

// safeDial resolves target and connects to a permitted address. With
// allowPrivate it applies no policy (dial as given). Otherwise it resolves the
// host ONCE and dials a vetted public IP directly — never re-resolving — so a
// DNS answer cannot swap a vetted public IP for a private one between the check
// and the connect (DNS-rebinding TOCTOU). A literal IP resolves to itself, so
// the same policy covers literal-IP targets.
func safeDial(target string, allowPrivate bool, timeout time.Duration) (net.Conn, error) {
	host, port, err := net.SplitHostPort(target)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	var d net.Dialer
	if allowPrivate {
		return d.DialContext(ctx, "tcp", target)
	}

	ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, err
	}
	var lastErr error = errBlockedTarget
	for _, ia := range ips {
		if isDisallowedIP(ia.IP) {
			continue
		}
		conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(ia.IP.String(), port))
		if err == nil {
			return conn, nil
		}
		lastErr = err
	}
	return nil, lastErr
}
