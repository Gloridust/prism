package prism

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strconv"
)

// Address type bytes, matching SOCKS5 so the mux target format is familiar and
// maps directly onto a SOCKS inbound.
const (
	atypIPv4   = 0x01
	atypDomain = 0x03
	atypIPv6   = 0x04
)

// EncodeAddr serialises "host:port" into the compact on-wire target form:
//
//	[atyp 1][addr][port 2]
//
// Domains are kept as names (not pre-resolved) so DNS resolution happens at the
// egress server in Singapore — the client never leaks the destination via a
// local DNS lookup.
func EncodeAddr(hostport string) ([]byte, error) {
	host, portStr, err := net.SplitHostPort(hostport)
	if err != nil {
		return nil, err
	}
	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return nil, fmt.Errorf("prism: bad port %q: %w", portStr, err)
	}
	var out []byte
	if ip := net.ParseIP(host); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			out = append(out, atypIPv4)
			out = append(out, v4...)
		} else {
			out = append(out, atypIPv6)
			out = append(out, ip.To16()...)
		}
	} else {
		if len(host) > 255 {
			return nil, errors.New("prism: domain too long")
		}
		out = append(out, atypDomain, byte(len(host)))
		out = append(out, host...)
	}
	var p [2]byte
	binary.BigEndian.PutUint16(p[:], uint16(port))
	return append(out, p[:]...), nil
}

// DecodeAddr parses the form produced by EncodeAddr back into "host:port".
func DecodeAddr(b []byte) (string, error) {
	if len(b) < 1 {
		return "", errors.New("prism: empty address")
	}
	var host string
	var rest []byte
	switch b[0] {
	case atypIPv4:
		if len(b) < 1+4+2 {
			return "", errors.New("prism: short ipv4 address")
		}
		host = net.IP(b[1 : 1+4]).String()
		rest = b[1+4:]
	case atypIPv6:
		if len(b) < 1+16+2 {
			return "", errors.New("prism: short ipv6 address")
		}
		host = net.IP(b[1 : 1+16]).String()
		rest = b[1+16:]
	case atypDomain:
		if len(b) < 2 {
			return "", errors.New("prism: short domain address")
		}
		n := int(b[1])
		if len(b) < 2+n+2 {
			return "", errors.New("prism: truncated domain address")
		}
		host = string(b[2 : 2+n])
		rest = b[2+n:]
	default:
		return "", fmt.Errorf("prism: unknown atyp 0x%02x", b[0])
	}
	port := binary.BigEndian.Uint16(rest[:2])
	return net.JoinHostPort(host, strconv.Itoa(int(port))), nil
}
