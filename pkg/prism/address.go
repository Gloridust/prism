package prism

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strconv"
)

// 目标地址编码（见 docs/PROTOCOL.md §6.1）：atyp(1) | addr | port(2 be)
const (
	atypIPv4   = 0x01
	atypDomain = 0x03
	atypIPv6   = 0x04
)

var errBadAddress = errors.New("prism: malformed address")

// EncodeAddress 把 host:port 编码为 Prism 地址字节。
func EncodeAddress(host string, port uint16) []byte {
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
			host = host[:255]
		}
		out = append(out, atypDomain, byte(len(host)))
		out = append(out, host...)
	}
	var p [2]byte
	binary.BigEndian.PutUint16(p[:], port)
	return append(out, p[:]...)
}

// ReadAddress 从流中读取一个 Prism 地址。
func ReadAddress(r io.Reader) (host string, port uint16, err error) {
	var atyp [1]byte
	if _, err = io.ReadFull(r, atyp[:]); err != nil {
		return
	}
	switch atyp[0] {
	case atypIPv4:
		b := make([]byte, 4)
		if _, err = io.ReadFull(r, b); err != nil {
			return
		}
		host = net.IP(b).String()
	case atypIPv6:
		b := make([]byte, 16)
		if _, err = io.ReadFull(r, b); err != nil {
			return
		}
		host = net.IP(b).String()
	case atypDomain:
		var l [1]byte
		if _, err = io.ReadFull(r, l[:]); err != nil {
			return
		}
		b := make([]byte, int(l[0]))
		if _, err = io.ReadFull(r, b); err != nil {
			return
		}
		host = string(b)
	default:
		err = errBadAddress
		return
	}
	var p [2]byte
	if _, err = io.ReadFull(r, p[:]); err != nil {
		return
	}
	port = binary.BigEndian.Uint16(p[:])
	return
}

// HostPort 拼接为 "host:port"。
func HostPort(host string, port uint16) string {
	return net.JoinHostPort(host, strconv.Itoa(int(port)))
}
