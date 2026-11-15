package prism

import (
	"errors"
	"io"
)

// Datagram framing for UDP-relay streams. A UDP stream's reliable byte channel
// carries a sequence of self-delimited, addressed datagrams:
//
//	[uint16 total][uint8 addrLen][addr (addrLen bytes)][payload (total-1-addrLen)]
//
// total = 1 + addrLen + len(payload), so one Write is one datagram and the
// reader recovers exact packet boundaries over the stream. addr is the compact
// Prism address form (atyp||addr||port), the same as a stream target. This is
// "UDP over a reliable stream": it adds ordering/reliability the original UDP
// lacked, the standard trade-off for tunnelling datagrams inside one carrier.
const maxDatagramPayload = 65535 - 1 - 1 - 1 - 255 // headroom under the uint16 total

var errBadDatagram = errors.New("prism: malformed datagram")

// WriteDatagram frames one addressed datagram onto w (one Write call).
func WriteDatagram(w io.Writer, hostport string, payload []byte) error {
	addr, err := EncodeAddr(hostport)
	if err != nil {
		return err
	}
	if len(addr) > 255 {
		return errBadDatagram
	}
	total := 1 + len(addr) + len(payload)
	if total > 65535 {
		return errBadDatagram
	}
	buf := make([]byte, 2+total)
	be.PutUint16(buf[0:2], uint16(total))
	buf[2] = byte(len(addr))
	copy(buf[3:], addr)
	copy(buf[3+len(addr):], payload)
	_, err = w.Write(buf)
	return err
}

// ReadDatagram reads the next framed datagram from r, returning its target
// "host:port" and payload. The returned payload is a fresh slice.
func ReadDatagram(r io.Reader) (hostport string, payload []byte, err error) {
	var h [2]byte
	if _, err = io.ReadFull(r, h[:]); err != nil {
		return
	}
	total := int(be.Uint16(h[:]))
	if total < 1 {
		err = errBadDatagram
		return
	}
	buf := make([]byte, total)
	if _, err = io.ReadFull(r, buf); err != nil {
		return
	}
	addrLen := int(buf[0])
	if 1+addrLen > total {
		err = errBadDatagram
		return
	}
	hostport, err = DecodeAddr(buf[1 : 1+addrLen])
	if err != nil {
		return
	}
	payload = buf[1+addrLen:]
	return
}

// SplitAddr parses a leading Prism/SOCKS address (atyp||addr||port) from b and
// returns it as "host:port" plus the bytes after the port. Used to peel the
// target off a SOCKS5 UDP request, which uses the same address encoding.
func SplitAddr(b []byte) (hostport string, rest []byte, err error) {
	if len(b) < 1 {
		return "", nil, errBadDatagram
	}
	var end int
	switch b[0] {
	case atypIPv4:
		end = 1 + 4 + 2
	case atypIPv6:
		end = 1 + 16 + 2
	case atypDomain:
		if len(b) < 2 {
			return "", nil, errBadDatagram
		}
		end = 1 + 1 + int(b[1]) + 2
	default:
		return "", nil, errBadDatagram
	}
	if len(b) < end {
		return "", nil, errBadDatagram
	}
	hostport, err = DecodeAddr(b[:end])
	if err != nil {
		return "", nil, err
	}
	return hostport, b[end:], nil
}
