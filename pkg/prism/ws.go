package prism

import (
	"bufio"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

// Minimal RFC 6455 WebSocket for tunneling: binary frames only, no extensions,
// no per-message compression. Both ends run over TLS, so the wire is already
// encrypted; WS framing lets the carrier traverse CDN/reverse-proxy infra
// (Cloudflare, etc.) that expects HTTP semantics.

const wsGUID = "258EAFA5-E914-47DA-95CA-5AB5B0082635"

// WebSocket opcodes.
const (
	wsOpBinary = 0x02
	wsOpClose  = 0x08
	wsOpPing   = 0x09
	wsOpPong   = 0x0a
)

// WSConn adapts a WebSocket connection to net.Conn. It is NOT safe for
// concurrent reads or concurrent writes — the Session serialises writes
// through wmu and runs reads from a single goroutine (readLoop). Deadlines
// and addresses are forwarded to the underlying net.Conn.
type WSConn struct {
	conn     net.Conn
	br       *bufio.Reader
	isClient bool

	// read state: bytes remaining in the current data frame
	readRemain int64
	readMask   [4]byte
	readMasked bool
	readPos    int
}

// NewWSConn wraps an already-upgraded connection. isClient controls masking:
// client→server frames are masked per RFC 6455; server→client are not.
func NewWSConn(conn net.Conn, br *bufio.Reader, isClient bool) *WSConn {
	if br == nil {
		br = bufio.NewReader(conn)
	}
	return &WSConn{conn: conn, br: br, isClient: isClient}
}

func (ws *WSConn) LocalAddr() net.Addr                { return ws.conn.LocalAddr() }
func (ws *WSConn) RemoteAddr() net.Addr               { return ws.conn.RemoteAddr() }
func (ws *WSConn) SetDeadline(t time.Time) error      { return ws.conn.SetDeadline(t) }
func (ws *WSConn) SetReadDeadline(t time.Time) error  { return ws.conn.SetReadDeadline(t) }
func (ws *WSConn) SetWriteDeadline(t time.Time) error { return ws.conn.SetWriteDeadline(t) }

func (ws *WSConn) Read(p []byte) (int, error) {
	for ws.readRemain == 0 {
		if err := ws.nextFrame(); err != nil {
			return 0, err
		}
	}
	n := int64(len(p))
	if n > ws.readRemain {
		n = ws.readRemain
	}
	nr, err := ws.br.Read(p[:n])
	if ws.readMasked && nr > 0 {
		for i := 0; i < nr; i++ {
			p[i] ^= ws.readMask[(ws.readPos+i)%4]
		}
		ws.readPos += nr
	}
	ws.readRemain -= int64(nr)
	return nr, err
}

func (ws *WSConn) nextFrame() error {
	for {
		hdr := make([]byte, 2)
		if _, err := io.ReadFull(ws.br, hdr); err != nil {
			return err
		}
		opcode := hdr[0] & 0x0f
		masked := hdr[1]&0x80 != 0
		length := int64(hdr[1] & 0x7f)

		switch {
		case length == 126:
			var buf [2]byte
			if _, err := io.ReadFull(ws.br, buf[:]); err != nil {
				return err
			}
			length = int64(binary.BigEndian.Uint16(buf[:]))
		case length == 127:
			var buf [8]byte
			if _, err := io.ReadFull(ws.br, buf[:]); err != nil {
				return err
			}
			length = int64(binary.BigEndian.Uint64(buf[:]))
		}

		var mask [4]byte
		if masked {
			if _, err := io.ReadFull(ws.br, mask[:]); err != nil {
				return err
			}
		}

		switch opcode {
		case wsOpBinary, 0x00: // binary or continuation
			ws.readRemain = length
			ws.readMask = mask
			ws.readMasked = masked
			ws.readPos = 0
			return nil
		case wsOpPing:
			// Read the payload, then reply with pong.
			payload := make([]byte, length)
			if _, err := io.ReadFull(ws.br, payload); err != nil {
				return err
			}
			if masked {
				for i := range payload {
					payload[i] ^= mask[i%4]
				}
			}
			ws.writeControl(wsOpPong, payload)
			continue
		case wsOpPong:
			// Discard.
			if _, err := io.CopyN(io.Discard, ws.br, length); err != nil {
				return err
			}
			continue
		case wsOpClose:
			return io.EOF
		default:
			return fmt.Errorf("ws: unsupported opcode 0x%02x", opcode)
		}
	}
}

func (ws *WSConn) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	hdr := ws.frameHeader(wsOpBinary, len(p))
	if ws.isClient {
		var mask [4]byte
		rand.Read(mask[:])
		hdr = append(hdr, mask[:]...)
		masked := make([]byte, len(p))
		for i := range p {
			masked[i] = p[i] ^ mask[i%4]
		}
		if _, err := ws.conn.Write(append(hdr, masked...)); err != nil {
			return 0, err
		}
	} else {
		if _, err := ws.conn.Write(append(hdr, p...)); err != nil {
			return 0, err
		}
	}
	return len(p), nil
}

func (ws *WSConn) frameHeader(opcode byte, payloadLen int) []byte {
	var hdr []byte
	b0 := byte(0x80) | opcode // FIN + opcode
	switch {
	case payloadLen <= 125:
		b1 := byte(payloadLen)
		if ws.isClient {
			b1 |= 0x80
		}
		hdr = []byte{b0, b1}
	case payloadLen <= 65535:
		b1 := byte(126)
		if ws.isClient {
			b1 |= 0x80
		}
		hdr = make([]byte, 4)
		hdr[0] = b0
		hdr[1] = b1
		binary.BigEndian.PutUint16(hdr[2:], uint16(payloadLen))
	default:
		b1 := byte(127)
		if ws.isClient {
			b1 |= 0x80
		}
		hdr = make([]byte, 10)
		hdr[0] = b0
		hdr[1] = b1
		binary.BigEndian.PutUint64(hdr[2:], uint64(payloadLen))
	}
	return hdr
}

func (ws *WSConn) writeControl(opcode byte, payload []byte) {
	hdr := ws.frameHeader(opcode, len(payload))
	ws.conn.Write(append(hdr, payload...))
}

func (ws *WSConn) Close() error {
	// Best-effort close frame with a short deadline — the peer may already be
	// gone, and we must not block the caller. The underlying conn always closes.
	ws.conn.SetWriteDeadline(time.Now().Add(time.Second))
	ws.writeControl(wsOpClose, []byte{0x03, 0xe8}) // 1000 normal closure
	return ws.conn.Close()
}

// --- WebSocket upgrade helpers ---

// WSClientUpgrade performs the WebSocket upgrade on an already-established
// connection (typically TLS). It sends the HTTP upgrade request and reads
// the 101 response. The returned WSConn carries the Prism byte stream.
func WSClientUpgrade(conn net.Conn, host, path string) (*WSConn, error) {
	keyBytes := make([]byte, 16)
	rand.Read(keyBytes)
	key := base64.StdEncoding.EncodeToString(keyBytes)

	req := fmt.Sprintf("GET %s HTTP/1.1\r\n"+
		"Host: %s\r\n"+
		"Upgrade: websocket\r\n"+
		"Connection: Upgrade\r\n"+
		"Sec-WebSocket-Key: %s\r\n"+
		"Sec-WebSocket-Version: 13\r\n"+
		"\r\n", path, host, key)
	if _, err := conn.Write([]byte(req)); err != nil {
		return nil, err
	}

	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		return nil, fmt.Errorf("ws: reading upgrade response: %w", err)
	}
	resp.Body.Close()
	if resp.StatusCode != 101 {
		return nil, fmt.Errorf("ws: server returned %d, want 101", resp.StatusCode)
	}
	wantAccept := wsAcceptKey(key)
	if got := resp.Header.Get("Sec-WebSocket-Accept"); got != wantAccept {
		return nil, errors.New("ws: Sec-WebSocket-Accept mismatch")
	}
	return NewWSConn(conn, br, true), nil
}

// WSServerUpgrade checks if an HTTP request is a WebSocket upgrade to the
// given path. If so it hijacks the connection, sends the 101 response, and
// returns a server-side WSConn. If not it returns nil and the caller should
// serve the request normally.
func WSServerUpgrade(w http.ResponseWriter, r *http.Request, path string) *WSConn {
	if r.URL.Path != path {
		return nil
	}
	if !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
		return nil
	}
	key := r.Header.Get("Sec-WebSocket-Key")
	if key == "" {
		return nil
	}

	hj, ok := w.(http.Hijacker)
	if !ok {
		return nil
	}
	conn, brw, err := hj.Hijack()
	if err != nil {
		return nil
	}

	accept := wsAcceptKey(key)
	resp := "HTTP/1.1 101 Switching Protocols\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Accept: " + accept + "\r\n" +
		"\r\n"
	if _, err := brw.WriteString(resp); err != nil {
		conn.Close()
		return nil
	}
	if err := brw.Flush(); err != nil {
		conn.Close()
		return nil
	}
	return NewWSConn(conn, brw.Reader, false)
}

func wsAcceptKey(clientKey string) string {
	h := sha1.New()
	h.Write([]byte(clientKey))
	h.Write([]byte(wsGUID))
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}
