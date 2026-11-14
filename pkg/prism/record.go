package prism

import (
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"time"
)

// MaxPayload 单条记录载荷上限（见 §5、§10）。
const MaxPayload = 16384

const lenChunkSize = 2 + TagSize // 加密长度段固定 18B

var errBadRecord = errors.New("prism: bad record length")

// Conn 是握手完成后的加密记录连接，实现 net.Conn。
// 每条记录 = AEAD(长度) || AEAD(载荷)，对外隐藏真实长度与边界（见 §5）。
type Conn struct {
	raw net.Conn

	rxAEAD  cipher.AEAD
	txAEAD  cipher.AEAD
	rxNonce uint64
	txNonce uint64

	rMu     sync.Mutex
	wMu     sync.Mutex
	readBuf []byte // 已解密但未被 Read 取走的载荷

	SessionID  []byte
	PeerStatic []byte
}

// NewConn 用握手结果包装底层连接。
func NewConn(raw net.Conn, hs *HandshakeResult) (*Conn, error) {
	tx, err := newAEAD(hs.TxKey)
	if err != nil {
		return nil, err
	}
	rx, err := newAEAD(hs.RxKey)
	if err != nil {
		return nil, err
	}
	return &Conn{
		raw:        raw,
		txAEAD:     tx,
		rxAEAD:     rx,
		SessionID:  hs.SessionID,
		PeerStatic: hs.PeerStatic,
	}, nil
}

func (c *Conn) Read(p []byte) (int, error) {
	c.rMu.Lock()
	defer c.rMu.Unlock()
	if len(c.readBuf) == 0 {
		if err := c.readRecord(); err != nil {
			return 0, err
		}
	}
	n := copy(p, c.readBuf)
	c.readBuf = c.readBuf[n:]
	return n, nil
}

func (c *Conn) readRecord() error {
	encLen := make([]byte, lenChunkSize)
	if _, err := io.ReadFull(c.raw, encLen); err != nil {
		return err
	}
	lenBuf, err := c.rxAEAD.Open(encLen[:0], nonceFromCounter(c.rxNonce), encLen, nil)
	if err != nil {
		return err
	}
	c.rxNonce++
	n := int(binary.BigEndian.Uint16(lenBuf))
	if n == 0 || n > MaxPayload {
		return errBadRecord
	}
	encPay := make([]byte, n+TagSize)
	if _, err := io.ReadFull(c.raw, encPay); err != nil {
		return err
	}
	pay, err := c.rxAEAD.Open(encPay[:0], nonceFromCounter(c.rxNonce), encPay, nil)
	if err != nil {
		return err
	}
	c.rxNonce++
	c.readBuf = pay
	return nil
}

func (c *Conn) Write(p []byte) (int, error) {
	c.wMu.Lock()
	defer c.wMu.Unlock()
	total := 0
	for len(p) > 0 {
		n := len(p)
		if n > MaxPayload {
			n = MaxPayload
		}
		if err := c.writeRecord(p[:n]); err != nil {
			return total, err
		}
		p = p[n:]
		total += n
	}
	return total, nil
}

func (c *Conn) writeRecord(payload []byte) error {
	var lenPlain [2]byte
	binary.BigEndian.PutUint16(lenPlain[:], uint16(len(payload)))

	// 一次性拼好 [encLen || encPay] 再写出，减少 TCP 分段特征
	out := make([]byte, 0, lenChunkSize+len(payload)+TagSize)
	out = c.txAEAD.Seal(out, nonceFromCounter(c.txNonce), lenPlain[:], nil)
	c.txNonce++
	out = c.txAEAD.Seal(out, nonceFromCounter(c.txNonce), payload, nil)
	c.txNonce++

	_, err := c.raw.Write(out)
	return err
}

// 以下方法令 Conn 满足 net.Conn。
func (c *Conn) Close() error                       { return c.raw.Close() }
func (c *Conn) LocalAddr() net.Addr                { return c.raw.LocalAddr() }
func (c *Conn) RemoteAddr() net.Addr               { return c.raw.RemoteAddr() }
func (c *Conn) SetDeadline(t time.Time) error      { return c.raw.SetDeadline(t) }
func (c *Conn) SetReadDeadline(t time.Time) error  { return c.raw.SetReadDeadline(t) }
func (c *Conn) SetWriteDeadline(t time.Time) error { return c.raw.SetWriteDeadline(t) }
