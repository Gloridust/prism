package prism

import (
	"encoding/binary"
	"errors"
	"io"
	"sync"
	"time"
)

// Inner frame command bytes.
const (
	cmdData   byte = 0x00 // stream payload
	cmdPad    byte = 0x01 // cover padding, carries no stream data
	cmdSYN    byte = 0x02 // open a stream; data = encoded target address
	cmdFIN    byte = 0x03 // half-close: no more data from this side
	cmdRST    byte = 0x04 // abort a stream
	cmdWnd    byte = 0x05 // flow-control credit; data = uint32 big-endian bytes
	cmdSYNUDP byte = 0x06 // open a UDP-relay stream (carries addressed datagrams)
)

const (
	hdrSize = 7 // cmd(1) + streamID(4) + dataLen(2)
	// maxPayload keeps one full DATA frame inside a single TLS record: the
	// on-wire size is 2 (len prefix) + 16 (tag) + hdrSize + payload, which must
	// stay <= 16384 (TLS max record) to avoid splitting every full frame across
	// two records. 16000 leaves comfortable headroom.
	maxPayload = 16000
)

// Liveness: both ends emit a PAD keepalive every keepaliveInterval, and a
// session whose carrier delivers nothing for idleTimeout is torn down. This
// detects a silently dropped carrier (common on long-haul links behind stateful
// middleboxes) in bounded time instead of waiting minutes for TCP keepalive —
// the WireGuard/QUIC persistent-keepalive + idle-timeout pattern. idleTimeout
// is several keepalive intervals so a little jitter or loss never kills a live
// session. They are package vars (not consts) so an operator can tune them and
// tests can shorten them.
var (
	keepaliveInterval = 15 * time.Second
	idleTimeout       = 60 * time.Second
)

// Per-stream credit-based flow control (see docs/PROTOCOL.md §6.2). Each stream
// may have at most streamWindow unacknowledged bytes in flight; the receiver
// returns credit with a WND frame once it has consumed wndThreshold bytes. This
// bounds per-stream buffering AND — unlike a blocking receive queue — never
// stalls the shared session read loop, so one slow stream can't head-of-line
// block the others multiplexed over the same carrier.
const (
	streamWindow = 512 * 1024
	wndThreshold = streamWindow / 2
)

var (
	// ErrSessionClosed is returned once the underlying carrier is gone.
	ErrSessionClosed = errors.New("prism: session closed")
	// ErrStreamClosed is returned on a locally closed stream.
	ErrStreamClosed = errors.New("prism: stream closed")
	// ErrStreamReset is returned when the peer aborts a stream.
	ErrStreamReset = errors.New("prism: stream reset by peer")
)

var be = binary.BigEndian

// Session is a multiplexed, AEAD-framed data phase over one carrier connection.
// After a completed handshake, wrap the carrier with NewSession. The initiator
// (client) opens streams; the responder (server) accepts them.
type Session struct {
	transport io.ReadWriteCloser
	sendAEAD  AEAD
	recvAEAD  AEAD

	wmu     sync.Mutex
	sendCtr uint64
	werr    error

	recvCtr uint64 // only touched by readLoop

	mu        sync.Mutex
	streams   map[uint32]*Stream
	nextID    uint32
	initiator bool
	accept    chan *Stream
	closed    bool
	closeErr  error
	done      chan struct{}

	// liveness timeouts captured at construction (from the package vars) so the
	// readLoop/keepalive goroutines read fields, never shared globals.
	keepEvery   time.Duration
	idleTimeout time.Duration
}

// NewSession wraps a post-handshake carrier. initiator must be true on the
// client and false on the server. The data phase uses the cipher the handshake
// agreed on (keys.aead); a hand-built Keys with no cipher set defaults to
// AES-256-GCM, matching the zero-dependency reference build.
func NewSession(transport io.ReadWriteCloser, keys *Keys, initiator bool) (*Session, error) {
	newAEAD := keys.aead
	if newAEAD == nil {
		newAEAD = NewAEAD
	}
	sendAEAD, err := newAEAD(keys.Send)
	if err != nil {
		return nil, err
	}
	recvAEAD, err := newAEAD(keys.Recv)
	if err != nil {
		return nil, err
	}
	s := &Session{
		transport:   transport,
		sendAEAD:    sendAEAD,
		recvAEAD:    recvAEAD,
		streams:     make(map[uint32]*Stream),
		initiator:   initiator,
		accept:      make(chan *Stream, 16),
		done:        make(chan struct{}),
		keepEvery:   keepaliveInterval,
		idleTimeout: idleTimeout,
	}
	if initiator {
		s.nextID = 1
	} else {
		s.nextID = 2 // disjoint id space, avoids collisions if both ever open
	}
	go s.readLoop()
	go s.keepalive()
	return s, nil
}

func (s *Session) writeFrame(cmd byte, id uint32, data []byte, pad int) error {
	s.wmu.Lock()
	defer s.wmu.Unlock()
	if s.werr != nil {
		return s.werr
	}
	plain := make([]byte, hdrSize+len(data)+pad)
	plain[0] = cmd
	be.PutUint32(plain[1:5], id)
	be.PutUint16(plain[5:7], uint16(len(data)))
	copy(plain[7:], data)
	// Padding bytes stay zero; they are inside the AEAD so an observer cannot
	// tell padding from payload. The length prefix below is the only cleartext.
	ct := s.sendAEAD.Seal(s.sendCtr, plain, nil)
	s.sendCtr++

	out := make([]byte, 2+len(ct))
	be.PutUint16(out[:2], uint16(len(ct)))
	copy(out[2:], ct)
	if _, err := s.transport.Write(out); err != nil {
		s.werr = err
		return err
	}
	return nil
}

func (s *Session) readLoop() {
	defer s.teardown(ErrSessionClosed)
	// If the carrier supports deadlines (TLS/TCP do), bound each frame read by
	// idleTimeout so a dead peer is detected instead of blocking forever.
	rd, _ := s.transport.(interface{ SetReadDeadline(time.Time) error })
	hdr := make([]byte, 2)
	for {
		if rd != nil {
			_ = rd.SetReadDeadline(time.Now().Add(s.idleTimeout))
		}
		if _, err := io.ReadFull(s.transport, hdr); err != nil {
			return
		}
		n := int(be.Uint16(hdr))
		if n < tagSize {
			return // malformed
		}
		ct := make([]byte, n)
		if _, err := io.ReadFull(s.transport, ct); err != nil {
			return
		}
		plain, err := s.recvAEAD.Open(s.recvCtr, ct, nil)
		if err != nil {
			return // authentication failure -> tear the session down
		}
		s.recvCtr++
		if len(plain) < hdrSize {
			return
		}
		s.dispatch(plain)
	}
}

// keepalive emits an empty PAD frame every keepaliveInterval until the session
// ends. Both ends run it, so each sees carrier activity well within idleTimeout
// even when no stream is sending; PAD carries no stream data and is ignored on
// receipt.
func (s *Session) keepalive() {
	t := time.NewTicker(s.keepEvery)
	defer t.Stop()
	for {
		select {
		case <-s.done:
			return
		case <-t.C:
			if err := s.writeFrame(cmdPad, 0, nil, 0); err != nil {
				return
			}
		}
	}
}

func (s *Session) dispatch(plain []byte) {
	cmd := plain[0]
	id := be.Uint32(plain[1:5])
	dataLen := int(be.Uint16(plain[5:7]))
	if hdrSize+dataLen > len(plain) {
		return // truncated; ignore
	}
	data := plain[hdrSize : hdrSize+dataLen]

	switch cmd {
	case cmdPad:
		return
	case cmdSYN:
		if s.initiator {
			return // clients don't accept streams
		}
		target, err := DecodeAddr(data)
		if err != nil {
			return
		}
		st := s.newStream(id, target)
		s.mu.Lock()
		if _, exists := s.streams[id]; exists || s.closed {
			s.mu.Unlock()
			return
		}
		s.streams[id] = st
		s.mu.Unlock()
		select {
		case s.accept <- st:
		case <-s.done:
		}
	case cmdSYNUDP:
		if s.initiator {
			return // clients don't accept streams
		}
		st := s.newStream(id, "")
		st.udp = true
		s.mu.Lock()
		if _, exists := s.streams[id]; exists || s.closed {
			s.mu.Unlock()
			return
		}
		s.streams[id] = st
		s.mu.Unlock()
		select {
		case s.accept <- st:
		case <-s.done:
		}
	case cmdData:
		if st := s.lookup(id); st != nil {
			st.deliver(append([]byte(nil), data...))
		}
	case cmdWnd:
		if st := s.lookup(id); st != nil && len(data) >= 4 {
			st.addCredit(int(be.Uint32(data)))
		}
	case cmdFIN:
		if st := s.lookup(id); st != nil {
			st.closeRead(io.EOF)
		}
	case cmdRST:
		if st := s.lookup(id); st != nil {
			st.closeRead(ErrStreamReset)
			st.failWrite(ErrStreamReset)
			s.removeStream(id)
		}
	}
}

func (s *Session) lookup(id uint32) *Stream {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.streams[id]
}

func (s *Session) removeStream(id uint32) {
	s.mu.Lock()
	delete(s.streams, id)
	s.mu.Unlock()
}

// OpenStream (client) opens a new logical stream to target "host:port".
func (s *Session) OpenStream(target string) (*Stream, error) {
	if !s.initiator {
		return nil, errors.New("prism: only the initiator may open streams")
	}
	enc, err := EncodeAddr(target)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil, s.closeErr
	}
	id := s.nextID
	s.nextID += 2
	st := s.newStream(id, target)
	s.streams[id] = st
	s.mu.Unlock()

	if err := s.writeFrame(cmdSYN, id, enc, 0); err != nil {
		s.removeStream(id)
		return nil, err
	}
	return st, nil
}

// OpenUDP (client) opens a UDP-relay stream. Write addressed datagrams to it
// with WriteDatagram and read them with ReadDatagram; the server relays each to
// its target over UDP and frames replies back the same way.
func (s *Session) OpenUDP() (*Stream, error) {
	if !s.initiator {
		return nil, errors.New("prism: only the initiator may open streams")
	}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil, s.closeErr
	}
	id := s.nextID
	s.nextID += 2
	st := s.newStream(id, "")
	st.udp = true
	s.streams[id] = st
	s.mu.Unlock()

	if err := s.writeFrame(cmdSYNUDP, id, nil, 0); err != nil {
		s.removeStream(id)
		return nil, err
	}
	return st, nil
}

// Accept (server) returns the next stream opened by the peer.
func (s *Session) Accept() (*Stream, error) {
	select {
	case st := <-s.accept:
		if st == nil {
			return nil, s.closeErr
		}
		return st, nil
	case <-s.done:
		return nil, s.closeErr
	}
}

func (s *Session) teardown(err error) {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.closed = true
	s.closeErr = err
	streams := s.streams
	s.streams = make(map[uint32]*Stream)
	close(s.done)
	s.mu.Unlock()

	s.wmu.Lock()
	if s.werr == nil {
		s.werr = err
	}
	s.wmu.Unlock()

	for _, st := range streams {
		st.closeRead(err)
		st.failWrite(err)
	}
	s.transport.Close()
}

// Close shuts the session and its carrier down.
func (s *Session) Close() error {
	s.teardown(ErrSessionClosed)
	return nil
}

// Done is closed when the session ends.
func (s *Session) Done() <-chan struct{} { return s.done }

// --- Stream ---

// Stream is one logical connection inside a Session. It satisfies io.Reader,
// io.Writer and io.Closer, plus CloseWrite for half-close. Reads and writes are
// each guarded by their own mutex/cond so the two directions never contend.
type Stream struct {
	id     uint32
	s      *Session
	target string
	udp    bool // true: a UDP-relay stream carrying addressed datagrams

	// receive side
	rmu      sync.Mutex
	rcond    *sync.Cond
	queue    [][]byte
	queued   int
	readErr  error
	consumed int // bytes consumed since the last WND credit was returned

	// send side (flow control)
	wmu       sync.Mutex
	wcond     *sync.Cond
	sendWin   int
	writeErr  error
	writeDone bool

	closeOnce sync.Once
}

func (s *Session) newStream(id uint32, target string) *Stream {
	st := &Stream{id: id, s: s, target: target, sendWin: streamWindow}
	st.rcond = sync.NewCond(&st.rmu)
	st.wcond = sync.NewCond(&st.wmu)
	return st
}

// Target is the destination "host:port" for a server-accepted stream.
func (st *Stream) Target() string { return st.target }

// IsUDP reports whether this is a UDP-relay stream (opened with OpenUDP). Its
// byte stream carries length-delimited addressed datagrams (see datagram.go),
// not a single TCP target.
func (st *Stream) IsUDP() bool { return st.udp }

// deliver is called by the session read loop. It never blocks: the sender's
// flow-control window bounds how much can be queued here, so appending is safe
// and the read loop stays free to service other streams.
func (st *Stream) deliver(b []byte) {
	st.rmu.Lock()
	if st.readErr == nil {
		st.queue = append(st.queue, b)
		st.queued += len(b)
		st.rcond.Broadcast()
	}
	st.rmu.Unlock()
}

func (st *Stream) closeRead(err error) {
	st.rmu.Lock()
	if st.readErr == nil {
		st.readErr = err
	}
	st.rcond.Broadcast()
	st.rmu.Unlock()
}

func (st *Stream) failWrite(err error) {
	st.wmu.Lock()
	if st.writeErr == nil {
		st.writeErr = err
	}
	st.wcond.Broadcast()
	st.wmu.Unlock()
}

func (st *Stream) addCredit(n int) {
	st.wmu.Lock()
	st.sendWin += n
	st.wcond.Broadcast()
	st.wmu.Unlock()
}

func (st *Stream) Read(p []byte) (int, error) {
	st.rmu.Lock()
	for len(st.queue) == 0 {
		if st.readErr != nil {
			err := st.readErr
			st.rmu.Unlock()
			return 0, err
		}
		st.rcond.Wait()
	}
	n := 0
	for n < len(p) && len(st.queue) > 0 {
		chunk := st.queue[0]
		c := copy(p[n:], chunk)
		n += c
		if c < len(chunk) {
			st.queue[0] = chunk[c:]
		} else {
			st.queue = st.queue[1:]
		}
		st.queued -= c
	}
	st.consumed += n
	var credit int
	if st.consumed >= wndThreshold {
		credit = st.consumed
		st.consumed = 0
	}
	st.rmu.Unlock()

	if credit > 0 {
		var b [4]byte
		be.PutUint32(b[:], uint32(credit))
		_ = st.s.writeFrame(cmdWnd, st.id, b[:], 0) // best-effort; teardown covers errors
	}
	return n, nil
}

func (st *Stream) Write(p []byte) (int, error) {
	total := 0
	for len(p) > 0 {
		st.wmu.Lock()
		for st.sendWin == 0 && st.writeErr == nil && !st.writeDone {
			st.wcond.Wait()
		}
		if st.writeErr != nil {
			err := st.writeErr
			st.wmu.Unlock()
			return total, err
		}
		if st.writeDone {
			st.wmu.Unlock()
			return total, ErrStreamClosed
		}
		n := len(p)
		if n > maxPayload {
			n = maxPayload
		}
		if n > st.sendWin {
			n = st.sendWin
		}
		st.sendWin -= n
		st.wmu.Unlock()

		if err := st.s.writeFrame(cmdData, st.id, p[:n], 0); err != nil {
			return total, err
		}
		total += n
		p = p[n:]
	}
	return total, nil
}

// CloseWrite sends FIN: this side will send no more data, but can still read.
func (st *Stream) CloseWrite() error {
	st.wmu.Lock()
	if st.writeDone {
		st.wmu.Unlock()
		return nil
	}
	st.writeDone = true
	st.wcond.Broadcast()
	st.wmu.Unlock()
	return st.s.writeFrame(cmdFIN, st.id, nil, 0)
}

// Close tears the stream down in both directions.
func (st *Stream) Close() error {
	st.closeOnce.Do(func() {
		_ = st.s.writeFrame(cmdRST, st.id, nil, 0)
		st.closeRead(ErrStreamClosed)
		st.failWrite(ErrStreamClosed)
		st.s.removeStream(st.id)
	})
	return nil
}
