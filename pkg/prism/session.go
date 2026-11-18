package prism

import (
	"encoding/binary"
	"errors"
	"io"
	"math/rand"
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

// shapeBuckets are the plaintext frame sizes the "pad" shaping profile rounds
// up to. Small inner records — a tunnelled TLS ClientHello, a DNS query, an ACK
// — otherwise pass their length straight through to the carrier; padding them
// to a handful of fixed sizes breaks that length correlation (obfs4-style). The
// pad bytes live inside the AEAD and are ignored on receipt, so shaping is a
// purely local per-direction choice that needs no negotiation. Full-size frames
// exceed the largest bucket and are never padded, so bulk throughput is intact.
var shapeBuckets = []int{64, 256, 576, 1280, 4096, 16000}

var (
	// ErrSessionClosed is returned once the underlying carrier is gone.
	ErrSessionClosed = errors.New("prism: session closed")
	// ErrStreamClosed is returned on a locally closed stream.
	ErrStreamClosed = errors.New("prism: stream closed")
	// ErrStreamReset is returned when the peer aborts a stream.
	ErrStreamReset = errors.New("prism: stream reset by peer")
	// ErrTooManyStreams is returned when a session is at its stream cap.
	ErrTooManyStreams = errors.New("prism: too many concurrent streams")
	// ErrSessionDraining is returned when new streams are rejected because
	// the session's max lifetime has been reached and it is draining.
	ErrSessionDraining = errors.New("prism: session draining (max lifetime reached)")
	// ErrFlowControl ends a session whose peer sent more than its window allows.
	ErrFlowControl = errors.New("prism: peer violated stream flow control")
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

	buckets    []int    // egress length-shaping buckets; nil = no shaping
	profile    *Profile // traffic profile (superset of buckets; nil = no profile)
	maxStreams int      // cap on concurrent streams; 0 = unlimited
	maxLife    time.Duration
	draining   chan struct{} // closed when the session starts draining (max lifetime)
	iatMaxMs   int           // inter-arrival time shaping: max random delay in ms (0 = off)
	headFrames int           // per-stream head frames to length-randomise (0 = off)

	// Reusable buffers — eliminate per-frame heap allocations on the hot path.
	// wplain/wout are protected by wmu; rct is readLoop-only.
	wplain []byte // plaintext frame assembly
	wout   []byte // wire output: [2-byte len][ciphertext]
	rct    []byte // ciphertext read from wire
}

// Option configures a Session at construction.
type Option func(*Session)

// WithShaping enables an egress traffic-shaping profile by name. Built-in
// profiles: "none" (default), "pad" (length bucketing only), "web" (browsing
// pattern), "video" (streaming pattern), "download" (bulk transfer pattern).
func WithShaping(mode string) Option {
	return func(s *Session) {
		if p := LookupProfile(mode); p != nil {
			s.profile = p
			s.buckets = p.Buckets
		} else if mode == "pad" {
			s.buckets = shapeBuckets
		}
	}
}

// WithMaxStreams caps concurrent streams on a session (0 = unlimited). The
// responder RSTs new streams past the cap; the initiator gets ErrTooManyStreams
// from Open. It bounds per-carrier memory (each stream may buffer up to one
// receive window) against a client that opens streams without bound.
func WithMaxStreams(n int) Option {
	return func(s *Session) { s.maxStreams = n }
}

// WithMaxLifetime sets a carrier session max lifetime. After d elapses, the
// session enters a "draining" state: OpenStream/OpenUDP return
// ErrSessionDraining, but existing streams continue until they close naturally.
// The client dialer sees Draining() and redials a fresh session for new streams.
// 0 means no limit (the default).
func WithMaxLifetime(d time.Duration) Option {
	return func(s *Session) { s.maxLife = d }
}

// WithIAT enables inter-arrival time shaping: each outgoing DATA frame is
// preceded by a random delay of 0–maxMs milliseconds. Only frames whose
// plaintext payload (before padding) is smaller than 1280 bytes are delayed,
// so bulk throughput is unaffected. The jitter blurs per-frame timing patterns
// that could distinguish Prism from ordinary HTTPS browsing. 0 disables it.
func WithIAT(maxMs int) Option {
	return func(s *Session) { s.iatMaxMs = maxMs }
}

// DefaultHeadFrames is how many frames per stream the commands pad by default:
// enough to cover a TLS 1.3 handshake in both directions.
const DefaultHeadFrames = 8

// WithHeadPadding randomises the length of the first n DATA frames of every
// stream (and of the SYN that opens it). Those frames carry the tunnelled
// connection's own handshake — typically a TLS ClientHello/ServerHello whose
// sizes are a well-known TLS-in-TLS signature — so hiding their lengths removes
// the signature while leaving bulk transfer untouched. Padding sits inside the
// AEAD and is ignored on receipt, so each side enables it independently.
func WithHeadPadding(n int) Option {
	return func(s *Session) { s.headFrames = n }
}

// headPad picks the padding for a head frame carrying n payload bytes: short
// frames are lifted to a random length in [900, 1400), longer ones get up to
// 255 bytes, and near-full frames are left alone to stay inside one TLS record.
func headPad(n int) int {
	switch {
	case n < 900:
		return 900 + rand.Intn(500) - n
	case n+255 <= maxPayload-64:
		return rand.Intn(256)
	default:
		return 0
	}
}

// NewSession wraps a post-handshake carrier. initiator must be true on the
// client and false on the server. The data phase uses the cipher the handshake
// agreed on (keys.aead); a hand-built Keys with no cipher set defaults to
// AES-256-GCM, matching the zero-dependency reference build.
func NewSession(transport io.ReadWriteCloser, keys *Keys, initiator bool, opts ...Option) (*Session, error) {
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
	s.draining = make(chan struct{})
	for _, o := range opts {
		o(s)
	}
	go s.readLoop()
	go s.keepalive()
	if s.maxLife > 0 {
		go s.drainTimer()
	}
	return s, nil
}

func (s *Session) writeFrame(cmd byte, id uint32, data []byte, pad int) error {
	// IAT shaping: delay small DATA frames by a random interval to blur timing.
	if s.iatMaxMs > 0 && cmd == cmdData && len(data) < 1280 {
		time.Sleep(time.Duration(rand.Intn(s.iatMaxMs)) * time.Millisecond)
	}
	s.wmu.Lock()
	defer s.wmu.Unlock()
	if s.werr != nil {
		return s.werr
	}
	if p := s.shapePad(hdrSize + len(data)); p > pad {
		pad = p
	}
	plainLen := hdrSize + len(data) + pad
	s.wplain = growBuf(s.wplain, plainLen)
	plain := s.wplain[:plainLen]
	plain[0] = cmd
	be.PutUint32(plain[1:5], id)
	be.PutUint16(plain[5:7], uint16(len(data)))
	copy(plain[7:], data)
	// Zero the padding region; bytes are inside the AEAD so an observer cannot
	// tell padding from payload.
	clear(plain[hdrSize+len(data):])

	ct := s.sendAEAD.Seal(s.sendCtr, plain, nil)
	s.sendCtr++

	wireLen := 2 + len(ct)
	s.wout = growBuf(s.wout, wireLen)
	out := s.wout[:wireLen]
	be.PutUint16(out[:2], uint16(len(ct)))
	copy(out[2:], ct)
	if _, err := s.transport.Write(out); err != nil {
		s.werr = err
		return err
	}
	return nil
}

// growBuf returns b resized to n, reusing its backing array when possible.
func growBuf(b []byte, n int) []byte {
	if cap(b) >= n {
		return b[:n]
	}
	return make([]byte, n)
}

// shapePad returns how many pad bytes to add to a frame whose current plaintext
// length is n, per the shaping profile (0 when disabled or n exceeds the top
// bucket).
func (s *Session) shapePad(n int) int {
	for _, b := range s.buckets {
		if n <= b {
			return b - n
		}
	}
	return 0
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
		s.rct = growBuf(s.rct, n)
		ct := s.rct[:n]
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

// drainTimer closes the draining channel after maxLife, signalling that no new
// streams should be opened. Existing streams are unaffected.
func (s *Session) drainTimer() {
	t := time.NewTimer(s.maxLife)
	defer t.Stop()
	select {
	case <-s.done:
		return
	case <-t.C:
		select {
		case <-s.draining:
		default:
			close(s.draining)
		}
	}
}

// Draining reports whether the session has exceeded its max lifetime and is
// refusing new streams. The client dialer should open a fresh session.
func (s *Session) Draining() bool {
	select {
	case <-s.draining:
		return true
	default:
		return false
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
		if s.maxStreams > 0 && len(s.streams) >= s.maxStreams {
			s.mu.Unlock()
			s.writeFrame(cmdRST, id, nil, 0)
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
		if s.maxStreams > 0 && len(s.streams) >= s.maxStreams {
			s.mu.Unlock()
			s.writeFrame(cmdRST, id, nil, 0)
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
			if !st.deliver(append([]byte(nil), data...)) {
				// The peer sent past the window it was granted. A conforming
				// sender cannot do this, so treat it as hostile: buffering it
				// would let one stream exhaust memory.
				s.teardown(ErrFlowControl)
			}
		}
	case cmdWnd:
		if st := s.lookup(id); st != nil && len(data) >= 4 {
			st.addCredit(be.Uint32(data))
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
	if s.Draining() {
		return nil, ErrSessionDraining
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
	if s.maxStreams > 0 && len(s.streams) >= s.maxStreams {
		s.mu.Unlock()
		return nil, ErrTooManyStreams
	}
	id := s.nextID
	s.nextID += 2
	st := s.newStream(id, target)
	s.streams[id] = st
	s.mu.Unlock()

	synPad := 0
	if s.headFrames > 0 {
		// Hide the target's length (a domain name's size) in the SYN.
		synPad = 64 - len(enc)%64 + 64*rand.Intn(2)
	}
	if err := s.writeFrame(cmdSYN, id, enc, synPad); err != nil {
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
	if s.Draining() {
		return nil, ErrSessionDraining
	}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil, s.closeErr
	}
	if s.maxStreams > 0 && len(s.streams) >= s.maxStreams {
		s.mu.Unlock()
		return nil, ErrTooManyStreams
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

	// Close the carrier FIRST: a writeFrame blocked on a stuck transport Write
	// still holds wmu, so acquiring wmu before closing would deadlock teardown
	// against it. Closing unblocks that Write; then we take wmu to latch werr.
	s.transport.Close()

	s.wmu.Lock()
	if s.werr == nil {
		s.werr = err
	}
	s.wmu.Unlock()

	for _, st := range streams {
		st.closeRead(err)
		st.failWrite(err)
	}
}

// Close shuts the session and its carrier down.
func (s *Session) Close() error {
	s.teardown(ErrSessionClosed)
	return nil
}

// Done is closed when the session ends.
func (s *Session) Done() <-chan struct{} { return s.done }

// StreamCount returns the number of currently open streams on the session.
func (s *Session) StreamCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.streams)
}

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
	headLeft  int // head frames still to pad (see WithHeadPadding)

	closeOnce sync.Once
}

func (s *Session) newStream(id uint32, target string) *Stream {
	st := &Stream{id: id, s: s, target: target, sendWin: streamWindow, headLeft: s.headFrames}
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
//
// It returns false if the peer overran the receive window. Bytes the reader
// has consumed but not yet credited back still count against the window, so a
// conforming sender can never have more than streamWindow outstanding.
func (st *Stream) deliver(b []byte) bool {
	st.rmu.Lock()
	defer st.rmu.Unlock()
	if st.readErr != nil {
		return true
	}
	if st.queued+st.consumed+len(b) > streamWindow {
		return false
	}
	st.queue = append(st.queue, b)
	st.queued += len(b)
	st.rcond.Broadcast()
	return true
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

// addCredit grows the send window by a peer-supplied amount. The value is
// untrusted: it is clamped so the window can never exceed streamWindow (or go
// negative on 32-bit targets), whatever the peer sends.
func (st *Stream) addCredit(n uint32) {
	st.wmu.Lock()
	if room := streamWindow - st.sendWin; uint64(n) > uint64(room) {
		st.sendWin = streamWindow
	} else {
		st.sendWin += int(n)
	}
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
		pad := 0
		if st.headLeft > 0 {
			st.headLeft--
			pad = headPad(n)
		}
		st.wmu.Unlock()

		if err := st.s.writeFrame(cmdData, st.id, p[:n], pad); err != nil {
			return total, err
		}
		if sz := st.s.profile.ShouldCover(); sz > 0 {
			_ = st.s.writeFrame(cmdPad, 0, nil, sz)
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
