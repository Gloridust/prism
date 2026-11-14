// Package mux 在单条有序可靠连接（如 prism.Conn）之上提供多路复用逻辑流，
// 带基于信用的流量控制。见 docs/PROTOCOL.md §6。
package mux

import (
	"encoding/binary"
	"errors"
	"io"
	"sync"
)

// 帧命令
const (
	cmdSYN = 1 // 新建流
	cmdPSH = 2 // 数据
	cmdFIN = 3 // 半关闭（写方向结束）
	cmdRST = 4 // 强制关闭
	cmdWND = 5 // 窗口信用更新
	cmdNOP = 6 // 保活/填充
)

const (
	headerSize    = 7
	InitialWindow = 262144 // 每流初始接收窗口 256KiB
	MaxFrame      = 16384  // 单个 PSH 载荷上限
	wndThreshold  = InitialWindow / 2
)

var (
	ErrSessionClosed = errors.New("mux: session closed")
	ErrStreamClosed  = errors.New("mux: stream closed")
	ErrStreamReset   = errors.New("mux: stream reset by peer")
)

// Session 管理一条底层连接上的所有逻辑流。
type Session struct {
	conn    io.ReadWriteCloser
	writeMu sync.Mutex

	mu      sync.Mutex
	streams map[uint32]*Stream
	nextID  uint32
	err     error

	acceptCh chan *Stream
	die      chan struct{}
	dieOnce  sync.Once
}

// Client / Server 分别用奇数、偶数流 ID，避免双向开流冲突。
func Client(conn io.ReadWriteCloser) *Session { return newSession(conn, 1) }
func Server(conn io.ReadWriteCloser) *Session { return newSession(conn, 2) }

func newSession(conn io.ReadWriteCloser, firstID uint32) *Session {
	s := &Session{
		conn:     conn,
		streams:  make(map[uint32]*Stream),
		nextID:   firstID,
		acceptCh: make(chan *Stream, 256),
		die:      make(chan struct{}),
	}
	go s.recvLoop()
	return s
}

// OpenStream 发起一条新流。
func (s *Session) OpenStream() (*Stream, error) {
	s.mu.Lock()
	select {
	case <-s.die:
		err := s.err
		s.mu.Unlock()
		if err == nil {
			err = ErrSessionClosed
		}
		return nil, err
	default:
	}
	id := s.nextID
	s.nextID += 2
	st := newStream(id, s)
	s.streams[id] = st
	s.mu.Unlock()

	if err := s.writeFrame(id, cmdSYN, nil); err != nil {
		s.removeStream(id)
		return nil, err
	}
	return st, nil
}

// AcceptStream 接收对端发起的流。
func (s *Session) AcceptStream() (*Stream, error) {
	select {
	case st := <-s.acceptCh:
		return st, nil
	case <-s.die:
		if s.err != nil {
			return nil, s.err
		}
		return nil, ErrSessionClosed
	}
}

func (s *Session) Close() error {
	s.closeWith(ErrSessionClosed)
	return nil
}

func (s *Session) getStream(id uint32) *Stream {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.streams[id]
}

func (s *Session) removeStream(id uint32) {
	s.mu.Lock()
	delete(s.streams, id)
	s.mu.Unlock()
}

func (s *Session) closeWith(err error) {
	s.dieOnce.Do(func() {
		s.mu.Lock()
		s.err = err
		sts := make([]*Stream, 0, len(s.streams))
		for _, st := range s.streams {
			sts = append(sts, st)
		}
		s.mu.Unlock()
		close(s.die)
		for _, st := range sts {
			st.sessionClosed(err)
		}
		s.conn.Close()
	})
}

func (s *Session) writeFrame(id uint32, cmd byte, payload []byte) error {
	if len(payload) > 65535 {
		return errors.New("mux: frame too large")
	}
	s.writeMu.Lock()
	defer s.writeMu.Unlock()

	buf := make([]byte, headerSize+len(payload))
	binary.BigEndian.PutUint32(buf[0:4], id)
	buf[4] = cmd
	binary.BigEndian.PutUint16(buf[5:7], uint16(len(payload)))
	copy(buf[headerSize:], payload)

	if _, err := s.conn.Write(buf); err != nil {
		s.closeWith(err)
		return err
	}
	return nil
}

func (s *Session) recvLoop() {
	var hdr [headerSize]byte
	for {
		if _, err := io.ReadFull(s.conn, hdr[:]); err != nil {
			s.closeWith(err)
			return
		}
		id := binary.BigEndian.Uint32(hdr[0:4])
		cmd := hdr[4]
		length := int(binary.BigEndian.Uint16(hdr[5:7]))
		var payload []byte
		if length > 0 {
			payload = make([]byte, length)
			if _, err := io.ReadFull(s.conn, payload); err != nil {
				s.closeWith(err)
				return
			}
		}
		s.dispatch(id, cmd, payload)
	}
}

func (s *Session) dispatch(id uint32, cmd byte, payload []byte) {
	switch cmd {
	case cmdSYN:
		s.mu.Lock()
		if _, ok := s.streams[id]; ok {
			s.mu.Unlock()
			return
		}
		st := newStream(id, s)
		s.streams[id] = st
		s.mu.Unlock()
		select {
		case s.acceptCh <- st:
		case <-s.die:
			s.removeStream(id)
		}
	case cmdPSH:
		if st := s.getStream(id); st != nil {
			st.pushData(payload)
		} else {
			s.writeFrame(id, cmdRST, nil)
		}
	case cmdFIN:
		if st := s.getStream(id); st != nil {
			st.pushFIN()
		}
	case cmdRST:
		if st := s.getStream(id); st != nil {
			st.reset()
			s.removeStream(id)
		}
	case cmdWND:
		if st := s.getStream(id); st != nil && len(payload) >= 4 {
			st.addWindow(int(binary.BigEndian.Uint32(payload)))
		}
	case cmdNOP:
		// 保活/填充：忽略
	}
}
