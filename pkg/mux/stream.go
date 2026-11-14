package mux

import (
	"encoding/binary"
	"io"
	"sync"
)

// Stream 是一条逻辑流，满足 io.ReadWriteCloser，并提供 CloseWrite 半关闭。
type Stream struct {
	id   uint32
	sess *Session

	// 接收侧
	rmu      sync.Mutex
	rcond    *sync.Cond
	rbuf     []byte
	rErr     error // 被 RST / 会话关闭 时置位
	finRecv  bool  // 收到对端 FIN
	consumed int   // 自上次窗口更新以来已消费字节

	// 发送侧（流量控制）
	wmu     sync.Mutex
	wcond   *sync.Cond
	sendWin int // 可发送信用
	wErr    error
	finSent bool
	closed  bool
}

func newStream(id uint32, sess *Session) *Stream {
	st := &Stream{id: id, sess: sess, sendWin: InitialWindow}
	st.rcond = sync.NewCond(&st.rmu)
	st.wcond = sync.NewCond(&st.wmu)
	return st
}

// ID 返回流标识。
func (st *Stream) ID() uint32 { return st.id }

// --- 接收侧回调（由 recvLoop 调用）---

func (st *Stream) pushData(data []byte) {
	st.rmu.Lock()
	if st.rErr == nil && !st.finRecv {
		st.rbuf = append(st.rbuf, data...)
	}
	st.rcond.Broadcast()
	st.rmu.Unlock()
}

func (st *Stream) pushFIN() {
	st.rmu.Lock()
	st.finRecv = true
	st.rcond.Broadcast()
	st.rmu.Unlock()
}

func (st *Stream) reset() {
	st.rmu.Lock()
	if st.rErr == nil {
		st.rErr = ErrStreamReset
	}
	st.rcond.Broadcast()
	st.rmu.Unlock()

	st.wmu.Lock()
	if st.wErr == nil {
		st.wErr = ErrStreamReset
	}
	st.wcond.Broadcast()
	st.wmu.Unlock()
}

func (st *Stream) sessionClosed(err error) {
	st.rmu.Lock()
	if st.rErr == nil {
		st.rErr = err
	}
	st.rcond.Broadcast()
	st.rmu.Unlock()

	st.wmu.Lock()
	if st.wErr == nil {
		st.wErr = err
	}
	st.wcond.Broadcast()
	st.wmu.Unlock()
}

func (st *Stream) addWindow(n int) {
	st.wmu.Lock()
	st.sendWin += n
	st.wcond.Broadcast()
	st.wmu.Unlock()
}

// --- io 接口 ---

func (st *Stream) Read(p []byte) (int, error) {
	st.rmu.Lock()
	for len(st.rbuf) == 0 {
		if st.rErr != nil {
			err := st.rErr
			st.rmu.Unlock()
			return 0, err
		}
		if st.finRecv {
			st.rmu.Unlock()
			return 0, io.EOF
		}
		st.rcond.Wait()
	}
	n := copy(p, st.rbuf)
	st.rbuf = st.rbuf[n:]
	st.consumed += n
	var credit int
	if st.consumed >= wndThreshold {
		credit = st.consumed
		st.consumed = 0
	}
	st.rmu.Unlock()

	if credit > 0 {
		var b [4]byte
		binary.BigEndian.PutUint32(b[:], uint32(credit))
		st.sess.writeFrame(st.id, cmdWND, b[:]) // 出错由会话关闭统一处理
	}
	return n, nil
}

func (st *Stream) Write(p []byte) (int, error) {
	total := 0
	for len(p) > 0 {
		st.wmu.Lock()
		for st.sendWin == 0 && st.wErr == nil && !st.closed && !st.finSent {
			st.wcond.Wait()
		}
		if st.wErr != nil {
			err := st.wErr
			st.wmu.Unlock()
			return total, err
		}
		if st.closed || st.finSent {
			st.wmu.Unlock()
			return total, ErrStreamClosed
		}
		n := len(p)
		if n > st.sendWin {
			n = st.sendWin
		}
		if n > MaxFrame {
			n = MaxFrame
		}
		st.sendWin -= n
		st.wmu.Unlock()

		if err := st.sess.writeFrame(st.id, cmdPSH, p[:n]); err != nil {
			return total, err
		}
		p = p[n:]
		total += n
	}
	return total, nil
}

// CloseWrite 发送 FIN，半关闭写方向；读方向仍可继续。
func (st *Stream) CloseWrite() error {
	st.wmu.Lock()
	if st.finSent || st.closed {
		st.wmu.Unlock()
		return nil
	}
	st.finSent = true
	st.wcond.Broadcast()
	st.wmu.Unlock()
	return st.sess.writeFrame(st.id, cmdFIN, nil)
}

// Close 关闭流。若写方向未经 FIN 正常结束，则发送 RST 通知对端中止。
func (st *Stream) Close() error {
	st.wmu.Lock()
	wasFin := st.finSent
	st.closed = true
	st.wcond.Broadcast()
	st.wmu.Unlock()

	st.rmu.Lock()
	if st.rErr == nil {
		st.rErr = ErrStreamClosed
	}
	st.rcond.Broadcast()
	st.rmu.Unlock()

	st.sess.removeStream(st.id)
	if !wasFin {
		return st.sess.writeFrame(st.id, cmdRST, nil)
	}
	return nil
}
