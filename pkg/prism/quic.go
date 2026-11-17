package prism

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
)

// QUICConn adapts a quic-go QUIC stream to a net.Conn-like ReadWriteCloser
// suitable for running a Prism session on top of.
type QUICConn struct {
	conn   *quic.Conn
	stream *quic.Stream
	mu     sync.Mutex
}

// QUICClientDial establishes a QUIC connection to the server and opens a
// single bidirectional stream for the Prism handshake + data phase.
func QUICClientDial(addr string, tlsCfg *tls.Config, timeout time.Duration) (*QUICConn, error) {
	if tlsCfg.NextProtos == nil {
		tlsCfg = tlsCfg.Clone()
		tlsCfg.NextProtos = []string{"h3", "prism-quic"}
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	conn, err := quic.DialAddr(ctx, addr, tlsCfg, &quic.Config{
		MaxIdleTimeout:  60 * time.Second,
		KeepAlivePeriod: 15 * time.Second,
	})
	if err != nil {
		return nil, err
	}

	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		conn.CloseWithError(0, "stream open failed")
		return nil, err
	}

	return &QUICConn{conn: conn, stream: stream}, nil
}

// QUICServerAccept accepts an incoming QUIC connection and its first stream.
func QUICServerAccept(conn *quic.Conn, timeout time.Duration) (*QUICConn, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	stream, err := conn.AcceptStream(ctx)
	if err != nil {
		return nil, err
	}

	return &QUICConn{conn: conn, stream: stream}, nil
}

func (q *QUICConn) Read(p []byte) (int, error) {
	return q.stream.Read(p)
}

func (q *QUICConn) Write(p []byte) (int, error) {
	return q.stream.Write(p)
}

func (q *QUICConn) Close() error {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.stream.CancelRead(0)
	q.stream.Close()
	return q.conn.CloseWithError(0, "done")
}

func (q *QUICConn) SetDeadline(t time.Time) error {
	return q.stream.SetDeadline(t)
}

func (q *QUICConn) SetReadDeadline(t time.Time) error {
	return q.stream.SetReadDeadline(t)
}

func (q *QUICConn) SetWriteDeadline(t time.Time) error {
	return q.stream.SetWriteDeadline(t)
}

func (q *QUICConn) LocalAddr() net.Addr {
	return q.conn.LocalAddr()
}

func (q *QUICConn) RemoteAddr() net.Addr {
	return q.conn.RemoteAddr()
}

// QUICListener wraps a quic.Listener for the server to accept Prism sessions
// over QUIC.
type QUICListener struct {
	ln *quic.Listener
}

// NewQUICListener creates a QUIC listener on the given address.
func NewQUICListener(addr string, tlsCfg *tls.Config) (*QUICListener, error) {
	if tlsCfg.NextProtos == nil {
		tlsCfg = tlsCfg.Clone()
		tlsCfg.NextProtos = []string{"h3", "prism-quic"}
	}

	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, err
	}
	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return nil, err
	}

	tr := &quic.Transport{Conn: udpConn}
	ln, err := tr.Listen(tlsCfg, &quic.Config{
		MaxIdleTimeout:  60 * time.Second,
		KeepAlivePeriod: 15 * time.Second,
	})
	if err != nil {
		udpConn.Close()
		return nil, err
	}

	return &QUICListener{ln: ln}, nil
}

// Accept waits for and returns an incoming QUIC connection.
func (l *QUICListener) Accept(ctx context.Context) (*quic.Conn, error) {
	return l.ln.Accept(ctx)
}

// Close closes the QUIC listener.
func (l *QUICListener) Close() error {
	return l.ln.Close()
}

// Addr returns the listener's network address.
func (l *QUICListener) Addr() net.Addr {
	return l.ln.Addr()
}

// ErrQUICNotAvailable is returned when QUIC transport is not configured.
var ErrQUICNotAvailable = errors.New("prism: QUIC transport not available")

// Ensure QUICConn satisfies io.ReadWriteCloser.
var _ io.ReadWriteCloser = (*QUICConn)(nil)
