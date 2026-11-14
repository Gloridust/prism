package prism

import (
	"bytes"
	"crypto/rand"
	"io"
	"net"
	"sync"
	"testing"
)

func mustKey(t *testing.T) ([]byte, []byte) {
	t.Helper()
	k, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	return k.Bytes(), k.PublicKey().Bytes()
}

func TestHandshakeAndRecordRoundTrip(t *testing.T) {
	psk := make([]byte, 32)
	rand.Read(psk)
	sPriv, sPub := mustKey(t)
	cPriv, cPub := mustKey(t)

	serverPriv, _ := ParsePrivateKey(sPriv)
	serverPub, _ := ParsePublicKey(sPub)
	clientPriv, _ := ParsePrivateKey(cPriv)

	c1, c2 := net.Pipe()
	replay := NewReplayCache(0)

	var wg sync.WaitGroup
	wg.Add(1)
	var serverErr error
	var srvConn *Conn

	go func() {
		defer wg.Done()
		allowed := func(pub []byte) bool { return bytes.Equal(pub, cPub) }
		res, _, err := ServerHandshake(c2, psk, serverPriv, allowed, replay)
		if err != nil {
			serverErr = err
			return
		}
		srvConn, serverErr = NewConn(c2, res)
	}()

	res, err := ClientHandshake(c1, psk, serverPub, clientPriv)
	if err != nil {
		t.Fatalf("client handshake: %v", err)
	}
	wg.Wait()
	if serverErr != nil {
		t.Fatalf("server handshake: %v", serverErr)
	}

	// 身份校验：服务器应看到客户端静态公钥
	if !bytes.Equal(srvConn.PeerStatic, cPub) {
		t.Fatalf("server saw wrong client identity")
	}
	// 会话 ID 两端一致
	if !bytes.Equal(res.SessionID, srvConn.SessionID) {
		t.Fatalf("session id mismatch")
	}

	cliConn, err := NewConn(c1, res)
	if err != nil {
		t.Fatal(err)
	}

	// 双向数据：客户端 -> 服务器
	payload := make([]byte, 100000)
	rand.Read(payload)
	go func() {
		cliConn.Write(payload)
		cliConn.Write([]byte("PING"))
	}()

	got := make([]byte, len(payload))
	if _, err := io.ReadFull(srvConn, got); err != nil {
		t.Fatalf("server read: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("payload mismatch")
	}
	ping := make([]byte, 4)
	io.ReadFull(srvConn, ping)
	if string(ping) != "PING" {
		t.Fatalf("ping mismatch: %q", ping)
	}

	// 服务器 -> 客户端
	go func() { srvConn.Write([]byte("PONG")) }()
	pong := make([]byte, 4)
	io.ReadFull(cliConn, pong)
	if string(pong) != "PONG" {
		t.Fatalf("pong mismatch: %q", pong)
	}
}

func TestReplayRejected(t *testing.T) {
	r := NewReplayCache(0)
	eph := make([]byte, 32)
	rand.Read(eph)
	if !r.Add(eph) {
		t.Fatal("first add should succeed")
	}
	if r.Add(eph) {
		t.Fatal("replay should be rejected")
	}
}

func TestWrongPSKFails(t *testing.T) {
	psk := make([]byte, 32)
	rand.Read(psk)
	badPSK := make([]byte, 32)
	rand.Read(badPSK)
	sPriv, sPub := mustKey(t)
	cPriv, cPub := mustKey(t)
	serverPriv, _ := ParsePrivateKey(sPriv)
	serverPub, _ := ParsePublicKey(sPub)
	clientPriv, _ := ParsePrivateKey(cPriv)

	c1, c2 := net.Pipe()
	done := make(chan error, 1)
	go func() {
		allowed := func(pub []byte) bool { return bytes.Equal(pub, cPub) }
		_, _, err := ServerHandshake(c2, psk, serverPriv, allowed, NewReplayCache(0))
		done <- err
	}()
	// 客户端用错误 PSK；服务器应认证失败
	go ClientHandshake(c1, badPSK, serverPub, clientPriv)
	if err := <-done; err == nil {
		t.Fatal("expected handshake failure with wrong PSK")
	}
}
