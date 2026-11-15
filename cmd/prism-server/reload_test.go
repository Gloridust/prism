package main

import (
	"encoding/json"
	"net"
	"os"
	"testing"
	"time"

	"github.com/gloridust/prism/pkg/prism"
)

func fakeSession(t *testing.T) *prism.Session {
	t.Helper()
	a, _ := net.Pipe()
	s, err := prism.NewSession(a, &prism.Keys{Send: make([]byte, 32), Recv: make([]byte, 32)}, false)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func isClosed(s *prism.Session) bool {
	select {
	case <-s.Done():
		return true
	case <-time.After(time.Second):
		return false
	}
}

// reload must kick sessions whose credential was removed and spare the rest.
func TestReloadKicksRevoked(t *testing.T) {
	kp, _ := prism.GenerateServerKeypair()
	idA := prism.ClientID{1, 1, 1, 1}
	idB := prism.ClientID{2, 2, 2, 2}
	pskB, _ := prism.NewPSK()

	// New config keeps only credential B.
	cfg := Config{
		Listen:     ":0",
		PrivateKey: prism.EncodeKey(kp.Private.Bytes()),
		Credentials: []CredConfig{
			{Name: "B", ID: prism.EncodeKey(idB[:]), PSK: prism.EncodeKey(pskB)},
		},
	}
	path := t.TempDir() + "/s.json"
	raw, _ := json.Marshal(cfg)
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}

	s := &server{cfgPath: path, active: map[*sessConn]struct{}{}}
	sa, sb := fakeSession(t), fakeSession(t)
	defer sa.Close()
	defer sb.Close()
	s.register(&sessConn{sess: sa, id: idA}) // revoked
	s.register(&sessConn{sess: sb, id: idB}) // still valid

	s.reload()

	if !isClosed(sa) {
		t.Error("session with revoked credential A was not kicked")
	}
	if isClosed(sb) {
		t.Error("session with valid credential B was wrongly kicked")
	}
}
