package main

import (
	"bytes"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gloridust/prism/pkg/prism"
)

func TestMeterQuotaAndDailyReset(t *testing.T) {
	m := &meter{}
	if !m.add(1<<30, 1<<30) {
		t.Fatal("unlimited meter refused traffic")
	}
	m.quota.Store(1000)
	m.mu.Lock()
	m.dayUsed = 0
	m.mu.Unlock()
	if !m.add(400, 500) {
		t.Fatal("900/1000 should still be within quota")
	}
	if m.add(100, 0) {
		t.Fatal("reaching the quota should cut the client off")
	}
	if m.allowed() {
		t.Fatal("over-quota meter reports allowed")
	}
	// A new UTC day starts from zero.
	m.mu.Lock()
	m.day--
	m.mu.Unlock()
	if !m.allowed() || m.usedToday() != 0 {
		t.Fatal("quota did not reset on day rollover")
	}
}

func TestCopyMeteredStopsAtQuota(t *testing.T) {
	m := &meter{}
	m.quota.Store(100_000)
	var dst bytes.Buffer
	copyMetered(&dst, bytes.NewReader(make([]byte, 1<<20)), func(n int64) bool { return m.add(n, 0) })
	if dst.Len() >= 1<<20 || dst.Len() < 100_000 {
		t.Fatalf("copied %d bytes with a 100k quota", dst.Len())
	}
}

// The cover path must return when the visitor's connection ends; it used to
// park forever in Accept, leaking a goroutine per unauthenticated connection.
func TestServeCoverReturns(t *testing.T) {
	for name, req := range map[string]string{
		"close":      "GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
		"keep-alive": "GET / HTTP/1.1\r\nHost: x\r\n\r\n",
		"garbage":    "\x00\x01\x02 not http at all\r\n\r\n",
	} {
		t.Run(name, func(t *testing.T) {
			cl, sv := net.Pipe()
			done := make(chan struct{})
			go func() {
				serveCover(sv, []byte(req[:5]), coverHandler(&Config{}))
				close(done)
			}()
			go func() {
				cl.Write([]byte(req[5:]))
				cl.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
				io.Copy(io.Discard, cl)
				cl.Close()
			}()
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Fatal("serveCover never returned after the client went away")
			}
		})
	}
}

func testServer(t *testing.T, withStore bool) (*server, *adminAPI) {
	t.Helper()
	kp, _ := prism.GenerateServerKeypair()
	psk, _ := prism.NewPSK()
	ccs := []CredConfig{{Name: "a", ID: "AQEBAQ==", PSK: prism.EncodeKey(psk)}}
	creds, _ := parseCreds(ccs)
	s := &server{priv: kp.Private, creds: creds, credCfgs: ccs, acct: newAccounting(), active: map[*sessConn]struct{}{}}
	if withStore {
		s.credsFile = filepath.Join(t.TempDir(), "creds.json")
	}
	return s, newAdminAPI(s, "0123456789abcdef-token")
}

func adminDo(a *adminAPI, method, path, token, body string) (int, string) {
	req, _ := http.NewRequest(method, path, strings.NewReader(body))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := &respRecorder{h: http.Header{}, code: 200}
	a.mux().ServeHTTP(rec, req)
	return rec.code, rec.body.String()
}

type respRecorder struct {
	h    http.Header
	code int
	body bytes.Buffer
}

func (r *respRecorder) Header() http.Header         { return r.h }
func (r *respRecorder) WriteHeader(c int)           { r.code = c }
func (r *respRecorder) Write(b []byte) (int, error) { return r.body.Write(b) }

func TestAdminAuth(t *testing.T) {
	_, a := testServer(t, true)
	for _, tok := range []string{"", "wrong", "0123456789abcdef-toke"} {
		if code, _ := adminDo(a, "GET", "/api/credentials", tok, ""); code != http.StatusUnauthorized {
			t.Errorf("token %q got %d", tok, code)
		}
	}
	if code, _ := adminDo(a, "GET", "/api/credentials", a.token, ""); code != 200 {
		t.Errorf("valid token got %d", code)
	}
	if code, _ := adminDo(a, "GET", "/api/credentials/revoke", a.token, ""); code != http.StatusMethodNotAllowed {
		t.Errorf("GET on a mutating endpoint got %d", code)
	}
	// An API with no token configured must never authenticate anyone.
	open := newAdminAPI(a.srv, "")
	if code, _ := adminDo(open, "GET", "/api/credentials", "", ""); code != http.StatusUnauthorized {
		t.Errorf("empty-token API accepted an empty bearer: %d", code)
	}
}

func TestAdminRefusesUnpersistedChanges(t *testing.T) {
	s, a := testServer(t, false)
	code, _ := adminDo(a, "POST", "/api/credentials/revoke", a.token, `{"id":"AQEBAQ=="}`)
	if code != http.StatusConflict {
		t.Fatalf("revoke without a credentials file got %d, want 409", code)
	}
	if len(s.snapshotCreds()) != 1 {
		t.Fatal("credential list changed despite the refusal")
	}
}

func TestAdminMutationsPersistAndKick(t *testing.T) {
	s, a := testServer(t, true)
	sess := fakeSession(t)
	defer sess.Close()
	s.register(&sessConn{sess: sess, id: prism.ClientID{1, 1, 1, 1}})

	// Rotation kicks the session still authenticated under the old PSK.
	code, body := adminDo(a, "POST", "/api/credentials/rotate", a.token, `{"id":"AQEBAQ=="}`)
	if code != 200 || !strings.Contains(body, "new_psk") {
		t.Fatalf("rotate: %d %s", code, body)
	}
	if !isClosed(sess) {
		t.Fatal("session under the rotated PSK was not kicked")
	}

	code, body = adminDo(a, "POST", "/api/credentials/add", a.token, `{"name":"b","max_bytes_per_day":5}`)
	if code != 200 {
		t.Fatalf("add: %d %s", code, body)
	}
	if code, _ := adminDo(a, "POST", "/api/credentials/revoke", a.token, `{"id":"AQEBAQ=="}`); code != 200 {
		t.Fatalf("revoke: %d", code)
	}
	if code, _ := adminDo(a, "POST", "/api/credentials/revoke", a.token, `{"id":"AQEBAQ=="}`); code != http.StatusNotFound {
		t.Fatalf("second revoke got %d, want 404", code)
	}

	// What is on disk is exactly what a restart would load.
	fi, err := os.Stat(s.credsFile)
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("credentials file: %v mode %v", err, fi.Mode())
	}
	loaded, err := loadCredConfigs(&Config{CredentialsFile: s.credsFile})
	if err != nil || len(loaded) != 1 || loaded[0].Name != "b" || loaded[0].MaxBytesPerDay != 5 {
		t.Fatalf("persisted = %+v, %v", loaded, err)
	}
	id, _ := prism.ParseClientID(loaded[0].ID)
	if s.acct.meter(id).quota.Load() != 5 {
		t.Fatal("quota from the new credential not applied")
	}
}

func TestCredentialsFileSeedAndReload(t *testing.T) {
	psk, _ := prism.NewPSK()
	path := filepath.Join(t.TempDir(), "creds.json")
	inline := []CredConfig{{Name: "seed", ID: "AQEBAQ==", PSK: prism.EncodeKey(psk)}}

	got, err := loadCredConfigs(&Config{Credentials: inline, CredentialsFile: path})
	if err != nil || len(got) != 1 {
		t.Fatalf("seed: %v %v", got, err)
	}
	// Once the file exists it wins over the inline list (so a revocation holds).
	saveCredConfigs(path, nil)
	got, err = loadCredConfigs(&Config{Credentials: inline, CredentialsFile: path})
	if err != nil || len(got) != 0 {
		t.Fatalf("file should override inline credentials, got %v %v", got, err)
	}
}

func TestSelfSignedSizedMatchesTarget(t *testing.T) {
	for _, size := range []int{0, 900, 2500, 4321, 6000} {
		cert, err := selfSignedSized("www.example.com", size)
		if err != nil {
			t.Fatal(err)
		}
		got := len(cert.Certificate[0])
		if size > 600 && (got < size-2 || got > size+2) {
			t.Errorf("asked for a %d-byte certificate, got %d", size, got)
		}
	}
}
