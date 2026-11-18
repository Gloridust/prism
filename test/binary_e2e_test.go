package e2e

// End-to-end tests of the real prism-server and prism-client binaries. Unlike
// the in-process tests, which re-create a server from library calls, these
// build both commands and drive traffic through them exactly as deployed:
// app → SOCKS5 → prism-client → carrier → prism-server → target.

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/quic-go/quic-go/http3"

	"github.com/gloridust/prism/pkg/prism"
)

var (
	buildOnce sync.Once
	buildDir  string
	buildErr  error
)

func binaries(t *testing.T) (server, client string) {
	t.Helper()
	if testing.Short() {
		t.Skip("binary e2e skipped in -short mode")
	}
	buildOnce.Do(func() {
		buildDir, buildErr = os.MkdirTemp("", "prism-bin-")
		if buildErr != nil {
			return
		}
		for _, name := range []string{"prism-server", "prism-client"} {
			out := filepath.Join(buildDir, name+exeSuffix())
			cmd := exec.Command("go", "build", "-o", out, "../cmd/"+name)
			if b, err := cmd.CombinedOutput(); err != nil {
				buildErr = fmt.Errorf("build %s: %v\n%s", name, err, b)
				return
			}
		}
	})
	if buildErr != nil {
		t.Fatal(buildErr)
	}
	return filepath.Join(buildDir, "prism-server"+exeSuffix()), filepath.Join(buildDir, "prism-client"+exeSuffix())
}

func exeSuffix() string {
	if runtime.GOOS == "windows" {
		return ".exe"
	}
	return ""
}

func TestMain(m *testing.M) {
	code := m.Run()
	if buildDir != "" {
		os.RemoveAll(buildDir)
	}
	os.Exit(code)
}

func freeTCP(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().String()
}

// logBuf collects a child's output and prints it only if the test fails.
type logBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *logBuf) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *logBuf) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

func start(t *testing.T, name, bin, cfgPath string) *logBuf {
	t.Helper()
	_, out := startProc(t, name, bin, cfgPath)
	return out
}

func startProc(t *testing.T, name, bin, cfgPath string) (*exec.Cmd, *logBuf) {
	t.Helper()
	out := &logBuf{}
	cmd := exec.Command(bin, "-c", cfgPath)
	cmd.Stdout, cmd.Stderr = out, out
	if err := cmd.Start(); err != nil {
		t.Fatalf("start %s: %v", name, err)
	}
	t.Cleanup(func() {
		cmd.Process.Kill()
		cmd.Wait()
		if t.Failed() || os.Getenv("PRISM_E2E_LOGS") != "" {
			t.Logf("---- %s output ----\n%s", name, out.String())
		}
	})
	return cmd, out
}

func waitTCP(t *testing.T, addr string) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if c, err := net.DialTimeout("tcp", addr, 200*time.Millisecond); err == nil {
			c.Close()
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("%s never came up", addr)
}

func writeJSONFile(t *testing.T, path string, v any) {
	t.Helper()
	raw, _ := json.MarshalIndent(v, "", "  ")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
}

// deployment is one running server + client pair.
type deployment struct {
	t          *testing.T
	dir        string
	serverAddr string
	socks      string
	admin      string
	token      string
	id, psk    string
	pub        string
	serverLog  *logBuf
	clientLog  *logBuf
	clientBin  string
	clientBase map[string]any
}

type deployOpts struct {
	transport string // "", "ws", "quic"
	handshake string // "", "noise"
	cipher    string
	steal     string // steal dest ("" = off)
	shaping   string
}

func deploy(t *testing.T, o deployOpts) *deployment {
	t.Helper()
	serverBin, clientBin := binaries(t)
	dir := t.TempDir()

	kp, _ := prism.GenerateServerKeypair()
	psk, _ := prism.NewPSK()
	id, _ := prism.NewClientID()
	d := &deployment{
		t: t, dir: dir, serverAddr: freeTCP(t), socks: freeTCP(t), admin: freeTCP(t),
		token: "test-admin-token-0123456789", clientBin: clientBin,
		id: prism.EncodeKey(id[:]), psk: prism.EncodeKey(psk), pub: prism.EncodeKey(kp.Public.Bytes()),
	}

	srv := map[string]any{
		"listen":           d.serverAddr,
		"self_signed":      "localhost",
		"private_key":      prism.EncodeKey(kp.Private.Bytes()),
		"credentials":      []map[string]any{{"name": "e2e", "id": d.id, "psk": d.psk}},
		"credentials_file": filepath.Join(dir, "credentials.json"),
		"ciphers":          []string{"aes-256-gcm", "chacha20-poly1305"},
		"allow_private":    true, // targets are on loopback
		"handshake":        o.handshake,
		"shaping":          o.shaping,
		"admin":            map[string]any{"listen": d.admin, "token": d.token},
	}
	if o.transport == "ws" {
		srv["ws_path"] = "/_prism/ws"
	}
	if o.transport == "quic" {
		srv["quic_listen"] = d.serverAddr // same port number, UDP
	}
	if o.steal != "" {
		srv["steal"] = map[string]any{"dest": o.steal, "server_names": []string{"localhost"}}
		delete(srv, "self_signed")
	}
	writeJSONFile(t, filepath.Join(dir, "server.json"), srv)
	d.serverLog = start(t, "prism-server", serverBin, filepath.Join(dir, "server.json"))
	waitTCP(t, d.serverAddr)
	waitTCP(t, d.admin)

	d.clientBase = map[string]any{
		"server": d.serverAddr, "sni": "localhost", "server_public_key": d.pub,
		"id": d.id, "psk": d.psk, "allow_insecure": true,
		"mode": "router", "socks_listen": d.socks, "pool_size": 2,
		"transport": o.transport, "handshake": o.handshake, "cipher": o.cipher,
		"steal": o.steal != "", "shaping": o.shaping,
	}
	if o.transport == "ws" {
		d.clientBase["ws_path"] = "/_prism/ws"
	}
	writeJSONFile(t, filepath.Join(dir, "client.json"), d.clientBase)
	d.clientLog = start(t, "prism-client", clientBin, filepath.Join(dir, "client.json"))
	waitTCP(t, d.socks)
	return d
}

// socksConnect opens a TCP connection to target through the client's SOCKS5.
func socksConnect(socks, target string) (net.Conn, error) {
	c, err := net.DialTimeout("tcp", socks, 5*time.Second)
	if err != nil {
		return nil, err
	}
	c.SetDeadline(time.Now().Add(20 * time.Second))
	host, portStr, _ := net.SplitHostPort(target)
	var port uint16
	fmt.Sscan(portStr, &port)
	req := []byte{5, 1, 0, 5, 1, 0, 3, byte(len(host))}
	req = append(req, host...)
	req = binary.BigEndian.AppendUint16(req, port)
	if _, err := c.Write(req); err != nil {
		c.Close()
		return nil, err
	}
	rep := make([]byte, 2+10)
	if _, err := io.ReadFull(c, rep); err != nil {
		c.Close()
		return nil, fmt.Errorf("socks reply: %w", err)
	}
	if rep[3] != 0 {
		c.Close()
		return nil, fmt.Errorf("socks connect refused: code %d", rep[3])
	}
	return c, nil
}

func tcpEchoServer(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); io.Copy(c, c) }()
		}
	}()
	return ln.Addr().String()
}

func udpEchoServer(t *testing.T) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close() })
	go func() {
		buf := make([]byte, 65535)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			pc.WriteTo(buf[:n], from)
		}
	}()
	return pc.LocalAddr().String()
}

// echoThrough pushes size random-ish bytes through the tunnel and back.
func echoThrough(t *testing.T, socks, target string, size int) {
	t.Helper()
	var c net.Conn
	var err error
	for i := 0; i < 20; i++ { // the first carrier dial may still be in flight
		if c, err = socksConnect(socks, target); err == nil {
			break
		}
		time.Sleep(250 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("connect through tunnel: %v", err)
	}
	defer c.Close()
	payload := make([]byte, size)
	for i := range payload {
		payload[i] = byte(i*31 + i>>8)
	}
	go func() { c.Write(payload) }()
	got := make([]byte, size)
	if _, err := io.ReadFull(c, got); err != nil {
		t.Fatalf("echo read: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("payload corrupted through the tunnel")
	}
}

func udpThrough(t *testing.T, socks, target string) {
	t.Helper()
	ctrl, err := net.DialTimeout("tcp", socks, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer ctrl.Close()
	ctrl.SetDeadline(time.Now().Add(20 * time.Second))
	ctrl.Write([]byte{5, 1, 0, 5, 3, 0, 1, 0, 0, 0, 0, 0, 0})
	rep := make([]byte, 2+10)
	if _, err := io.ReadFull(ctrl, rep); err != nil || rep[3] != 0 {
		t.Fatalf("udp associate: %v %v", err, rep)
	}
	relay := &net.UDPAddr{IP: net.IP(rep[6:10]), Port: int(binary.BigEndian.Uint16(rep[10:12]))}

	uc, err := net.DialUDP("udp", nil, relay)
	if err != nil {
		t.Fatal(err)
	}
	defer uc.Close()
	ta, _ := net.ResolveUDPAddr("udp", target)
	msg := []byte("udp through the real binaries")
	pkt := append([]byte{0, 0, 0, 1}, ta.IP.To4()...)
	pkt = binary.BigEndian.AppendUint16(pkt, uint16(ta.Port))
	pkt = append(pkt, msg...)

	buf := make([]byte, 2048)
	for i := 0; i < 10; i++ {
		uc.Write(pkt)
		uc.SetReadDeadline(time.Now().Add(time.Second))
		n, err := uc.Read(buf)
		if err == nil {
			if !bytes.HasSuffix(buf[:n], msg) {
				t.Fatalf("udp reply = %q", buf[:n])
			}
			return
		}
	}
	t.Fatal("no UDP reply through the tunnel")
}

func (d *deployment) adminCall(method, path string, body any) (int, []byte) {
	d.t.Helper()
	var rd io.Reader
	if body != nil {
		raw, _ := json.Marshal(body)
		rd = bytes.NewReader(raw)
	}
	req, _ := http.NewRequest(method, "http://"+d.admin+path, rd)
	req.Header.Set("Authorization", "Bearer "+d.token)
	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		d.t.Fatalf("admin %s: %v", path, err)
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, out
}

// TestBinariesTransportMatrix runs every carrier × handshake × cipher
// combination through the shipped binaries.
func TestBinariesTransportMatrix(t *testing.T) {
	cases := []deployOpts{
		{},
		{handshake: "noise", cipher: "chacha20-poly1305"},
		{transport: "ws", shaping: "pad"},
		{transport: "ws", handshake: "noise"},
		{transport: "quic"},
		{transport: "quic", handshake: "noise", cipher: "chacha20-poly1305"},
	}
	for _, o := range cases {
		name := fmt.Sprintf("transport=%s/handshake=%s/cipher=%s", orDefault(o.transport, "tls"), orDefault(o.handshake, "legacy"), orDefault(o.cipher, "aes"))
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			d := deploy(t, o)
			tcp, udp := tcpEchoServer(t), udpEchoServer(t)
			echoThrough(t, d.socks, tcp, 2<<20)
			var wg sync.WaitGroup
			for i := 0; i < 12; i++ {
				wg.Add(1)
				go func(n int) { defer wg.Done(); echoThrough(t, d.socks, tcp, 20000+n*3333) }(i)
			}
			wg.Wait()
			udpThrough(t, d.socks, udp)
		})
	}
}

func orDefault(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

// fakeRealSite is the TLS site a steal-mode server relays strangers to.
func fakeRealSite(t *testing.T) string {
	t.Helper()
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{selfSignedCert(t)}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go http.Serve(ln, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "the real site")
	}))
	return ln.Addr().String()
}

func httpsGet(t *testing.T, addr string, protos ...string) (body string, proto string, cn string) {
	t.Helper()
	tr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true, NextProtos: protos}, ForceAttemptHTTP2: len(protos) > 0 && protos[0] == "h2"}
	defer tr.CloseIdleConnections()
	resp, err := (&http.Client{Transport: tr, Timeout: 10 * time.Second}).Get("https://" + addr + "/")
	if err != nil {
		t.Fatalf("GET https://%s: %v", addr, err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return string(b), resp.Proto, resp.TLS.PeerCertificates[0].Subject.CommonName
}

// TestBinariesStealMode: marked clients tunnel (under both handshakes); anyone
// else is relayed to the real site and sees its certificate and content.
func TestBinariesStealMode(t *testing.T) {
	for _, hs := range []string{"", "noise"} {
		t.Run("handshake="+orDefault(hs, "legacy"), func(t *testing.T) {
			t.Parallel()
			site := fakeRealSite(t)
			d := deploy(t, deployOpts{steal: site, handshake: hs})
			echoThrough(t, d.socks, tcpEchoServer(t), 1<<20)

			body, _, _ := httpsGet(t, d.serverAddr)
			if body != "the real site" {
				t.Fatalf("prober saw %q, want the real site's content", body)
			}
			// Non-TLS garbage is relayed too (and the server stays up).
			c, _ := net.Dial("tcp", d.serverAddr)
			c.Write([]byte("GET / HTTP/1.0\r\n\r\n"))
			c.SetReadDeadline(time.Now().Add(3 * time.Second))
			io.Copy(io.Discard, c)
			c.Close()
			echoThrough(t, d.socks, tcpEchoServer(t), 4096)
		})
	}
}

// TestBinariesCoverFallback: an ordinary browser or prober hitting the server
// gets the cover site over HTTP/1.1 and HTTP/2, and probing never disturbs
// real clients.
func TestBinariesCoverFallback(t *testing.T) {
	d := deploy(t, deployOpts{transport: "ws"})
	echo := tcpEchoServer(t)
	echoThrough(t, d.socks, echo, 4096)

	if body, proto, _ := httpsGet(t, d.serverAddr, "http/1.1"); !strings.Contains(body, "It works.") || proto != "HTTP/1.1" {
		t.Fatalf("h1 cover: %q over %s", body, proto)
	}
	if body, proto, _ := httpsGet(t, d.serverAddr, "h2", "http/1.1"); !strings.Contains(body, "It works.") || proto != "HTTP/2.0" {
		t.Fatalf("h2 cover: %q over %s", body, proto)
	}

	// A flood of half-open and garbage connections must all be released.
	for i := 0; i < 200; i++ {
		c, err := tls.Dial("tcp", d.serverAddr, &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"http/1.1"}})
		if err != nil {
			t.Fatalf("probe %d: %v", i, err)
		}
		switch i % 3 {
		case 0:
			c.Write([]byte("GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"))
			io.Copy(io.Discard, c)
		case 1:
			c.Write(bytes.Repeat([]byte{0xA5}, 200)) // looks like a ClientInit, isn't
		}
		c.Close()
	}
	echoThrough(t, d.socks, echo, 1<<20)
}

// TestBinariesAdminLifecycle exercises the management API against the real
// server: auth, stats, add → use → revoke (with kick), persistence, quota.
func TestBinariesAdminLifecycle(t *testing.T) {
	d := deploy(t, deployOpts{})
	echo := tcpEchoServer(t)
	echoThrough(t, d.socks, echo, 300_000)

	// Auth is enforced.
	resp, err := http.Get("http://" + d.admin + "/api/stats")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauthenticated admin call returned %d", resp.StatusCode)
	}

	// Traffic is accounted.
	var stats []struct {
		ID           string `json:"id"`
		BytesUp      int64  `json:"bytes_up"`
		BytesDown    int64  `json:"bytes_down"`
		LiveSessions int    `json:"live_sessions"`
	}
	_, raw := d.adminCall("GET", "/api/stats", nil)
	json.Unmarshal(raw, &stats)
	if len(stats) != 1 || stats[0].BytesUp < 300_000 || stats[0].BytesDown < 300_000 || stats[0].LiveSessions == 0 {
		t.Fatalf("stats = %s", raw)
	}

	// Prometheus metrics expose the same accounting.
	if code, raw := d.adminCall("GET", "/metrics", nil); code != 200 ||
		!bytes.Contains(raw, []byte("prism_sessions ")) || !bytes.Contains(raw, []byte(`prism_client_bytes_up_total{id="`)) {
		t.Fatalf("metrics: %d %s", code, raw)
	}

	// Add a credential: persisted to the credentials file and usable at once.
	code, raw := d.adminCall("POST", "/api/credentials/add", map[string]any{"name": "laptop-2"})
	var added struct{ ID, PSK string }
	json.Unmarshal(raw, &added)
	if code != 200 || added.ID == "" || added.PSK == "" {
		t.Fatalf("add credential: %d %s", code, raw)
	}
	file, _ := os.ReadFile(filepath.Join(d.dir, "credentials.json"))
	if !bytes.Contains(file, []byte(added.ID)) {
		t.Fatalf("new credential not persisted: %s", file)
	}
	socks2 := freeTCP(t)
	cfg2 := map[string]any{}
	for k, v := range d.clientBase {
		cfg2[k] = v
	}
	cfg2["id"], cfg2["psk"], cfg2["socks_listen"] = added.ID, added.PSK, socks2
	writeJSONFile(t, filepath.Join(d.dir, "client2.json"), cfg2)
	start(t, "prism-client-2", d.clientBin, filepath.Join(d.dir, "client2.json"))
	waitTCP(t, socks2)
	echoThrough(t, socks2, echo, 50_000)

	// A quota cuts the client off once it is spent.
	if code, raw := d.adminCall("POST", "/api/quota", map[string]any{"id": added.ID, "max_bytes_per_day": 200_000}); code != 200 {
		t.Fatalf("set quota: %d %s", code, raw)
	}
	if c, err := socksConnect(socks2, echo); err == nil {
		c.SetDeadline(time.Now().Add(5 * time.Second))
		go c.Write(make([]byte, 400_000))
		n, _ := io.Copy(io.Discard, c)
		c.Close()
		if n >= 400_000 {
			t.Fatalf("quota of 200k let %d bytes through", n)
		}
	}
	// And stays cut off for new connections.
	if c, err := socksConnect(socks2, echo); err == nil {
		c.SetDeadline(time.Now().Add(3 * time.Second))
		c.Write([]byte("more"))
		if n, _ := c.Read(make([]byte, 4)); n > 0 {
			t.Fatal("client over quota still passes traffic")
		}
		c.Close()
	}

	// Revoking the first credential kicks its live session and blocks redial.
	code, raw = d.adminCall("POST", "/api/credentials/revoke", map[string]any{"id": d.id})
	if code != 200 || !bytes.Contains(raw, []byte(`"revoked":true`)) {
		t.Fatalf("revoke: %d %s", code, raw)
	}
	time.Sleep(500 * time.Millisecond)
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	for ctx.Err() == nil {
		c, err := socksConnect(d.socks, echo)
		if err != nil {
			break // refused: revoked client can no longer open streams
		}
		c.SetDeadline(time.Now().Add(2 * time.Second))
		c.Write([]byte("ping"))
		n, _ := c.Read(make([]byte, 4))
		c.Close()
		if n == 0 {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	if ctx.Err() != nil {
		t.Fatal("revoked credential still tunnels traffic")
	}
	file, _ = os.ReadFile(filepath.Join(d.dir, "credentials.json"))
	if bytes.Contains(file, []byte(d.psk)) {
		t.Fatal("revoked credential still in the credentials file (would return on restart)")
	}
}

// TestBinariesRejectBadConfig: dangerous or broken configs fail at startup.
func TestBinariesRejectBadConfig(t *testing.T) {
	serverBin, clientBin := binaries(t)
	kp, _ := prism.GenerateServerKeypair()
	psk, _ := prism.NewPSK()
	good := map[string]any{
		"listen": "127.0.0.1:0", "self_signed": "localhost",
		"private_key": prism.EncodeKey(kp.Private.Bytes()),
		"credentials": []map[string]any{{"id": "AAAAAA==", "psk": prism.EncodeKey(psk)}},
	}
	with := func(k string, v any) map[string]any {
		m := map[string]any{}
		for kk, vv := range good {
			m[kk] = vv
		}
		m[k] = v
		return m
	}
	check := func(bin string, cfg map[string]any, want string) {
		t.Helper()
		path := filepath.Join(t.TempDir(), "c.json")
		writeJSONFile(t, path, cfg)
		out, err := exec.Command(bin, "-c", path, "-check").CombinedOutput()
		if want == "" {
			if err != nil {
				t.Errorf("valid config rejected: %s", out)
			}
			return
		}
		if err == nil || !strings.Contains(string(out), want) {
			t.Errorf("config should fail with %q, got err=%v out=%s", want, err, out)
		}
	}
	check(serverBin, good, "")
	check(serverBin, with("admin", map[string]any{"listen": "127.0.0.1:1", "token": ""}), "admin.token")
	check(serverBin, with("admin", map[string]any{"listen": "127.0.0.1:1", "token": "short"}), "admin.token")
	check(serverBin, with("handshake", "nosie"), "handshake")
	check(serverBin, with("ciphers", []string{"rc4"}), "cipher")
	check(serverBin, with("credentials", []map[string]any{{"id": "AAAAAA==", "psk": prism.EncodeKey(psk)}, {"id": "AAAAAA==", "psk": prism.EncodeKey(psk)}}), "duplicate")

	cgood := map[string]any{
		"server": "sg.example.com:443", "sni": "sg.example.com",
		"server_public_key": prism.EncodeKey(kp.Public.Bytes()), "id": "AAAAAA==", "psk": prism.EncodeKey(psk),
	}
	cwith := func(k string, v any) map[string]any {
		m := map[string]any{}
		for kk, vv := range cgood {
			m[kk] = vv
		}
		m[k] = v
		return m
	}
	check(clientBin, cgood, "")
	check(clientBin, cwith("transport", "websocket"), "transport")
	check(clientBin, cwith("server", "sg.example.com"), "host:port")
	check(clientBin, cwith("tun", map[string]any{"address": "10.0.85.1/24", "gateway": "10.0.85.2"}), "orig_gateway")
	m := cwith("steal", true)
	m["ech"] = "auto"
	check(clientBin, m, "steal")
}

// TestBinariesFailover: when the primary egress dies the client moves to the
// backup on its own, and existing applications just reconnect.
func TestBinariesFailover(t *testing.T) {
	serverBin, clientBin := binaries(t)
	backup := deploy(t, deployOpts{}) // its server is the backup egress
	echo := tcpEchoServer(t)

	// A second server with its own identity, accepting the same credential.
	kp, _ := prism.GenerateServerKeypair()
	primaryAddr := freeTCP(t)
	writeJSONFile(t, filepath.Join(backup.dir, "primary.json"), map[string]any{
		"listen": primaryAddr, "self_signed": "localhost", "allow_private": true,
		"private_key": prism.EncodeKey(kp.Private.Bytes()),
		"credentials": []map[string]any{{"name": "e2e", "id": backup.id, "psk": backup.psk}},
	})
	primary, primaryLog := startProc(t, "prism-server-primary", serverBin, filepath.Join(backup.dir, "primary.json"))
	waitTCP(t, primaryAddr)

	socks := freeTCP(t)
	cfg := map[string]any{}
	for k, v := range backup.clientBase {
		cfg[k] = v
	}
	cfg["server"], cfg["server_public_key"], cfg["socks_listen"] = primaryAddr, prism.EncodeKey(kp.Public.Bytes()), socks
	cfg["backups"] = []map[string]any{{"server": backup.serverAddr, "sni": "localhost", "server_public_key": backup.pub}}
	writeJSONFile(t, filepath.Join(backup.dir, "client-ha.json"), cfg)
	clientLog := start(t, "prism-client-ha", clientBin, filepath.Join(backup.dir, "client-ha.json"))
	waitTCP(t, socks)

	echoThrough(t, socks, echo, 100_000)
	if !strings.Contains(primaryLog.String(), "connected via tls") {
		t.Fatal("client did not start on the primary")
	}

	primary.Process.Kill()
	primary.Wait()
	echoThrough(t, socks, echo, 100_000) // retries internally while carriers fail over
	if !strings.Contains(clientLog.String(), "egress switched: "+primaryAddr+" -> "+backup.serverAddr) {
		t.Fatalf("no failover to the backup; client log:\n%s", clientLog.String())
	}
}

// TestBinariesH3Cover: the QUIC port is a real HTTP/3 website to everyone but
// authenticated clients — including a prober that knows the carrier path.
func TestBinariesH3Cover(t *testing.T) {
	d := deploy(t, deployOpts{transport: "quic"})
	echo := tcpEchoServer(t)
	echoThrough(t, d.socks, echo, 200_000)

	tr := &http3.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	defer tr.Close()
	client := &http.Client{Transport: tr, Timeout: 10 * time.Second}

	get := func(method, path string, body io.Reader) (int, string, string) {
		t.Helper()
		req, _ := http.NewRequest(method, "https://"+d.serverAddr+path, body)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("%s %s over HTTP/3: %v", method, path, err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, resp.Proto, string(b)
	}

	if code, proto, body := get("GET", "/", nil); code != 200 || proto != "HTTP/3.0" || !strings.Contains(body, "It works.") {
		t.Fatalf("browser over HTTP/3 got %d %s %q", code, proto, body)
	}
	// Probing the carrier path without credentials looks exactly the same.
	for name, body := range map[string][]byte{
		"empty":            nil,
		"short":            []byte("hello"),
		"clientinit-sized": bytes.Repeat([]byte{0x5a}, 80),
		"large":            bytes.Repeat([]byte{0x11}, 5000),
	} {
		code, _, got := get("POST", "/_prism/h3", bytes.NewReader(body))
		if code != 200 || !strings.Contains(got, "It works.") {
			t.Fatalf("probe %q of the carrier path got %d %q, want the cover page", name, code, got)
		}
	}
	echoThrough(t, d.socks, echo, 200_000) // real clients unaffected
}
