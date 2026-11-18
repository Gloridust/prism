package main

import (
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
	"sync/atomic"
	"testing"
	"time"
)

// testBrowser is a browser the guard configures and the tests can launch.
type testBrowser struct {
	name  string   // as reported by applyChromiumWebRTC
	paths []string // candidates, per OS
}

func chromiumTestBrowsers() []testBrowser {
	pf, pf86 := os.Getenv("ProgramFiles"), os.Getenv("ProgramFiles(x86)")
	switch runtime.GOOS {
	case "darwin":
		return []testBrowser{
			{"Chrome", []string{"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"}},
			{"Edge", []string{"/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge"}},
			{"Brave", []string{"/Applications/Brave Browser.app/Contents/MacOS/Brave Browser"}},
		}
	case "windows":
		return []testBrowser{
			{"Chrome", []string{pf + `\Google\Chrome\Application\chrome.exe`, pf86 + `\Google\Chrome\Application\chrome.exe`}},
			{"Edge", []string{pf86 + `\Microsoft\Edge\Application\msedge.exe`, pf + `\Microsoft\Edge\Application\msedge.exe`}},
			{"Brave", []string{pf + `\BraveSoftware\Brave-Browser\Application\brave.exe`}},
		}
	default:
		return []testBrowser{
			{"Chrome", []string{"google-chrome", "google-chrome-stable"}},
			{"Edge", []string{"microsoft-edge", "microsoft-edge-stable"}},
			{"Brave", []string{"brave-browser", "brave"}},
		}
	}
}

func (b testBrowser) find() string {
	for _, c := range b.paths {
		if p, err := exec.LookPath(c); err == nil {
			return p
		}
	}
	return ""
}

func firefoxPath() string {
	paths := []string{"firefox"}
	switch runtime.GOOS {
	case "darwin":
		paths = []string{"/Applications/Firefox.app/Contents/MacOS/firefox"}
	case "windows":
		paths = []string{os.Getenv("ProgramFiles") + `\Mozilla Firefox\firefox.exe`, os.Getenv("ProgramFiles(x86)") + `\Mozilla Firefox\firefox.exe`}
	}
	return testBrowser{paths: paths}.find()
}

// killTree stops a browser and the helper processes it spawned. It never
// blocks: a confined browser (snap) may refuse the signal, and a test must not
// hang on that.
func killTree(cmd *exec.Cmd, marker string) {
	if runtime.GOOS == "windows" {
		exec.Command("taskkill", "/F", "/T", "/PID", fmt.Sprint(cmd.Process.Pid)).Run()
	} else {
		exec.Command("pkill", "-KILL", "-f", marker).Run()
	}
	cmd.Process.Kill()
	done := make(chan struct{})
	go func() { cmd.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
	}
}

// stunServer answers RFC 5389 Binding Requests and counts them. A request
// arriving here is exactly the packet that would reveal the client's address.
type stunServer struct {
	conn *net.UDPConn
	hits atomic.Int64
}

func newSTUNServer(t *testing.T, ip net.IP) *stunServer {
	t.Helper()
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: ip})
	if err != nil {
		t.Fatal(err)
	}
	s := &stunServer{conn: conn}
	t.Cleanup(func() { conn.Close() })
	go func() {
		buf := make([]byte, 1500)
		for {
			n, from, err := conn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			if n < 20 || binary.BigEndian.Uint16(buf[0:2]) != 0x0001 {
				continue
			}
			s.hits.Add(1)
			resp := make([]byte, 0, 32)
			resp = append(resp, 0x01, 0x01, 0x00, 0x0c)
			resp = append(resp, buf[4:20]...) // magic cookie + transaction id
			resp = append(resp, 0x00, 0x20, 0x00, 0x08, 0x00, 0x01)
			resp = binary.BigEndian.AppendUint16(resp, uint16(from.Port)^0x2112)
			ip4 := from.IP.To4()
			for i := 0; i < 4; i++ {
				resp = append(resp, ip4[i]^buf[4+i])
			}
			conn.WriteToUDP(resp, from)
		}
	}()
	return s
}

const webrtcProbePage = `<!doctype html><script>
const cands = [];
const pc = new RTCPeerConnection({iceServers: [{urls: 'stun:%s'}]});
pc.createDataChannel('probe');
let sent = false;
function report() {
  if (sent) return; sent = true;
  fetch('/result', {method: 'POST', body: JSON.stringify(cands)});
}
pc.onicecandidate = e => { if (e.candidate) cands.push(e.candidate.candidate); else report(); };
pc.createOffer().then(o => pc.setLocalDescription(o));
setTimeout(report, 8000);
</script>`

// webrtcLab is the fixture a browser is pointed at: a page that gathers WebRTC
// candidates, a STUN server on the machine's real address that counts what
// reaches it, and a local proxy standing in for prism-client's.
type webrtcLab struct {
	t      *testing.T
	hostIP net.IP
	stun   *stunServer
	web    net.Listener
	proxy  net.Listener // forwarding HTTP proxy (also accepts and drops SOCKS)

	mu     sync.Mutex
	result chan []string
}

func newWebRTCLab(t *testing.T) *webrtcLab {
	t.Helper()
	c, err := net.Dial("udp4", "203.0.113.1:9")
	if err != nil {
		t.Skipf("no outbound interface: %v", err)
	}
	l := &webrtcLab{t: t, hostIP: c.LocalAddr().(*net.UDPAddr).IP}
	c.Close()
	l.stun = newSTUNServer(t, l.hostIP)

	if l.web, err = net.Listen("tcp", "127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, webrtcProbePage, l.stun.conn.LocalAddr().String())
	})
	mux.HandleFunc("/result", func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		var cands []string
		json.Unmarshal(raw, &cands)
		l.mu.Lock()
		ch := l.result
		l.mu.Unlock()
		select {
		case ch <- cands:
		default:
		}
	})
	go http.Serve(l.web, mux)

	if l.proxy, err = net.Listen("tcp", "127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	go http.Serve(l.proxy, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !r.URL.IsAbs() {
			http.Error(w, "proxy", http.StatusBadRequest)
			return
		}
		r.RequestURI = ""
		resp, err := http.DefaultTransport.RoundTrip(r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()
		for k, v := range resp.Header {
			w.Header()[k] = v
		}
		w.WriteHeader(resp.StatusCode)
		io.Copy(w, resp.Body)
	}))
	t.Cleanup(func() { l.web.Close(); l.proxy.Close() })
	return l
}

func (l *webrtcLab) url() string { return "http://" + l.web.Addr().String() + "/" }

// gather launches the browser and returns the candidates it reported and how
// many STUN requests reached the server meanwhile.
func (l *webrtcLab) gather(label, bin, marker string, args ...string) (cands []string, hits int64) {
	l.t.Helper()
	cands, hits, ok := l.tryGather(label, bin, marker, args...)
	if !ok {
		l.t.Fatalf("%s: the browser never reported WebRTC candidates", label)
	}
	return cands, hits
}

// tryGather is gather that reports, rather than fails on, a browser that never
// loads the page (ok=false) — some builds will not run headless as root.
func (l *webrtcLab) tryGather(label, bin, marker string, args ...string) (cands []string, hits int64, ok bool) {
	l.t.Helper()
	ch := make(chan []string, 1)
	l.mu.Lock()
	l.result = ch
	l.mu.Unlock()
	before := l.stun.hits.Load()

	cmd := exec.Command(bin, args...)
	if err := cmd.Start(); err != nil {
		l.t.Fatalf("start %s: %v", bin, err)
	}
	defer killTree(cmd, marker)
	select {
	case cands = <-ch:
	case <-time.After(60 * time.Second):
		return nil, 0, false
	}
	time.Sleep(500 * time.Millisecond)
	hits = l.stun.hits.Load() - before
	l.t.Logf("%s: %d STUN request(s) reached the server; candidates: %q", label, hits, cands)
	return cands, hits, true
}

func (l *webrtcLab) assertNoLeak(cands []string, hits int64) {
	l.t.Helper()
	if hits != 0 {
		l.t.Errorf("the browser still sent %d STUN request(s) from the real address with the guard in place", hits)
	}
	for _, cand := range cands {
		if strings.Contains(cand, "typ srflx") || strings.Contains(cand, " "+l.hostIP.String()+" ") {
			l.t.Errorf("candidate exposes the real address: %s", cand)
		}
	}
}

// TestChromiumHonoursWebRTCGuard drives every installed Chromium-family
// browser (Chrome, Edge, Brave): each loads a page that gathers WebRTC
// candidates against a local STUN server, first without and then with the
// policy prism-client installs. Without it the browser sends a STUN probe from
// the machine's real address; with it, behind a proxy, it must not.
//
// Requires PRISM_BROWSER_TEST=1 (root on Linux, where managed policy lives in
// /etc).
func TestChromiumHonoursWebRTCGuard(t *testing.T) {
	if os.Getenv("PRISM_BROWSER_TEST") == "" {
		t.Skip("set PRISM_BROWSER_TEST=1 (launches browsers and sets their WebRTC policy)")
	}
	ran := 0
	for _, b := range chromiumTestBrowsers() {
		bin := b.find()
		if bin == "" {
			continue
		}
		ran++
		t.Run(b.name, func(t *testing.T) {
			if runtime.GOOS == "linux" && b.name == "Edge" {
				t.Skip("Edge has no WebRTC IP-handling policy on Linux; the guard reports it as unprotected (see webrtc_other.go)")
			}
			lab := newWebRTCLab(t)
			run := func(label string) ([]string, int64) {
				dir := t.TempDir()
				args := []string{"--headless=new", "--disable-gpu", "--no-first-run", "--no-default-browser-check",
					"--user-data-dir=" + dir, "--proxy-server=socks5://" + lab.proxy.Addr().String(), lab.url()}
				if runtime.GOOS == "linux" {
					args = append([]string{"--no-sandbox"}, args...)
				}
				return lab.gather(label, bin, dir, args...)
			}
			dir := t.TempDir()
			baseArgs := []string{"--headless=new", "--disable-gpu", "--no-first-run", "--no-default-browser-check",
				"--user-data-dir=" + dir, "--proxy-server=socks5://" + lab.proxy.Addr().String(), lab.url()}
			if runtime.GOOS == "linux" {
				baseArgs = append([]string{"--no-sandbox"}, baseArgs...)
			}
			_, baseline, ok := lab.tryGather("without the guard", bin, dir, baseArgs...)
			if !ok {
				t.Skipf("%s does not run headless in this environment; cannot test it here", b.name)
			}
			if baseline == 0 {
				t.Skip("this browser sends no STUN even without the policy; nothing to compare against")
			}
			restore, applied := applyChromiumWebRTC(webrtcProxyOnly)
			defer func() {
				for i := len(restore) - 1; i >= 0; i-- {
					restore[i]()
				}
			}()
			if !strings.Contains(","+strings.Join(applied, ",")+",", ","+b.name+",") {
				t.Fatalf("policy was not applied to %s (applied to %v)", b.name, applied)
			}
			lab.assertNoLeak(run("with the guard"))
		})
	}
	if ran == 0 {
		t.Skip("no Chromium-family browser installed")
	}
}

// TestFirefoxHonoursWebRTCGuard does the same with a real Firefox and the
// user.js block prism-client writes into Firefox profiles.
func TestFirefoxHonoursWebRTCGuard(t *testing.T) {
	if os.Getenv("PRISM_BROWSER_TEST") == "" {
		t.Skip("set PRISM_BROWSER_TEST=1 (launches Firefox)")
	}
	bin := firefoxPath()
	if bin == "" {
		t.Skip("Firefox not installed")
	}
	lab := newWebRTCLab(t)

	// A throwaway profile in a real profile root (snap/flatpak builds cannot
	// read arbitrary temp dirs), proxied through the lab's HTTP proxy.
	home, _, _ := targetUser()
	root := firefoxProfileRoots(home)[0]
	for _, r := range firefoxProfileRoots(home) {
		if _, err := os.Stat(r); err == nil {
			root = r
			break
		}
	}
	profile := filepath.Join(root, fmt.Sprintf("prismtest%d.webrtc", time.Now().UnixNano()))
	if err := os.MkdirAll(profile, 0o700); err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(profile)
	_, port, _ := net.SplitHostPort(lab.proxy.Addr().String())
	base := fmt.Sprintf(`user_pref("network.proxy.type", 1);
user_pref("network.proxy.http", "127.0.0.1");
user_pref("network.proxy.http_port", %s);
user_pref("network.proxy.allow_hijacking_localhost", true);
user_pref("network.proxy.no_proxies_on", "");
user_pref("browser.shell.checkDefaultBrowser", false);
user_pref("datareporting.policy.dataSubmissionEnabled", false);
user_pref("toolkit.telemetry.reportingpolicy.firstRun", false);
user_pref("browser.aboutwelcome.enabled", false);
`, port)
	os.WriteFile(filepath.Join(profile, "prefs.js"), nil, 0o600)
	userJS := filepath.Join(profile, "user.js")
	os.WriteFile(userJS, []byte(base), 0o600)

	run := func(label string) ([]string, int64) {
		return lab.gather(label, bin, profile, "--headless", "--no-remote", "--profile", profile, lab.url())
	}
	if _, baseline := run("without the guard"); baseline == 0 {
		t.Skip("this Firefox sends no STUN even without the prefs; nothing to compare against")
	}
	if err := writeFirefoxBlock(userJS, -1, -1); err != nil {
		t.Fatal(err)
	}
	lab.assertNoLeak(run("with the guard"))
}
