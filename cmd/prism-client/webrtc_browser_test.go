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
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func findChrome() string {
	candidates := []string{"google-chrome", "google-chrome-stable"}
	switch runtime.GOOS {
	case "darwin":
		candidates = []string{"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"}
	case "windows":
		candidates = []string{
			os.Getenv("ProgramFiles") + `\Google\Chrome\Application\chrome.exe`,
			os.Getenv("ProgramFiles(x86)") + `\Google\Chrome\Application\chrome.exe`,
		}
	}
	for _, c := range candidates {
		if p, err := exec.LookPath(c); err == nil {
			return p
		}
	}
	return ""
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

// TestChromeHonoursWebRTCGuard drives a real Chrome: it loads a page that
// gathers WebRTC candidates against a local STUN server, first without and
// then with the policy prism-client installs. Without it Chrome sends a STUN
// probe from the machine's real address; with it, behind a proxy, it must not.
//
// Requires PRISM_BROWSER_TEST=1 and an installed Chrome (root on Linux, where
// managed policy lives in /etc).
func TestChromeHonoursWebRTCGuard(t *testing.T) {
	if os.Getenv("PRISM_BROWSER_TEST") == "" {
		t.Skip("set PRISM_BROWSER_TEST=1 (launches Chrome and sets its WebRTC policy)")
	}
	chrome := findChrome()
	if chrome == "" {
		t.Skip("Chrome not installed")
	}
	c, err := net.Dial("udp4", "203.0.113.1:9")
	if err != nil {
		t.Skipf("no outbound interface: %v", err)
	}
	hostIP := c.LocalAddr().(*net.UDPAddr).IP
	c.Close()

	stun := newSTUNServer(t, hostIP)
	stunAddr := stun.conn.LocalAddr().String()

	var mu sync.Mutex
	var result chan []string
	web, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer web.Close()
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, webrtcProbePage, stunAddr)
	})
	mux.HandleFunc("/result", func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		var cands []string
		json.Unmarshal(raw, &cands)
		mu.Lock()
		ch := result
		mu.Unlock()
		select {
		case ch <- cands:
		default:
		}
	})
	go http.Serve(web, mux)

	// A stand-in for prism-client's local proxy: Chrome only needs one to be
	// configured for "no UDP outside the proxy" to apply.
	proxy, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer proxy.Close()
	go func() {
		for {
			pc, err := proxy.Accept()
			if err != nil {
				return
			}
			pc.Close()
		}
	}()

	gather := func(label string) (cands []string, hits int64) {
		t.Helper()
		ch := make(chan []string, 1)
		mu.Lock()
		result = ch
		mu.Unlock()
		before := stun.hits.Load()

		args := []string{"--headless=new", "--disable-gpu", "--no-first-run", "--no-default-browser-check",
			"--user-data-dir=" + t.TempDir(), "--proxy-server=socks5://" + proxy.Addr().String(),
			"http://" + web.Addr().String() + "/"}
		if runtime.GOOS == "linux" {
			args = append([]string{"--no-sandbox"}, args...)
		}
		cmd := exec.Command(chrome, args...)
		if err := cmd.Start(); err != nil {
			t.Fatalf("start chrome: %v", err)
		}
		defer func() { cmd.Process.Kill(); cmd.Wait() }()
		select {
		case cands = <-ch:
		case <-time.After(45 * time.Second):
			t.Fatalf("%s: Chrome never reported WebRTC candidates", label)
		}
		time.Sleep(500 * time.Millisecond)
		hits = stun.hits.Load() - before
		t.Logf("%s: %d STUN request(s) reached the server; candidates: %q", label, hits, cands)
		return
	}

	_, baseline := gather("without the guard")
	if baseline == 0 {
		t.Skip("this Chrome sends no STUN even without the policy (no usable interface); nothing to compare against")
	}

	restore, applied := applyChromiumWebRTC(webrtcProxyOnly)
	defer func() {
		for i := len(restore) - 1; i >= 0; i-- {
			restore[i]()
		}
	}()
	if !strings.Contains(strings.Join(applied, ","), "Chrome") {
		t.Fatalf("policy was not applied to Chrome (applied to %v)", applied)
	}

	cands, hits := gather("with the guard")
	if hits != 0 {
		t.Errorf("Chrome still sent %d STUN request(s) from the real address with the policy in place", hits)
	}
	for _, cand := range cands {
		if strings.Contains(cand, "typ srflx") || strings.Contains(cand, " "+hostIP.String()+" ") {
			t.Errorf("candidate exposes the real address: %s", cand)
		}
	}
}
