// Command prism-client is the cross-platform endpoint. It runs in two shapes:
//
//	mode "router"  : a SOCKS5 inbound on the OpenWrt router; Nikki/Mihomo
//	                 routes cross-border traffic into it.
//	mode "desktop" : SOCKS5 + HTTP proxy + automatic system-proxy toggling +
//	                 a local control-panel web page, for a work-from-home
//	                 macOS/Windows employee with no router.
//
// One binary, no external dependencies; cross-compile with GOOS/GOARCH.
package main

import (
	"flag"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
)

func main() {
	log.SetFlags(log.LstdFlags | log.Lmsgprefix)
	log.SetPrefix("[prism-client] ")

	cfgPath := flag.String("c", "client.json", "path to config JSON")
	flag.Parse()

	cfg, cred, err := loadClientConfig(*cfgPath)
	if err != nil {
		log.Fatalf("config: %v", err)
	}
	d, err := NewDialer(cfg, cred)
	if err != nil {
		log.Fatalf("dialer: %v", err)
	}
	a := &app{cfg: cfg, d: d}

	// SOCKS inbound runs in every mode.
	socksLn, err := net.Listen("tcp", cfg.SocksListen)
	if err != nil {
		log.Fatalf("socks listen %s: %v", cfg.SocksListen, err)
	}
	go serveSOCKS(socksLn, d)
	log.Printf("SOCKS5 inbound on %s -> %s", cfg.SocksListen, cfg.Server)

	if cfg.Mode == "desktop" {
		httpLn, err := net.Listen("tcp", cfg.HTTPListen)
		if err != nil {
			log.Fatalf("http listen %s: %v", cfg.HTTPListen, err)
		}
		go newHTTPProxy(d).Serve(httpLn)
		log.Printf("HTTP proxy inbound on %s", cfg.HTTPListen)

		panelLn, err := net.Listen("tcp", cfg.PanelListen)
		if err != nil {
			log.Fatalf("panel listen %s: %v", cfg.PanelListen, err)
		}
		go http.Serve(panelLn, a.panelMux())
		log.Printf("control panel: http://%s", cfg.PanelListen)

		if cfg.autoConnect() {
			a.Connect()
		}
	} else {
		log.Printf("router mode: configure Nikki/Mihomo to use SOCKS5 %s", cfg.SocksListen)
	}

	// Clean up the system proxy on exit so we never strand the machine offline.
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	log.Printf("shutting down")
	a.Disconnect()
	d.Close()
}

// app holds the runtime state the control panel toggles.
type app struct {
	cfg *ClientConfig
	d   *Dialer

	mu        sync.Mutex
	connected bool
}

// Connect points the OS system proxy at our local inbounds (desktop mode).
func (a *app) Connect() {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.connected {
		return
	}
	if a.cfg.Mode == "desktop" {
		setSystemProxy(a.cfg.HTTPListen, a.cfg.SocksListen)
	}
	a.connected = true
}

// Disconnect restores the OS system proxy.
func (a *app) Disconnect() {
	a.mu.Lock()
	defer a.mu.Unlock()
	if !a.connected {
		return
	}
	if a.cfg.Mode == "desktop" {
		clearSystemProxy()
	}
	a.connected = false
}

func (a *app) status() map[string]any {
	a.mu.Lock()
	connected := a.connected
	a.mu.Unlock()
	return map[string]any{
		"connected": connected,
		"server":    a.cfg.Server,
		"live":      a.d.Live(),
		"socks":     a.cfg.SocksListen,
		"http":      a.cfg.HTTPListen,
	}
}
