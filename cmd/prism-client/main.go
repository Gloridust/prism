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
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
)

// version is set at build time with -ldflags "-X main.version=...".
var version = "dev"

var killSwitchOn bool

func main() {
	log.SetFlags(log.LstdFlags | log.Lmsgprefix)
	log.SetPrefix("[prism-client] ")

	cfgPath := flag.String("c", "client.json", "path to config JSON")
	showVersion := flag.Bool("version", false, "print version and exit")
	checkOnly := flag.Bool("check", false, "validate the config and exit")
	ksOff := flag.Bool("killswitch-off", false, "remove kill-switch firewall rules left by a previous run, then exit")
	flag.Parse()
	if *ksOff {
		if err := disableKillSwitch(); err != nil {
			log.Fatalf("kill switch: %v", err)
		}
		fmt.Println("kill switch removed")
		return
	}
	resolveCachePath = *cfgPath + ".resolved"
	if *showVersion {
		fmt.Println("prism-client", version)
		return
	}

	cfg, cred, err := loadClientConfig(*cfgPath)
	if err != nil {
		log.Fatalf("config: %v", err)
	}
	if *checkOnly {
		fmt.Println("config OK")
		return
	}
	for name, addr := range map[string]string{"socks_listen": cfg.SocksListen, "http_listen": cfg.HTTPListen} {
		if (name == "socks_listen" || cfg.Mode == "desktop") && !isLoopbackListen(addr) {
			log.Printf("WARNING: %s %s is not loopback: anyone who can reach it can use this tunnel "+
				"(the inbound has no authentication). Firewall it to your LAN.", name, addr)
		}
	}
	if cfg.TUN != nil && cfg.tunSetRoutes() {
		// The carrier must use the one IPv4 address that gets a host route via the
		// original gateway; anything else would be captured by the TUN and loop.
		pinned, err := pinServerIPv4(cfg.Server)
		if err != nil {
			log.Fatalf("tun: %v", err)
		}
		cfg.Server = pinned
		for i := range cfg.Backups {
			if cfg.Backups[i].Server, err = pinServerIPv4(cfg.Backups[i].Server); err != nil {
				log.Fatalf("tun: backups[%d]: %v", i, err)
			}
		}
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

	// DNS leak prevention: local DNS proxy forwards queries through Prism.
	var dnsP *dnsProxy
	if cfg.DNS != nil {
		listen := cfg.DNS.Listen
		if listen == "" {
			listen = "127.0.0.1:53"
		}
		var dnsErr error
		dnsP, dnsErr = newDNSProxy(d, listen, cfg.DNS.Upstream)
		if dnsErr != nil {
			log.Printf("dns proxy on %s: %v (continuing without DNS leak prevention)", listen, dnsErr)
		} else {
			go dnsP.Serve()
			log.Printf("DNS leak prevention: forwarding %s -> %s via tunnel", dnsP.Addr(), cfg.DNS.Upstream)
		}
	}

	// TUN global mode: create a TUN device and route all traffic through Prism.
	var tunDev *tunDevice
	if cfg.TUN != nil {
		devName := cfg.TUN.DeviceName
		if devName == "" {
			devName = "prism0"
		}
		var tunErr error
		tunDev, tunErr = openTUN(devName)
		if tunErr != nil {
			log.Fatalf("tun: %v", tunErr)
		}
		if tunErr = configureTUN(tunDev, cfg.TUN.Address, cfg.TUN.Gateway); tunErr != nil {
			tunDev.Close()
			log.Fatalf("tun configure: %v", tunErr)
		}
		if cfg.tunSetRoutes() {
			serverHost, _, _ := net.SplitHostPort(cfg.Server)
			if tunErr = addDefaultRoute(tunDev, serverHost, cfg.TUN.OrigGateway); tunErr != nil {
				tunDev.Close()
				log.Fatalf("tun routes: %v", tunErr)
			}
			for _, b := range cfg.Backups {
				if h, _, _ := net.SplitHostPort(b.Server); h != serverHost {
					if tunErr = addHostRoute(h, cfg.TUN.OrigGateway); tunErr != nil {
						log.Printf("tun: no direct route for backup %s (it will be unusable): %v", h, tunErr)
					}
				}
			}
			// IPv6 is captured too, otherwise WebRTC/STUN (and anything else)
			// would leave over the physical link's IPv6 with the real address.
			if tunErr = addIPv6Capture(tunDev); tunErr != nil {
				if hostHasGlobalIPv6(tunDev.Name()) {
					removeDefaultRoute(tunDev, serverHost, cfg.TUN.OrigGateway)
					tunDev.Close()
					log.Fatalf("tun ipv6 capture failed and this host has global IPv6 (would leak): %v", tunErr)
				}
				log.Printf("tun: IPv6 capture unavailable (%v); host has no global IPv6, nothing to leak", tunErr)
			}
		}
		if cfg.TUN.KillSwitch {
			p, err := ksParamsFor(tunDev, cfg)
			if err == nil {
				err = enableKillSwitch(p)
			}
			if err == nil && cfg.TUN.KillSwitchBoot {
				if err = persistKillSwitch(p); err != nil {
					disableKillSwitch()
				}
			}
			if err != nil {
				serverHost, _, _ := net.SplitHostPort(cfg.Server)
				removeDefaultRoute(tunDev, serverHost, cfg.TUN.OrigGateway)
				tunDev.Close()
				log.Fatalf("kill switch could not be installed, refusing to run without it: %v", err)
			}
			killSwitchOn = true
			log.Printf("kill switch on: only the tunnel, the server and the local network are reachable; " +
				"it stays in force if this process dies (remove with -killswitch-off)")
		}
		go tunRouter(tunDev, &realDialerAdapter{d: d})
		log.Printf("TUN device %s up, routing all IPv4+IPv6 traffic through Prism", tunDev.Name())
	}

	// Clean up the system proxy on exit so we never strand the machine offline.
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	log.Printf("shutting down")
	if dnsP != nil {
		dnsP.Close()
	}
	if tunDev != nil {
		if cfg.tunSetRoutes() {
			serverHost, _, _ := net.SplitHostPort(cfg.Server)
			removeDefaultRoute(tunDev, serverHost, cfg.TUN.OrigGateway)
			for _, b := range cfg.Backups {
				if h, _, _ := net.SplitHostPort(b.Server); h != serverHost {
					delHostRoute(h, cfg.TUN.OrigGateway)
				}
			}
		}
		tunDev.Close()
		if killSwitchOn && cfg.TUN.KillSwitchBoot {
			log.Printf("kill switch stays on (kill_switch_boot): remove it with -killswitch-off")
		} else if killSwitchOn {
			if err := disableKillSwitch(); err != nil {
				log.Printf("kill switch: %v", err)
			}
		}
	}
	a.Disconnect()
	d.Close()
}

// app holds the runtime state the control panel toggles.
type app struct {
	cfg *ClientConfig
	d   *Dialer

	mu        sync.Mutex
	connected bool
	webrtc    *webrtcGuard
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
		if a.cfg.DNS != nil {
			listen := a.cfg.DNS.Listen
			if listen == "" {
				listen = "127.0.0.1:53"
			}
			setSystemDNS(listen)
		}
		if a.cfg.webrtcGuard() {
			a.webrtc = applyWebRTCGuard(a.cfg.TUN != nil)
		}
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
		if a.cfg.DNS != nil {
			clearSystemDNS()
		}
		a.webrtc.Remove()
		a.webrtc = nil
	}
	a.connected = false
}

func (a *app) status() map[string]any {
	a.mu.Lock()
	connected := a.connected
	webrtc := a.webrtc.Applied()
	a.mu.Unlock()
	live, server := 0, a.cfg.Server
	if a.d != nil {
		live, server = a.d.Live(), a.d.Server()
	}
	return map[string]any{
		"connected": connected,
		"server":    server,
		"live":      live,
		"socks":     a.cfg.SocksListen,
		"http":      a.cfg.HTTPListen,
		"webrtc":    webrtc,
	}
}
