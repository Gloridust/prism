package main

import (
	"encoding/json"
	"net/http"
	"net/url"
)

// panelHTML is the one-page control panel a non-technical employee opens in a
// browser. It talks to the local /api endpoints below — nothing leaves the
// machine except, once connected, the tunnelled traffic itself.
const panelHTML = `<!doctype html><html lang="zh"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Prism</title><style>
:root{color-scheme:light dark}
body{font:16px/1.5 system-ui,-apple-system,Segoe UI,Roboto,sans-serif;max-width:460px;margin:8vh auto;padding:0 20px}
h1{font-size:22px;margin:0 0 2px}.sub{color:#888;font-size:13px;margin-bottom:24px}
.card{border:1px solid #8883;border-radius:14px;padding:20px;margin-bottom:16px}
.dot{display:inline-block;width:10px;height:10px;border-radius:50%;margin-right:8px;vertical-align:middle}
.on{background:#2ecc71}.off{background:#bbb}
.state{font-size:19px;font-weight:600}
button{font:inherit;font-weight:600;border:0;border-radius:10px;padding:12px 22px;cursor:pointer;width:100%;margin-top:8px}
.connect{background:#2ecc71;color:#fff}.disconnect{background:#e74c3c;color:#fff}
.kv{display:flex;justify-content:space-between;color:#888;font-size:13px;margin-top:6px}
.kv b{color:inherit;font-weight:500}
</style></head><body>
<h1>Prism</h1><div class="sub">统一出口 · Unified egress</div>
<div class="card">
  <div class="state"><span id="dot" class="dot off"></span><span id="st">…</span></div>
  <div class="kv"><span>出口 Egress</span><b id="srv">–</b></div>
  <div class="kv"><span>活动链路 Carriers</span><b id="live">–</b></div>
  <div class="kv"><span>SOCKS</span><b id="socks">–</b></div>
  <div class="kv"><span>HTTP</span><b id="http">–</b></div>
  <button id="btn" class="connect" onclick="toggle()">连接 Connect</button>
</div>
<script>
let connected=false;
async function refresh(){
  try{const r=await fetch('/api/status');const s=await r.json();
  connected=s.connected;
  document.getElementById('dot').className='dot '+(s.connected?'on':'off');
  document.getElementById('st').textContent=s.connected?'已连接 Connected':'未连接 Disconnected';
  document.getElementById('srv').textContent=s.server;
  document.getElementById('live').textContent=s.live;
  document.getElementById('socks').textContent=s.socks;
  document.getElementById('http').textContent=s.http;
  const b=document.getElementById('btn');
  b.textContent=s.connected?'断开 Disconnect':'连接 Connect';
  b.className=s.connected?'disconnect':'connect';
  }catch(e){}
}
async function toggle(){await fetch(connected?'/api/disconnect':'/api/connect',{method:'POST'});refresh();}
refresh();setInterval(refresh,2000);
</script></body></html>`

func (a *app) panelMux() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write([]byte(panelHTML))
	})
	mux.HandleFunc("/api/status", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, a.status())
	})
	mux.HandleFunc("/api/connect", func(w http.ResponseWriter, r *http.Request) {
		if !sameOrigin(r) {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		a.Connect()
		writeJSON(w, a.status())
	})
	mux.HandleFunc("/api/disconnect", func(w http.ResponseWriter, r *http.Request) {
		if !sameOrigin(r) {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		a.Disconnect()
		writeJSON(w, a.status())
	})
	return mux
}

// sameOrigin guards the state-changing panel endpoints against CSRF. Without it
// any web page the employee visits could POST (or GET) to the loopback panel
// and toggle their proxy. We require POST and, when the browser supplies an
// Origin/Referer, that it match the panel's own host; cross-site browser
// requests always carry an Origin, so this blocks them while leaving the panel's
// own same-origin fetch and local tooling (curl, no Origin) working.
func sameOrigin(r *http.Request) bool {
	if r.Method != http.MethodPost {
		return false
	}
	if o := r.Header.Get("Origin"); o != "" {
		u, err := url.Parse(o)
		return err == nil && u.Host == r.Host
	}
	if ref := r.Header.Get("Referer"); ref != "" {
		u, err := url.Parse(ref)
		return err == nil && u.Host == r.Host
	}
	return true // no Origin/Referer: not a browser cross-site request (e.g. curl)
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}
