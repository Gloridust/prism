package main

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/gloridust/prism/pkg/prism"
)

// AdminConfig is the optional management API config.
type AdminConfig struct {
	Listen string `json:"listen"` // e.g. "127.0.0.1:9090"
	Token  string `json:"token"`  // bearer token (at least 16 characters)
}

// adminAPI is the management API: credential lifecycle, quotas and stats.
// Changes are written to the credentials file before they are acknowledged, so
// a revocation can never be undone by a restart.
type adminAPI struct {
	srv   *server
	token string
}

func newAdminAPI(srv *server, token string) *adminAPI {
	return &adminAPI{srv: srv, token: token}
}

var errNoCredStore = errors.New("set credentials_file in the server config to change credentials through the admin API")

func (a *adminAPI) auth(method string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if a.token == "" || subtle.ConstantTimeCompare([]byte(tok), []byte(a.token)) != 1 {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if r.Method != method {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 1<<16)
		next(w, r)
	}
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

// mutate applies fn to a copy of the credential list, persists the result and
// only then makes it live. It returns how many sessions were kicked.
func (a *adminAPI) mutate(fn func([]CredConfig) ([]CredConfig, error)) (int, error) {
	s := a.srv
	if s.credsFile == "" {
		return 0, errNoCredStore
	}
	s.credsMu.RLock()
	cur := append([]CredConfig(nil), s.credCfgs...)
	s.credsMu.RUnlock()

	next, err := fn(cur)
	if err != nil {
		return 0, err
	}
	if _, err := parseCreds(next); err != nil {
		return 0, err
	}
	if err := saveCredConfigs(s.credsFile, next); err != nil {
		return 0, err
	}
	return s.setCreds(next)
}

var errCredNotFound = errors.New("credential not found")

func adminFail(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, errCredNotFound):
		http.Error(w, err.Error(), http.StatusNotFound)
	case errors.Is(err, errNoCredStore):
		http.Error(w, err.Error(), http.StatusConflict)
	default:
		log.Printf("admin: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
	}
}

// findCred returns the index of the credential with the given base64 id.
func findCred(ccs []CredConfig, id prism.ClientID) int {
	for i := range ccs {
		if got, err := prism.ParseClientID(ccs[i].ID); err == nil && got == id {
			return i
		}
	}
	return -1
}

func decodeID(w http.ResponseWriter, r *http.Request, dst any, idField *string) (prism.ClientID, bool) {
	if err := json.NewDecoder(r.Body).Decode(dst); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return prism.ClientID{}, false
	}
	id, err := prism.ParseClientID(*idField)
	if err != nil {
		http.Error(w, "invalid id", http.StatusBadRequest)
		return prism.ClientID{}, false
	}
	return id, true
}

func (a *adminAPI) handleListCredentials(w http.ResponseWriter, r *http.Request) {
	a.srv.credsMu.RLock()
	ccs := a.srv.credCfgs
	a.srv.credsMu.RUnlock()

	type credInfo struct {
		ID             string `json:"id"`
		Name           string `json:"name"`
		MaxBytesPerDay int64  `json:"max_bytes_per_day"`
	}
	out := make([]credInfo, 0, len(ccs))
	for _, c := range ccs {
		out = append(out, credInfo{ID: c.ID, Name: c.Name, MaxBytesPerDay: c.MaxBytesPerDay})
	}
	writeJSON(w, out)
}

func (a *adminAPI) handleAddCredential(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name           string `json:"name"`
		MaxBytesPerDay int64  `json:"max_bytes_per_day"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	psk, err := prism.NewPSK()
	if err != nil {
		adminFail(w, err)
		return
	}
	var cc CredConfig
	_, err = a.mutate(func(ccs []CredConfig) ([]CredConfig, error) {
		for {
			id, err := prism.NewClientID()
			if err != nil {
				return nil, err
			}
			if findCred(ccs, id) < 0 {
				cc = CredConfig{ID: prism.EncodeKey(id[:]), PSK: prism.EncodeKey(psk), Name: req.Name, MaxBytesPerDay: req.MaxBytesPerDay}
				return append(ccs, cc), nil
			}
		}
	})
	if err != nil {
		adminFail(w, err)
		return
	}
	log.Printf("admin: added credential %q (%s)", cc.Name, cc.ID)
	writeJSON(w, cc)
}

func (a *adminAPI) handleRevokeCredential(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID string `json:"id"`
	}
	id, ok := decodeID(w, r, &req, &req.ID)
	if !ok {
		return
	}
	kicked, err := a.mutate(func(ccs []CredConfig) ([]CredConfig, error) {
		i := findCred(ccs, id)
		if i < 0 {
			return nil, errCredNotFound
		}
		return append(ccs[:i], ccs[i+1:]...), nil
	})
	if err != nil {
		adminFail(w, err)
		return
	}
	log.Printf("admin: revoked credential %x, kicked %d session(s)", id, kicked)
	writeJSON(w, map[string]any{"revoked": true, "kicked": kicked})
}

func (a *adminAPI) handleRotateKey(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID string `json:"id"`
	}
	id, ok := decodeID(w, r, &req, &req.ID)
	if !ok {
		return
	}
	newPSK, err := prism.NewPSK()
	if err != nil {
		adminFail(w, err)
		return
	}
	kicked, err := a.mutate(func(ccs []CredConfig) ([]CredConfig, error) {
		i := findCred(ccs, id)
		if i < 0 {
			return nil, errCredNotFound
		}
		ccs[i].PSK = prism.EncodeKey(newPSK)
		return ccs, nil
	})
	if err != nil {
		adminFail(w, err)
		return
	}
	log.Printf("admin: rotated PSK for %x, kicked %d session(s)", id, kicked)
	writeJSON(w, map[string]any{"id": req.ID, "new_psk": prism.EncodeKey(newPSK), "kicked": kicked})
}

func (a *adminAPI) handleSetQuota(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID             string `json:"id"`
		MaxBytesPerDay int64  `json:"max_bytes_per_day"`
	}
	id, ok := decodeID(w, r, &req, &req.ID)
	if !ok {
		return
	}
	if req.MaxBytesPerDay < 0 {
		http.Error(w, "max_bytes_per_day must be >= 0", http.StatusBadRequest)
		return
	}
	_, err := a.mutate(func(ccs []CredConfig) ([]CredConfig, error) {
		i := findCred(ccs, id)
		if i < 0 {
			return nil, errCredNotFound
		}
		ccs[i].MaxBytesPerDay = req.MaxBytesPerDay
		return ccs, nil
	})
	if err != nil {
		adminFail(w, err)
		return
	}
	writeJSON(w, map[string]any{"id": req.ID, "max_bytes_per_day": req.MaxBytesPerDay})
}

func (a *adminAPI) handleStats(w http.ResponseWriter, r *http.Request) {
	a.srv.credsMu.RLock()
	ccs := a.srv.credCfgs
	a.srv.credsMu.RUnlock()

	live := make(map[prism.ClientID]int)
	a.srv.actMu.Lock()
	for rec := range a.srv.active {
		live[rec.id]++
	}
	a.srv.actMu.Unlock()

	type snap struct {
		ID             string `json:"id"`
		Name           string `json:"name"`
		BytesUp        int64  `json:"bytes_up"`
		BytesDown      int64  `json:"bytes_down"`
		BytesToday     int64  `json:"bytes_today"`
		MaxBytesPerDay int64  `json:"max_bytes_per_day"`
		ConnCount      int64  `json:"conn_count"`
		LiveSessions   int    `json:"live_sessions"`
		LastSeen       int64  `json:"last_seen"`
	}
	out := make([]snap, 0, len(ccs))
	for _, c := range ccs {
		id, err := prism.ParseClientID(c.ID)
		if err != nil {
			continue
		}
		m := a.srv.acct.meter(id)
		out = append(out, snap{
			ID: c.ID, Name: c.Name,
			BytesUp: m.up.Load(), BytesDown: m.down.Load(),
			BytesToday: m.usedToday(), MaxBytesPerDay: c.MaxBytesPerDay,
			ConnCount: m.conns.Load(), LiveSessions: live[id], LastSeen: m.lastSeen.Load(),
		})
	}
	writeJSON(w, out)
}

// handleSubscription returns one credential's secrets for provisioning a client.
func (a *adminAPI) handleSubscription(w http.ResponseWriter, r *http.Request) {
	id, err := prism.ParseClientID(r.URL.Query().Get("id"))
	if err != nil {
		http.Error(w, "invalid id", http.StatusBadRequest)
		return
	}
	a.srv.credsMu.RLock()
	defer a.srv.credsMu.RUnlock()
	i := findCred(a.srv.credCfgs, id)
	if i < 0 {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	writeJSON(w, map[string]string{
		"id":                a.srv.credCfgs[i].ID,
		"psk":               a.srv.credCfgs[i].PSK,
		"server_public_key": prism.EncodeKey(a.srv.priv.PublicKey().Bytes()),
	})
}

// handleMetrics renders Prometheus text exposition.
func (a *adminAPI) handleMetrics(w http.ResponseWriter, r *http.Request) {
	s := a.srv
	s.credsMu.RLock()
	ccs := s.credCfgs
	s.credsMu.RUnlock()
	live := make(map[prism.ClientID]int)
	s.actMu.Lock()
	total := len(s.active)
	for rec := range s.active {
		live[rec.id]++
	}
	s.actMu.Unlock()

	var b strings.Builder
	metric := func(name, typ, help string) {
		fmt.Fprintf(&b, "# HELP %s %s\n# TYPE %s %s\n", name, help, name, typ)
	}
	metric("prism_sessions", "gauge", "Live authenticated carrier sessions.")
	fmt.Fprintf(&b, "prism_sessions %d\n", total)
	metric("prism_credentials", "gauge", "Provisioned credentials.")
	fmt.Fprintf(&b, "prism_credentials %d\n", len(ccs))
	metric("prism_authenticated_total", "counter", "Carriers that passed the Prism handshake.")
	fmt.Fprintf(&b, "prism_authenticated_total %d\n", s.nAuthed.Load())
	metric("prism_cover_served_total", "counter", "Connections that failed the handshake and were served the cover site.")
	fmt.Fprintf(&b, "prism_cover_served_total %d\n", s.nCover.Load())
	metric("prism_steal_relayed_total", "counter", "Connections relayed to the steal target.")
	fmt.Fprintf(&b, "prism_steal_relayed_total %d\n", s.nStealRelay.Load())

	type row struct {
		labels string
		m      *meter
		quota  int64
		live   int
	}
	rows := make([]row, 0, len(ccs))
	for _, c := range ccs {
		id, err := prism.ParseClientID(c.ID)
		if err != nil {
			continue
		}
		rows = append(rows, row{fmt.Sprintf(`{id=%q,name=%q}`, fmt.Sprintf("%x", id), c.Name), s.acct.meter(id), c.MaxBytesPerDay, live[id]})
	}
	per := func(name, typ, help string, val func(row) int64) {
		metric(name, typ, help)
		for _, r := range rows {
			fmt.Fprintf(&b, "%s%s %d\n", name, r.labels, val(r))
		}
	}
	per("prism_client_sessions", "gauge", "Live sessions per credential.", func(r row) int64 { return int64(r.live) })
	per("prism_client_bytes_up_total", "counter", "Bytes from client to the internet.", func(r row) int64 { return r.m.up.Load() })
	per("prism_client_bytes_down_total", "counter", "Bytes from the internet to client.", func(r row) int64 { return r.m.down.Load() })
	per("prism_client_connects_total", "counter", "Carriers established per credential.", func(r row) int64 { return r.m.conns.Load() })
	per("prism_client_bytes_today", "gauge", "Bytes used in the current UTC day.", func(r row) int64 { return r.m.usedToday() })
	per("prism_client_quota_bytes", "gauge", "Daily quota in bytes (0 = unlimited).", func(r row) int64 { return r.quota })
	per("prism_client_last_seen_seconds", "gauge", "Unix time of the credential's last activity.", func(r row) int64 { return r.m.lastSeen.Load() })

	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	io.WriteString(w, b.String())
}

func (a *adminAPI) mux() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/credentials", a.auth(http.MethodGet, a.handleListCredentials))
	mux.HandleFunc("/api/credentials/add", a.auth(http.MethodPost, a.handleAddCredential))
	mux.HandleFunc("/api/credentials/revoke", a.auth(http.MethodPost, a.handleRevokeCredential))
	mux.HandleFunc("/api/credentials/rotate", a.auth(http.MethodPost, a.handleRotateKey))
	mux.HandleFunc("/api/quota", a.auth(http.MethodPost, a.handleSetQuota))
	mux.HandleFunc("/api/stats", a.auth(http.MethodGet, a.handleStats))
	mux.HandleFunc("/api/subscription", a.auth(http.MethodGet, a.handleSubscription))
	mux.HandleFunc("/metrics", a.auth(http.MethodGet, a.handleMetrics))
	return mux
}

func (a *adminAPI) listenAndServe(addr string) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	if host, _, _ := net.SplitHostPort(addr); host == "" || !net.ParseIP(host).IsLoopback() && host != "localhost" {
		log.Printf("WARNING: admin API on %s is reachable beyond loopback and speaks plain HTTP; "+
			"bind it to 127.0.0.1 and reach it over SSH", addr)
	}
	log.Printf("admin API listening on %s", addr)
	srv := &http.Server{Handler: a.mux(), ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 30 * time.Second}
	return srv.Serve(ln)
}
