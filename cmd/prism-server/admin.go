package main

import (
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gloridust/prism/pkg/prism"
)

// AdminConfig is the optional management API config.
type AdminConfig struct {
	Listen string `json:"listen"` // e.g. "127.0.0.1:9090"
	Token  string `json:"token"`  // bearer token for auth
}

// CIDQuota holds per-client traffic limits.
type CIDQuota struct {
	MaxBytesPerDay int64 `json:"max_bytes_per_day"` // 0 = unlimited
}

// CIDStats holds per-client traffic counters.
type CIDStats struct {
	BytesUp   atomic.Int64
	BytesDown atomic.Int64
	ConnCount atomic.Int64
	LastSeen  atomic.Int64 // unix timestamp
}

// CIDStatsSnapshot is the JSON-safe version of CIDStats.
type CIDStatsSnapshot struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	BytesUp   int64  `json:"bytes_up"`
	BytesDown int64  `json:"bytes_down"`
	ConnCount int64  `json:"conn_count"`
	LastSeen  int64  `json:"last_seen"`
}

// adminAPI is the management API server.
type adminAPI struct {
	srv   *server
	token string

	quotaMu sync.RWMutex
	quotas  map[prism.ClientID]*CIDQuota

	statsMu sync.RWMutex
	stats   map[prism.ClientID]*CIDStats
}

func newAdminAPI(srv *server, token string) *adminAPI {
	return &adminAPI{
		srv:    srv,
		token:  token,
		quotas: make(map[prism.ClientID]*CIDQuota),
		stats:  make(map[prism.ClientID]*CIDStats),
	}
}

func (a *adminAPI) auth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost && r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		tok := r.Header.Get("Authorization")
		if len(tok) > 7 && tok[:7] == "Bearer " {
			tok = tok[7:]
		}
		if subtle.ConstantTimeCompare([]byte(tok), []byte(a.token)) != 1 {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}

func (a *adminAPI) handleListCredentials(w http.ResponseWriter, r *http.Request) {
	a.srv.credsMu.RLock()
	creds := a.srv.creds
	a.srv.credsMu.RUnlock()

	type credInfo struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	}
	out := make([]credInfo, 0, len(creds))
	for _, c := range creds {
		out = append(out, credInfo{
			ID:   prism.EncodeKey(c.ID[:]),
			Name: c.Name,
		})
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(out)
}

func (a *adminAPI) handleAddCredential(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	psk, err := prism.NewPSK()
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	id, err := prism.NewClientID()
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	cred := prism.Credential{ID: id, PSK: psk, Name: req.Name}
	a.srv.credsMu.Lock()
	a.srv.creds = append(a.srv.creds, cred)
	a.srv.credsMu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"id":   prism.EncodeKey(id[:]),
		"psk":  prism.EncodeKey(psk),
		"name": req.Name,
	})
	log.Printf("admin: added credential %q (%x)", req.Name, id)
}

func (a *adminAPI) handleRevokeCredential(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	id, err := prism.ParseClientID(req.ID)
	if err != nil {
		http.Error(w, "invalid id", http.StatusBadRequest)
		return
	}

	a.srv.credsMu.Lock()
	found := false
	newCreds := make([]prism.Credential, 0, len(a.srv.creds))
	for _, c := range a.srv.creds {
		if c.ID == id {
			found = true
			continue
		}
		newCreds = append(newCreds, c)
	}
	a.srv.creds = newCreds
	a.srv.credsMu.Unlock()

	if !found {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}

	// Kick active sessions for this credential.
	a.srv.actMu.Lock()
	var kick []*sessConn
	for r := range a.srv.active {
		if r.id == id {
			kick = append(kick, r)
		}
	}
	a.srv.actMu.Unlock()
	for _, r := range kick {
		r.sess.Close()
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"revoked": true,
		"kicked":  len(kick),
	})
	log.Printf("admin: revoked credential %x, kicked %d session(s)", id, len(kick))
}

func (a *adminAPI) handleRotateKey(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	id, err := prism.ParseClientID(req.ID)
	if err != nil {
		http.Error(w, "invalid id", http.StatusBadRequest)
		return
	}
	newPSK, err := prism.NewPSK()
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	a.srv.credsMu.Lock()
	found := false
	for i := range a.srv.creds {
		if a.srv.creds[i].ID == id {
			a.srv.creds[i].PSK = newPSK
			found = true
			break
		}
	}
	a.srv.credsMu.Unlock()

	if !found {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"id":      prism.EncodeKey(id[:]),
		"new_psk": prism.EncodeKey(newPSK),
	})
	log.Printf("admin: rotated PSK for %x", id)
}

func (a *adminAPI) handleSetQuota(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID             string `json:"id"`
		MaxBytesPerDay int64  `json:"max_bytes_per_day"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	id, err := prism.ParseClientID(req.ID)
	if err != nil {
		http.Error(w, "invalid id", http.StatusBadRequest)
		return
	}

	a.quotaMu.Lock()
	a.quotas[id] = &CIDQuota{MaxBytesPerDay: req.MaxBytesPerDay}
	a.quotaMu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"id":               prism.EncodeKey(id[:]),
		"max_bytes_per_day": req.MaxBytesPerDay,
	})
}

func (a *adminAPI) handleStats(w http.ResponseWriter, r *http.Request) {
	a.srv.credsMu.RLock()
	creds := a.srv.creds
	a.srv.credsMu.RUnlock()

	a.statsMu.RLock()
	defer a.statsMu.RUnlock()

	out := make([]CIDStatsSnapshot, 0, len(creds))
	for _, c := range creds {
		snap := CIDStatsSnapshot{
			ID:   fmt.Sprintf("%x", c.ID),
			Name: c.Name,
		}
		if s, ok := a.stats[c.ID]; ok {
			snap.BytesUp = s.BytesUp.Load()
			snap.BytesDown = s.BytesDown.Load()
			snap.ConnCount = s.ConnCount.Load()
			snap.LastSeen = s.LastSeen.Load()
		}
		out = append(out, snap)
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(out)
}

func (a *adminAPI) handleSubscription(w http.ResponseWriter, r *http.Request) {
	idStr := r.URL.Query().Get("id")
	if idStr == "" {
		http.Error(w, "missing id parameter", http.StatusBadRequest)
		return
	}
	id, err := prism.ParseClientID(idStr)
	if err != nil {
		http.Error(w, "invalid id", http.StatusBadRequest)
		return
	}

	a.srv.credsMu.RLock()
	var found *prism.Credential
	for i := range a.srv.creds {
		if a.srv.creds[i].ID == id {
			found = &a.srv.creds[i]
			break
		}
	}
	a.srv.credsMu.RUnlock()

	if found == nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}

	// Return a client config template for this credential.
	cfg := map[string]interface{}{
		"id":  prism.EncodeKey(found.ID[:]),
		"psk": prism.EncodeKey(found.PSK),
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(cfg)
}

// recordTraffic records per-CID traffic for accounting.
func (a *adminAPI) recordTraffic(id prism.ClientID, up, down int64) {
	a.statsMu.RLock()
	s, ok := a.stats[id]
	a.statsMu.RUnlock()
	if !ok {
		a.statsMu.Lock()
		s, ok = a.stats[id]
		if !ok {
			s = &CIDStats{}
			a.stats[id] = s
		}
		a.statsMu.Unlock()
	}
	s.BytesUp.Add(up)
	s.BytesDown.Add(down)
	s.LastSeen.Store(time.Now().Unix())
}

// recordConnect records a new connection for a CID.
func (a *adminAPI) recordConnect(id prism.ClientID) {
	a.statsMu.RLock()
	s, ok := a.stats[id]
	a.statsMu.RUnlock()
	if !ok {
		a.statsMu.Lock()
		s, ok = a.stats[id]
		if !ok {
			s = &CIDStats{}
			a.stats[id] = s
		}
		a.statsMu.Unlock()
	}
	s.ConnCount.Add(1)
	s.LastSeen.Store(time.Now().Unix())
}

// checkQuota returns true if the CID is within its daily quota.
func (a *adminAPI) checkQuota(id prism.ClientID) bool {
	a.quotaMu.RLock()
	q, ok := a.quotas[id]
	a.quotaMu.RUnlock()
	if !ok || q.MaxBytesPerDay <= 0 {
		return true // no quota
	}
	a.statsMu.RLock()
	s, ok := a.stats[id]
	a.statsMu.RUnlock()
	if !ok {
		return true
	}
	total := s.BytesUp.Load() + s.BytesDown.Load()
	return total < q.MaxBytesPerDay
}

func (a *adminAPI) listenAndServe(addr string) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/credentials", a.auth(a.handleListCredentials))
	mux.HandleFunc("/api/credentials/add", a.auth(a.handleAddCredential))
	mux.HandleFunc("/api/credentials/revoke", a.auth(a.handleRevokeCredential))
	mux.HandleFunc("/api/credentials/rotate", a.auth(a.handleRotateKey))
	mux.HandleFunc("/api/quota", a.auth(a.handleSetQuota))
	mux.HandleFunc("/api/stats", a.auth(a.handleStats))
	mux.HandleFunc("/api/subscription", a.auth(a.handleSubscription))

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	log.Printf("admin API listening on %s", addr)
	return http.Serve(ln, mux)
}
