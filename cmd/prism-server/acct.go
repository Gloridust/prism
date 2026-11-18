package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gloridust/prism/pkg/prism"
)

// meter is one credential's traffic accounting and daily quota. All sessions of
// a credential share one meter. Meters are saved to the stats file (when one
// is configured) so totals and the current day's usage survive a restart.
type meter struct {
	up, down atomic.Int64 // lifetime totals (client→internet, internet→client)
	conns    atomic.Int64
	lastSeen atomic.Int64 // unix seconds
	quota    atomic.Int64 // bytes per UTC day; 0 = unlimited

	mu      sync.Mutex
	day     int64 // UTC day number the daily counter belongs to
	dayUsed int64
}

func utcDay(t time.Time) int64 { return t.Unix() / 86400 }

// add records traffic and reports whether the credential is still within quota.
func (m *meter) add(up, down int64) bool {
	m.up.Add(up)
	m.down.Add(down)
	now := time.Now()
	m.lastSeen.Store(now.Unix())

	m.mu.Lock()
	defer m.mu.Unlock()
	if d := utcDay(now); d != m.day {
		m.day, m.dayUsed = d, 0
	}
	m.dayUsed += up + down
	q := m.quota.Load()
	return q <= 0 || m.dayUsed < q
}

func (m *meter) allowed() bool { return m.add(0, 0) }

func (m *meter) usedToday() int64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	if utcDay(time.Now()) != m.day {
		return 0
	}
	return m.dayUsed
}

// accounting maps credentials to their meters.
type accounting struct {
	mu     sync.Mutex
	meters map[prism.ClientID]*meter
}

func newAccounting() *accounting {
	return &accounting{meters: make(map[prism.ClientID]*meter)}
}

func (a *accounting) meter(id prism.ClientID) *meter {
	a.mu.Lock()
	defer a.mu.Unlock()
	m := a.meters[id]
	if m == nil {
		m = &meter{}
		a.meters[id] = m
	}
	return m
}

// syncQuotas applies the configured quotas and forgets removed credentials.
func (a *accounting) syncQuotas(ccs []CredConfig) {
	keep := make(map[prism.ClientID]bool, len(ccs))
	for _, cc := range ccs {
		id, err := prism.ParseClientID(cc.ID)
		if err != nil {
			continue
		}
		keep[id] = true
		a.meter(id).quota.Store(cc.MaxBytesPerDay)
	}
	a.mu.Lock()
	for id := range a.meters {
		if !keep[id] {
			delete(a.meters, id)
		}
	}
	a.mu.Unlock()
}

// copyMetered copies src to dst, calling account with each chunk's size. It
// stops when account returns false (quota exhausted).
func copyMetered(dst io.Writer, src io.Reader, account func(n int64) bool) {
	buf := make([]byte, 32*1024)
	for {
		n, err := src.Read(buf)
		if n > 0 {
			if _, werr := dst.Write(buf[:n]); werr != nil {
				return
			}
			if !account(int64(n)) {
				return
			}
		}
		if err != nil {
			return
		}
	}
}

// meterState is a meter's persisted form.
type meterState struct {
	Up       int64 `json:"up"`
	Down     int64 `json:"down"`
	Conns    int64 `json:"conns"`
	LastSeen int64 `json:"last_seen"`
	Day      int64 `json:"day"`
	DayUsed  int64 `json:"day_used"`
}

// save writes every meter to path atomically, so totals and the current day's
// quota usage survive a restart.
func (a *accounting) save(path string) error {
	a.mu.Lock()
	out := make(map[string]meterState, len(a.meters))
	for id, m := range a.meters {
		m.mu.Lock()
		out[fmt.Sprintf("%x", id[:])] = meterState{
			Up: m.up.Load(), Down: m.down.Load(), Conns: m.conns.Load(),
			LastSeen: m.lastSeen.Load(), Day: m.day, DayUsed: m.dayUsed,
		}
		m.mu.Unlock()
	}
	a.mu.Unlock()

	raw, err := json.Marshal(out)
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// load restores meters saved by save. A missing file is not an error.
func (a *accounting) load(path string) error {
	raw, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	var in map[string]meterState
	if err := json.Unmarshal(raw, &in); err != nil {
		return err
	}
	for hexID, st := range in {
		b, err := hex.DecodeString(hexID)
		if err != nil || len(b) != 4 {
			continue
		}
		m := a.meter(prism.ClientID(b))
		m.up.Store(st.Up)
		m.down.Store(st.Down)
		m.conns.Store(st.Conns)
		m.lastSeen.Store(st.LastSeen)
		m.mu.Lock()
		m.day, m.dayUsed = st.Day, st.DayUsed
		m.mu.Unlock()
	}
	return nil
}

// persist saves to path every interval until stop is closed.
func (a *accounting) persist(path string, every time.Duration, stop <-chan struct{}) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			if err := a.save(path); err != nil {
				log.Printf("saving stats to %s: %v", path, err)
			}
		case <-stop:
			return
		}
	}
}
