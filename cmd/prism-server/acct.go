package main

import (
	"io"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gloridust/prism/pkg/prism"
)

// meter is one credential's traffic accounting and daily quota. All sessions of
// a credential share one meter. Counters live in memory, so totals and the
// current day's usage restart from zero when the server restarts.
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
