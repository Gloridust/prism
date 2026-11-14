package prism

import (
	"hash/maphash"
	"sync"
	"time"
)

// ReplayWindow rejects a client ephemeral public key that has already been seen
// inside the freshness window. Because every handshake uses a fresh ephemeral,
// a duplicate is necessarily a replayed ClientInit. Memory is bounded by the
// number of handshakes per window; entries expire lazily.
type ReplayWindow struct {
	ttl  time.Duration
	mu   sync.Mutex
	seed maphash.Seed
	seen map[uint64]int64 // hash(E_pub) -> expiry unix-nano
	next int64            // next lazy-sweep time (unix-nano)
}

// NewReplayWindow builds a replay guard that remembers ephemerals for ttl.
func NewReplayWindow(ttl time.Duration) *ReplayWindow {
	return &ReplayWindow{
		ttl:  ttl,
		seed: maphash.MakeSeed(),
		seen: make(map[uint64]int64),
	}
}

// Accept records ePub and returns true if it is new, false if it is a replay.
func (r *ReplayWindow) Accept(ePub []byte) bool {
	var h maphash.Hash
	h.SetSeed(r.seed)
	h.Write(ePub)
	key := h.Sum64()

	now := time.Now().UnixNano()
	r.mu.Lock()
	defer r.mu.Unlock()

	if now >= r.next {
		for k, exp := range r.seen {
			if exp <= now {
				delete(r.seen, k)
			}
		}
		r.next = now + r.ttl.Nanoseconds()
	}
	if exp, ok := r.seen[key]; ok && exp > now {
		return false
	}
	r.seen[key] = now + r.ttl.Nanoseconds()
	return true
}
