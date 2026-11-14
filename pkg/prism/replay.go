package prism

import (
	"encoding/binary"
	"sync"
	"time"
)

// ReplayCache 在时间窗内记录已见过的客户端临时公钥，拒绝重放。
// 轻量实现：map[string]deadline + 惰性清理；窗口应 >= 2*handshakeWindow。
type ReplayCache struct {
	mu     sync.Mutex
	seen   map[string]int64 // key -> 过期 Unix 秒
	window int64
	last   int64 // 上次清理时间
}

// NewReplayCache window 为保留秒数（默认取 2*handshakeWindow=180s 较安全）。
func NewReplayCache(window int64) *ReplayCache {
	if window <= 0 {
		window = 2 * handshakeWindow
	}
	return &ReplayCache{seen: make(map[string]int64), window: window}
}

// Add 登记一个临时公钥；若此前已见（重放）返回 false。
func (r *ReplayCache) Add(ephPub []byte) bool {
	now := time.Now().Unix()
	key := string(ephPub)

	r.mu.Lock()
	defer r.mu.Unlock()

	if now-r.last > r.window {
		r.prune(now)
		r.last = now
	}
	if exp, ok := r.seen[key]; ok && exp > now {
		return false
	}
	r.seen[key] = now + r.window
	return true
}

func (r *ReplayCache) prune(now int64) {
	for k, exp := range r.seen {
		if exp <= now {
			delete(r.seen, k)
		}
	}
}

// 占位：确保 binary 被引用（后续可能用于更紧凑的 key 编码）
var _ = binary.BigEndian
