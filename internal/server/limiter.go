package server

import (
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"
)

type Limiter struct {
	limit      int64
	window     time.Duration
	maxBuckets int
	shards     [64]limShard
}

// maxBucketsPerShard bounds memory: each tracked key holds a fixed-size
// token bucket. Distinct keys are cheap to mint (spoofed XFF, IPv6
// /64s), so the map must not grow without bound.
const maxBucketsPerShard = 4096

type bucket struct {
	tokens float64
	last   time.Time
}

type limShard struct {
	mu      sync.Mutex
	buckets map[string]*bucket
}

func NewLimiter(limit int64, window time.Duration) *Limiter {
	l := &Limiter{limit: limit, window: window, maxBuckets: maxBucketsPerShard}
	for i := range l.shards {
		l.shards[i].buckets = make(map[string]*bucket)
	}
	return l
}

func (l *Limiter) Allow(key string) (remaining int64, ok bool, retryAfter time.Duration) {
	now := time.Now()
	shard := &l.shards[shardIndex(key)]
	shard.mu.Lock()
	defer shard.mu.Unlock()
	b := shard.buckets[key]
	if b == nil {
		if len(shard.buckets) >= l.maxBuckets {
			l.evictLRU(shard)
		}
		b = &bucket{tokens: float64(l.limit), last: now}
		shard.buckets[key] = b
	}
	rate := float64(l.limit) / l.window.Seconds()
	if rate <= 0 {
		return 0, false, l.window
	}
	elapsed := now.Sub(b.last).Seconds()
	if elapsed > 0 {
		filled := b.tokens + elapsed*rate
		if filled > float64(l.limit) {
			filled = float64(l.limit)
		}
		b.tokens = filled
	}
	b.last = now
	if b.tokens < 1 {
		retry := time.Duration((1 - b.tokens) / rate * float64(time.Second))
		if retry < time.Second {
			retry = time.Second
		}
		return 0, false, retry
	}
	b.tokens -= 1
	return int64(b.tokens), true, 0
}

func (l *Limiter) evictLRU(shard *limShard) {
	var oldestKey string
	var oldest time.Time
	first := true
	for k, b := range shard.buckets {
		if first || b.last.Before(oldest) {
			oldestKey = k
			oldest = b.last
			first = false
		}
	}
	if oldestKey != "" {
		delete(shard.buckets, oldestKey)
	}
}

func (l *Limiter) sweep() {
	cutoff := time.Now().Add(-l.window)
	for i := range l.shards {
		shard := &l.shards[i]
		shard.mu.Lock()
		l.trimShard(shard, cutoff)
		shard.mu.Unlock()
	}
}

// trimShard drops buckets that have been idle past cutoff and are fully refilled.
func (l *Limiter) trimShard(shard *limShard, cutoff time.Time) {
	for k, b := range shard.buckets {
		if !b.last.After(cutoff) && b.tokens >= float64(l.limit)-1e-9 {
			delete(shard.buckets, k)
		} else if !b.last.After(cutoff) {
			// Fully idle for a window: tokens have refilled; drop the state.
			delete(shard.buckets, k)
		}
	}
}

func (l *Limiter) StartSweeper(stop <-chan struct{}) {
	go func() {
		t := time.NewTicker(10 * time.Minute)
		defer t.Stop()
		for {
			select {
			case <-stop:
				return
			case <-t.C:
				l.sweep()
			}
		}
	}()
}

func shardIndex(key string) int {
	var h uint32
	for i := 0; i < len(key); i++ {
		h = h*31 + uint32(key[i])
	}
	return int(h % 64)
}

func ClientKey(r *http.Request, trustedHops int) string {
	ipStr := remoteIP(r)
	if trustedHops > 0 {
		var chain []string
		for _, v := range r.Header.Values("X-Forwarded-For") {
			for _, part := range strings.Split(v, ",") {
				chain = append(chain, strings.TrimSpace(part))
			}
		}
		// The last trustedHops entries are the ones our trusted proxies
		// appended. If any of them is not a valid IP the header is bogus,
		// so fall back to the connection address instead of indexing into
		// client-controlled data.
		if len(chain) >= trustedHops && len(chain) <= 64 {
			trusted := chain[len(chain)-trustedHops:]
			bogus := false
			for _, p := range trusted {
				if _, err := netip.ParseAddr(p); err != nil {
					bogus = true
					break
				}
			}
			if !bogus {
				ipStr = trusted[0]
			}
		}
	}
	addr, err := netip.ParseAddr(ipStr)
	if err != nil {
		return "invalid:" + ipStr
	}
	if addr.Is4() || addr.Is4In6() {
		return addr.Unmap().String()
	}
	return netip.PrefixFrom(addr, 64).Masked().String()
}

func remoteIP(r *http.Request) string {
	host := r.RemoteAddr
	if h, _, err := net.SplitHostPort(host); err == nil {
		return h
	}
	return host
}

func fmtRetry(d time.Duration) string {
	s := int((d + time.Second - 1) / time.Second)
	return fmt.Sprintf("%d", s)
}
