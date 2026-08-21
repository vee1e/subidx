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

// maxBucketsPerShard bounds memory: each tracked key holds a hit list for
// up to one window. Distinct keys are cheap to mint (spoofed XFF, IPv6
// /64s), so the map must not grow without bound.
const maxBucketsPerShard = 4096

type limShard struct {
	mu      sync.Mutex
	buckets map[string][]time.Time
}

func NewLimiter(limit int64, window time.Duration) *Limiter {
	l := &Limiter{limit: limit, window: window, maxBuckets: maxBucketsPerShard}
	for i := range l.shards {
		l.shards[i].buckets = make(map[string][]time.Time)
	}
	return l
}

func (l *Limiter) Allow(key string) (remaining int64, ok bool, retryAfter time.Duration) {
	now := time.Now()
	shard := &l.shards[shardIndex(key)]
	shard.mu.Lock()
	defer shard.mu.Unlock()
	if len(shard.buckets) >= l.maxBuckets && shard.buckets[key] == nil {
		l.evictShard(shard, now)
	}
	hits := shard.buckets[key]
	cutoff := now.Add(-l.window)
	i := 0
	for i < len(hits) && hits[i].Before(cutoff) {
		i++
	}
	hits = hits[i:]
	if int64(len(hits)) >= l.limit {
		retry := l.window - now.Sub(hits[0])
		if retry < time.Second {
			retry = time.Second
		}
		shard.buckets[key] = hits
		return 0, false, retry
	}
	hits = append(hits, now)
	shard.buckets[key] = hits
	return l.limit - int64(len(hits)), true, 0
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

// evictShard makes room in a full shard: expired buckets first, then
// arbitrary victims if the attack is still filling the window.
func (l *Limiter) evictShard(shard *limShard, now time.Time) {
	l.trimShard(shard, now.Add(-l.window))
	for len(shard.buckets) >= l.maxBuckets {
		victimized := false
		for k := range shard.buckets {
			delete(shard.buckets, k)
			victimized = true
			break
		}
		if !victimized {
			break
		}
	}
}

func (l *Limiter) trimShard(shard *limShard, cutoff time.Time) {
	for k, hits := range shard.buckets {
		j := 0
		for j < len(hits) && hits[j].Before(cutoff) {
			j++
		}
		if j == len(hits) {
			delete(shard.buckets, k)
		} else {
			shard.buckets[k] = hits[j:]
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
	return int(h) % 64
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
