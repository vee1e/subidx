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
	limit  int64
	window time.Duration
	shards [64]limShard
}

type limShard struct {
	mu      sync.Mutex
	buckets map[string][]time.Time
}

func NewLimiter(limit int64, window time.Duration) *Limiter {
	l := &Limiter{limit: limit, window: window}
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
		shard.mu.Unlock()
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
		idx := len(chain) - trustedHops
		if idx >= 0 && idx < len(chain) {
			ipStr = chain[idx]
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
