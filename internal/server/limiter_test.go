package server

import (
	"fmt"
	"net/http/httptest"
	"testing"
	"time"
)

func TestClientKeyIgnoresBogusXFF(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "10.0.0.1:1234"
	direct := ClientKey(req, 1)

	// A garbage XFF entry must not become the rate limit key.
	req.Header.Set("X-Forwarded-For", "not-an-ip")
	if got := ClientKey(req, 1); got != direct {
		t.Errorf("bogus XFF key = %q, want fallback %q", got, direct)
	}

	// A well-formed chain with one trusted hop selects the client IP.
	req.Header.Set("X-Forwarded-For", "203.0.113.7, 10.0.0.2")
	if got := ClientKey(req, 1); got != "10.0.0.2" {
		t.Errorf("proxied key = %q, want 10.0.0.2", got)
	}
}

func TestLimiterBucketsBounded(t *testing.T) {
	l := NewLimiter(1000, timeHour())
	for i := 0; i < 20000; i++ {
		l.Allow(string(rune('a'+i%26)) + fmt.Sprintf("%d", i))
	}
	total := 0
	for i := range l.shards {
		total += len(l.shards[i].buckets)
	}
	if total > maxBucketsPerShard*64 {
		t.Errorf("buckets = %d, want <= %d", total, maxBucketsPerShard*64)
	}
}

func TestLimiterFullShardEvictsLRU(t *testing.T) {
	l := &Limiter{limit: 10, window: time.Hour, maxBuckets: 2}
	for i := range l.shards {
		l.shards[i].buckets = make(map[string]*bucket)
	}
	first := "client-a"
	var stale, peer string
	for i := 0; i < 100000 && (stale == "" || peer == ""); i++ {
		k := fmt.Sprintf("k%d", i)
		if shardIndex(k) != shardIndex(first) || k == first {
			continue
		}
		if stale == "" {
			stale = k
			continue
		}
		peer = k
	}
	if stale == "" || peer == "" {
		t.Fatal("not enough keys hashing to the same shard")
	}

	if _, ok, _ := l.Allow(first); !ok {
		t.Fatal("first key should be admitted")
	}
	if _, ok, _ := l.Allow(stale); !ok {
		t.Fatal("stale key should be admitted")
	}
	// first is now the most recently used; stale is the LRU.
	if rem, ok, _ := l.Allow(first); !ok || rem != 8 {
		t.Fatalf("first second allow remaining=%d ok=%v; want 8, true", rem, ok)
	}
	if _, ok, _ := l.Allow(peer); !ok {
		t.Fatal("peer should be admitted by evicting the LRU key")
	}
	rem, ok, _ := l.Allow(first)
	if !ok {
		t.Fatal("recently used first key must survive LRU eviction")
	}
	if rem != 7 {
		t.Fatalf("first remaining = %d, want 7 (bucket was reset if it was evicted)", rem)
	}
	rem, ok, _ = l.Allow(stale)
	if !ok {
		t.Fatal("evicted stale key should be re-admitted as a fresh bucket")
	}
	if rem != 9 {
		t.Fatalf("re-admitted stale remaining = %d, want 9", rem)
	}
}
