package server

import (
	"fmt"
	"net/http/httptest"
	"testing"
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
