package server

import (
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
