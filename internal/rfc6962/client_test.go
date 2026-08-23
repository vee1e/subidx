package rfc6962

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

func testKeyB64(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(der)
}

func TestNewClientTrimsTrailingSlash(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.URL.Path != "/ct/v1/get-sth" {
			t.Errorf("request path = %q; want /ct/v1/get-sth", r.URL.Path)
		}
		w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	c, err := NewClient(srv.URL+"/", testKeyB64(t))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.STH(context.Background()); err != nil {
		t.Fatal(err)
	}
	if hits.Load() == 0 {
		t.Fatal("no request reached the server")
	}
}

func TestNewClientRejectsPlainHTTP(t *testing.T) {
	if _, err := NewClient("http://ct.example.com/", testKeyB64(t)); err == nil {
		t.Fatal("NewClient should reject non-loopback plain http")
	}
}

func TestClientDoesNotFollowRedirects(t *testing.T) {
	var targetHits atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		targetHits.Add(1)
		w.Write([]byte(`{}`))
	}))
	defer target.Close()

	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+"/ct/v1/get-sth", http.StatusFound)
	}))
	defer source.Close()

	c, err := NewClient(source.URL, testKeyB64(t)) // loopback http is allowed
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.STH(context.Background())
	if err == nil {
		t.Fatal("STH via redirecting server should fail")
	}
	if targetHits.Load() != 0 {
		t.Fatalf("redirect was followed to target (%d hits)", targetHits.Load())
	}
}
