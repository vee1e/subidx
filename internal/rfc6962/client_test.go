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
