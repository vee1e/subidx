package rfc6962

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
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

// signedSTH builds a TreeHeadSignature over the given fields, mirroring
// RFC 6962 §4.1, with overridable hash/sig algorithm bytes.
func signedSTH(t *testing.T, key *ecdsa.PrivateKey, ts, size int64, root []byte, hashAlg, sigAlg byte) []byte {
	t.Helper()
	input := make([]byte, 0, 2+8+8+len(root))
	input = append(input, 0, 1)
	input = binary.BigEndian.AppendUint64(input, uint64(ts))
	input = binary.BigEndian.AppendUint64(input, uint64(size))
	input = append(input, root...)
	digest := sha256.Sum256(input)
	sig, err := ecdsa.SignASN1(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	out := []byte{hashAlg, sigAlg}
	out = binary.BigEndian.AppendUint16(out, uint16(len(sig)))
	return append(out, sig...)
}

func TestVerifySTH(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	_ = der
	c := &Client{pubKey: &key.PublicKey}
	root := make([]byte, 32)
	for i := range root {
		root[i] = byte(i)
	}
	ts, size := int64(1700000000000), int64(42)

	sth := &STH{TreeSize: size, Timestamp: ts, SHA256RootHash: root,
		TreeHeadSignature: signedSTH(t, key, ts, size, root, 4, 3)}
	if err := c.VerifySTH(sth); err != nil {
		t.Fatalf("valid STH rejected: %v", err)
	}

	// Forged: signed by a different key.
	wrongKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	sth.TreeHeadSignature = signedSTH(t, wrongKey, ts, size, root, 4, 3)
	if err := c.VerifySTH(sth); err == nil {
		t.Fatal("forged STH accepted")
	}

	// Root hash tampered after signing (also covers wrong length).
	sth.TreeHeadSignature = signedSTH(t, key, ts, size, root, 4, 3)
	sth.SHA256RootHash = root[:31]
	if err := c.VerifySTH(sth); err == nil {
		t.Fatal("short root hash accepted")
	}

	// Mismatched hash algorithm (sha1 instead of sha256).
	sth.SHA256RootHash = root
	sth.TreeHeadSignature = signedSTH(t, key, ts, size, root, 2, 3)
	if err := c.VerifySTH(sth); err == nil {
		t.Fatal("sha1-labeled signature accepted")
	}

	// Mismatched signature algorithm (rsa label on an ecdsa key).
	sth.TreeHeadSignature = signedSTH(t, key, ts, size, root, 4, 1)
	if err := c.VerifySTH(sth); err == nil {
		t.Fatal("rsa-labeled signature accepted for ecdsa key")
	}

	// Negative tree size.
	sth.TreeHeadSignature = signedSTH(t, key, ts, size, root, 4, 3)
	sth.TreeSize = -1
	if err := c.VerifySTH(sth); err == nil {
		t.Fatal("negative tree size accepted")
	}
}
