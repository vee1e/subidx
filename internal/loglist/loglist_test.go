package loglist

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestFetchOneHonorsContext(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-release
		w.Write([]byte(`{}`))
	}))
	defer func() {
		close(release)
		srv.Close()
	}()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	start := time.Now()
	if _, err := fetchOne(ctx, srv.Client(), srv.URL); err == nil {
		t.Fatal("fetchOne with canceled context should fail")
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("canceled fetch took %v; want immediate return", elapsed)
	}
}

func TestFetchOneRejectsBadStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "nope", http.StatusInternalServerError)
	}))
	defer srv.Close()
	if _, err := fetchOne(context.Background(), srv.Client(), srv.URL); err == nil {
		t.Fatal("fetchOne should fail on 500")
	}
}
