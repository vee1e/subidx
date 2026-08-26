package server

import (
	"bufio"
	"context"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"subidx/internal/store"
)

func TestWatchEndpoint(t *testing.T) {
	s, _ := newTestServer(t, 0)

	rec := do(t, s, http.MethodGet, "/v1/watch?apex=example.com&format=ndjson")
	if rec.Code != http.StatusOK {
		t.Fatalf("code = %d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/x-ndjson" {
		t.Errorf("content-type = %q", ct)
	}
	maxSeq, err := strconv.ParseUint(rec.Header().Get("x-max-seq"), 10, 64)
	if err != nil || maxSeq == 0 {
		t.Fatalf("x-max-seq = %q (%v)", rec.Header().Get("x-max-seq"), err)
	}
	lines := strings.Split(strings.TrimSpace(rec.Body.String()), "\n")
	if len(lines) != 3 {
		t.Fatalf("after=0 gave %d lines, want 3", len(lines))
	}

	rec2 := do(t, s, http.MethodGet, "/v1/watch?apex=example.com&format=ndjson&after="+strconv.FormatUint(maxSeq, 10))
	if rec2.Code != http.StatusOK {
		t.Fatalf("delta code = %d", rec2.Code)
	}
	if body := strings.TrimSpace(rec2.Body.String()); body != "" {
		t.Errorf("delta body = %q, want empty", body)
	}
	if rec2.Header().Get("x-max-seq") != strconv.FormatUint(maxSeq, 10) {
		t.Error("delta lost x-max-seq")
	}

	bad := do(t, s, http.MethodGet, "/v1/watch?apex=example.com&after=zero")
	if bad.Code != http.StatusBadRequest {
		t.Errorf("bad after code = %d", bad.Code)
	}
	miss := do(t, s, http.MethodGet, "/v1/watch")
	if miss.Code != http.StatusBadRequest {
		t.Errorf("missing apex code = %d", miss.Code)
	}
}

func TestFeedStream(t *testing.T) {
	s, st := newTestServer(t, 0)
	s.Hub = NewHub()
	defer s.Hub.Close()
	st.OnNew = func(r store.Record) {
		s.Hub.Broadcast(FeedEvent{Apex: r.Apex, Sub: r.Sub, FirstSeen: r.FirstSeen, Seq: r.Seq})
	}

	hs := httptest.NewServer(s.Handler())
	defer hs.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, hs.URL+"/v1/feed?apex=example.com", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("code = %d", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "text/event-stream" {
		t.Fatalf("content-type = %q", ct)
	}

	lines := make(chan string, 64)
	go func() {
		sc := bufio.NewScanner(resp.Body)
		for sc.Scan() {
			lines <- sc.Text()
		}
		close(lines)
	}()
	readUntil := func(substr string, d time.Duration) bool {
		timeout := time.After(d)
		for {
			select {
			case ln, ok := <-lines:
				if !ok {
					return false
				}
				if strings.Contains(ln, substr) {
					return true
				}
			case <-timeout:
				return false
			}
		}
	}

	if !readUntil("retry:", 3*time.Second) {
		t.Fatal("no retry preamble")
	}

	if err := st.Ingest(store.Record{Apex: "example.com", Sub: "zz.example.com", FirstSeen: 1240000000000, Source: 1}); err != nil {
		t.Fatal(err)
	}
	if !readUntil("zz.example.com", 5*time.Second) {
		t.Fatal("no event delivered for matching record")
	}

	if err := st.Ingest(store.Record{Apex: "other.example", Sub: "secret.other.example", FirstSeen: 1240000000000, Source: 1}); err != nil {
		t.Fatal(err)
	}
	if readUntil("secret.other.example", 1500*time.Millisecond) {
		t.Fatal("event leaked across apex filter")
	}
}
