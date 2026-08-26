package server

import (
	"compress/gzip"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"subidx/internal/store"
)

func newTestServer(t *testing.T, rate int64) (*Server, *store.Store) {
	t.Helper()
	st, err := store.Open(t.TempDir() + "/db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	seq := uint64(0)
	for _, r := range []store.Record{
		{Apex: "example.com", Sub: "example.com", FirstSeen: 1210000000000, Source: 1},
		{Apex: "example.com", Sub: "www.example.com", FirstSeen: 1220000000000, Source: 1},
		{Apex: "example.com", Sub: "api.example.com", FirstSeen: 1230000000000, Source: 1},
	} {
		if err := st.Ingest(r); err != nil {
			t.Fatal(err)
		}
		seq++
	}
	waitIngest(t, st)
	s := &Server{Store: st, RateLimit: rate}
	if rate > 0 {
		s.Limiter = NewLimiter(rate, timeHour())
	}
	return s, st
}

func waitIngest(t *testing.T, st *store.Store) {
	t.Helper()
	for i := 0; i < 200; i++ {
		n, err := st.Total()
		if err == nil && n >= 3 {
			return
		}
		sleepTiny()
	}
	t.Fatal("ingest did not settle")
}

func do(t *testing.T, s *Server, method, target string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, target, nil)
	req.Host = "localhost"
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	return rec
}

func TestSearchKnownText(t *testing.T) {
	s, _ := newTestServer(t, 0)
	rec := do(t, s, "GET", "/v1/search?apex=example.com")
	if rec.Code != 200 {
		t.Fatalf("code = %d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "text/plain; charset=utf-8" {
		t.Errorf("content-type = %q", ct)
	}
	want := "example.com\nwww.example.com\napi.example.com\n"
	if rec.Body.String() != want {
		t.Errorf("body = %q, want %q", rec.Body.String(), want)
	}
}

func TestSearchUnknownEmpty200(t *testing.T) {
	s, _ := newTestServer(t, 0)
	rec := do(t, s, "GET", "/v1/search?apex=noexist999888777xyz.com")
	if rec.Code != 200 || rec.Body.Len() != 0 {
		t.Errorf("unknown apex: code=%d body=%q", rec.Code, rec.Body.String())
	}
	jrec := do(t, s, "GET", "/v1/search?apex=noexist999888777xyz.com&format=json")
	if jrec.Code != 200 || strings.TrimSpace(jrec.Body.String()) != "[]" {
		t.Errorf("json miss: code=%d body=%q", jrec.Code, jrec.Body.String())
	}
}

func TestSearchInvalid(t *testing.T) {
	s, _ := newTestServer(t, 0)
	rec := do(t, s, "GET", "/v1/search?apex=not_a_domain")
	if rec.Code != 400 {
		t.Fatalf("code = %d", rec.Code)
	}
	if !strings.HasPrefix(rec.Body.String(), "invalid apex: idna: disallowed rune U+005F") {
		t.Errorf("body = %q", rec.Body.String())
	}
	sub := do(t, s, "GET", "/v1/search?apex=www.example.com")
	if sub.Code != 400 || !strings.Contains(sub.Body.String(), "not an eTLD+1") {
		t.Errorf("subdomain apex: code=%d body=%q", sub.Code, sub.Body.String())
	}
	miss := do(t, s, "GET", "/v1/search")
	if miss.Code != 400 || miss.Body.String() != "missing apex parameter\n" {
		t.Errorf("missing param: code=%d body=%q", miss.Code, miss.Body.String())
	}
}

func TestSearchCaseFold(t *testing.T) {
	s, _ := newTestServer(t, 0)
	rec := do(t, s, "GET", "/v1/search?apex=EXAMPLE.COM")
	if rec.Code != 200 || !strings.HasPrefix(rec.Body.String(), "example.com\n") {
		t.Errorf("case fold failed: %q", rec.Body.String())
	}
}

func TestSearchJSON(t *testing.T) {
	s, _ := newTestServer(t, 0)
	rec := do(t, s, "GET", "/v1/search?apex=example.com&format=json")
	var plain []map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &plain); err != nil {
		t.Fatal(err)
	}
	if len(plain) != 3 {
		t.Fatalf("len = %d", len(plain))
	}
	if _, has := plain[0]["first_seen"]; has {
		t.Error("first_seen present without dates=1")
	}
	if plain[0]["sub"] != "example.com" {
		t.Errorf("order wrong: %v", plain)
	}

	drec := do(t, s, "GET", "/v1/search?apex=example.com&format=json&dates=1")
	raw := drec.Body.String()
	if !strings.Contains(raw, `"first_seen":"2008-05-`) {
		t.Errorf("dates json missing first_seen: %s", raw)
	}
	if strings.Index(raw, `"first_seen"`) > strings.Index(raw, `"sub"`) {
		t.Errorf("field order wrong: %s", raw)
	}
}

func TestSearchDatesText(t *testing.T) {
	s, _ := newTestServer(t, 0)
	rec := do(t, s, "GET", "/v1/search?apex=example.com&dates=1")
	want := "example.com\t2008-05-05T15:06:40Z\n"
	if !strings.HasPrefix(rec.Body.String(), want) {
		t.Errorf("body = %q", rec.Body.String())
	}
}

func TestSearchNDJSON(t *testing.T) {
	s, _ := newTestServer(t, 0)
	rec := do(t, s, "GET", "/v1/search?apex=example.com&format=ndjson&dates=1")
	if rec.Code != 200 {
		t.Fatalf("code = %d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/x-ndjson" {
		t.Errorf("content-type = %q", ct)
	}
	if tc := rec.Header().Get("x-total-count"); tc != "3" {
		t.Errorf("x-total-count = %q", tc)
	}
	lines := strings.Split(strings.TrimSpace(rec.Body.String()), "\n")
	if len(lines) != 3 {
		t.Fatalf("lines = %d, want 3", len(lines))
	}
	var first struct {
		FirstSeen string `json:"first_seen"`
		Sub       string `json:"sub"`
	}
	if err := json.Unmarshal([]byte(lines[0]), &first); err != nil {
		t.Fatal(err)
	}
	if first.Sub != "example.com" || first.FirstSeen == "" {
		t.Errorf("first line = %+v", first)
	}
}

func TestSearchGzip(t *testing.T) {
	s, _ := newTestServer(t, 0)

	plain := do(t, s, "GET", "/v1/search?apex=example.com")

	req := httptest.NewRequest("GET", "/v1/search?apex=example.com", nil)
	req.Host = "localhost"
	req.Header.Set("Accept-Encoding", "gzip")
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("code = %d", rec.Code)
	}
	if enc := rec.Header().Get("Content-Encoding"); enc != "gzip" {
		t.Fatalf("content-encoding = %q", enc)
	}
	zr, err := gzip.NewReader(rec.Body)
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(zr)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != plain.Body.String() {
		t.Errorf("gzipped body mismatch")
	}

	sreq := httptest.NewRequest("GET", "/v1/stats", nil)
	sreq.Host = "localhost"
	sreq.Header.Set("Accept-Encoding", "gzip")
	srec := httptest.NewRecorder()
	s.Handler().ServeHTTP(srec, sreq)
	if srec.Header().Get("Content-Encoding") != "gzip" {
		t.Error("stats not gzipped")
	}
	zr2, err := gzip.NewReader(srec.Body)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadAll(zr2); err != nil {
		t.Fatal(err)
	}
}

func TestCORS(t *testing.T) {
	s, _ := newTestServer(t, 0)
	s.CORSOrigins = []string{"https://dash.example.vercel"}

	req := httptest.NewRequest("GET", "/v1/stats", nil)
	req.Host = "localhost"
	req.Header.Set("Origin", "https://dash.example.vercel")
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "https://dash.example.vercel" {
		t.Errorf("allowed origin got %q", got)
	}
	if v := rec.Header().Get("Vary"); !strings.Contains(v, "Origin") {
		t.Errorf("Vary = %q", v)
	}
	if ex := rec.Header().Get("Access-Control-Expose-Headers"); !strings.Contains(ex, "x-ratelimit-limit") || !strings.Contains(ex, "x-max-seq") {
		t.Errorf("expose-headers = %q", ex)
	}

	bad := httptest.NewRequest("GET", "/v1/stats", nil)
	bad.Host = "localhost"
	bad.Header.Set("Origin", "https://evil.example.com")
	rec2 := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec2, bad)
	if got := rec2.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Errorf("foreign origin got %q", got)
	}

	pre := httptest.NewRequest("OPTIONS", "/v1/stats", nil)
	pre.Host = "localhost"
	pre.Header.Set("Origin", "https://dash.example.vercel")
	pre.Header.Set("Access-Control-Request-Method", "GET")
	rec3 := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec3, pre)
	if rec3.Code != http.StatusNoContent {
		t.Errorf("preflight code = %d", rec3.Code)
	}

	off, _ := newTestServer(t, 0)
	plain := httptest.NewRequest("GET", "/v1/stats", nil)
	plain.Host = "localhost"
	plain.Header.Set("Origin", "https://dash.example.vercel")
	rec4 := httptest.NewRecorder()
	off.Handler().ServeHTTP(rec4, plain)
	if got := rec4.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Errorf("CORS active with no origins configured: %q", got)
	}
}

func TestHeadNotAllowed(t *testing.T) {
	s, _ := newTestServer(t, 0)
	rec := do(t, s, http.MethodHead, "/v1/search?apex=example.com")
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("head code = %d", rec.Code)
	}
	po := do(t, s, http.MethodPost, "/v1/search?apex=example.com")
	if po.Code != http.StatusMethodNotAllowed {
		t.Errorf("post code = %d", po.Code)
	}
	// Unknown paths serve the embedded UI shell instead of a bare 404.
	nf := do(t, s, http.MethodGet, "/nope")
	if nf.Code != http.StatusOK || !strings.Contains(nf.Header().Get("Content-Type"), "text/html") {
		t.Errorf("ui shell code = %d ct = %q", nf.Code, nf.Header().Get("Content-Type"))
	}
}

func TestStatsEndpoint(t *testing.T) {
	s, _ := newTestServer(t, 0)
	rec := do(t, s, http.MethodGet, "/v1/stats")
	if rec.Code != 200 {
		t.Fatalf("code = %d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("content-type = %q", ct)
	}
	var out struct {
		Total uint64 `json:"total"`
		Top   []struct {
			Apex  string `json:"apex"`
			Count uint64 `json:"count"`
		} `json:"top"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out.Total != 3 || len(out.Top) != 1 || out.Top[0].Apex != "example.com" || out.Top[0].Count != 3 {
		t.Errorf("stats = %+v", out)
	}

	rec1 := do(t, s, http.MethodGet, "/v1/stats?n=1")
	if err := json.Unmarshal(rec1.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if len(out.Top) != 1 {
		t.Errorf("n=1 gave %d entries", len(out.Top))
	}

	bad := do(t, s, http.MethodGet, "/v1/stats?n=zero")
	if bad.Code != 400 {
		t.Errorf("bad n code = %d", bad.Code)
	}
	post := do(t, s, http.MethodPost, "/v1/stats")
	if post.Code != http.StatusMethodNotAllowed {
		t.Errorf("post stats code = %d", post.Code)
	}
}

func TestRateLimit(t *testing.T) {
	s, _ := newTestServer(t, 3)
	var lastRem, limit string
	for i := 0; i < 5; i++ {
		rec := do(t, s, "GET", "/v1/search?apex=example.com")
		lastRem = rec.Header().Get("x-ratelimit-remaining")
		limit = rec.Header().Get("x-ratelimit-limit")
		if i < 3 {
			if rec.Code != 200 {
				t.Fatalf("req %d: code %d", i, rec.Code)
			}
			continue
		}
		if rec.Code != http.StatusTooManyRequests {
			t.Fatalf("req %d: expected 429, got %d", i, rec.Code)
		}
		if rec.Header().Get("Retry-After") == "" {
			t.Error("missing Retry-After on 429")
		}
	}
	if limit != "3" {
		t.Errorf("limit header = %q", limit)
	}
	if lastRem != "0" {
		t.Errorf("remaining header = %q", lastRem)
	}
	hz := do(t, s, "GET", "/healthz")
	if hz.Code != 200 {
		t.Errorf("healthz behind limiter: %d", hz.Code)
	}
}

var _ = io.Discard

func TestHostAllowList(t *testing.T) {
	s, _ := newTestServer(t, 0)

	ok := do(t, s, "GET", "http://localhost:8080/v1/search?apex=example.com")
	if ok.Code != 200 {
		t.Errorf("localhost: code = %d", ok.Code)
	}
	rebound := httptest.NewRequest("GET", "/v1/search?apex=example.com", nil)
	rebound.Host = "evil.example.net"
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, rebound)
	if rec.Code != http.StatusMisdirectedRequest {
		t.Errorf("rebound host: code = %d, want 421", rec.Code)
	}
	hz := httptest.NewRequest("GET", "/healthz", nil)
	hz.Host = "evil.example.net"
	rec2 := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec2, hz)
	if rec2.Code != http.StatusMisdirectedRequest {
		t.Errorf("rebound healthz: code = %d, want 421", rec2.Code)
	}

	s.AllowedHosts = []string{"MyHost.Example.COM"}
	custom := httptest.NewRequest("GET", "/v1/search?apex=example.com", nil)
	custom.Host = "myhost.example.com:8099"
	rec3 := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec3, custom)
	if rec3.Code != 200 {
		t.Errorf("custom allowed host: code = %d", rec3.Code)
	}
}
