// Package server serves the read-only search API in front of the
// store, with per-IP rate limiting, Host allow-listing, and bounded
// result sizes.
package server

import (
	"encoding/json"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"subidx/internal/apex"
	"subidx/internal/store"
	"subidx/internal/web"
)

type Server struct {
	Store        *store.Store
	Limiter      *Limiter
	TrustedHops  int
	RateLimit    int64
	MaxResults   int
	AllowedHosts []string
	ReadyFn      func() bool

	// Hub fans ingest events out to /v1/feed subscribers; nil disables
	// the endpoint. Stop, when closed, tears active streams down quickly
	// so Shutdown is not stuck waiting on them. CORSOrigins, when set,
	// lets separately hosted frontends call the API from the browser.
	Hub         *Hub
	Stop        chan struct{}
	CORSOrigins []string
	activeFeeds atomic.Int64

	statsMu    sync.Mutex
	statsCache map[int]statsCacheEntry
}

// statsCacheTTL bounds how stale dashboard stats may be.
const statsCacheTTL = 15 * time.Second

type statsCacheEntry struct {
	body []byte
	at   time.Time
}

var defaultHosts = []string{"localhost", "127.0.0.1", "::1"}

// hostAllowed blocks requests whose Host header is not expected. Browsers
// always send the origin's real hostname, but a DNS rebinding attack makes
// attacker.com resolve to 127.0.0.1 while the browser keeps sending
// attacker.com in Host, which never matches the allow list.
func (s *Server) hostAllowed(host string) bool {
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	host = strings.ToLower(strings.Trim(host, "[]"))
	allowed := s.AllowedHosts
	if len(allowed) == 0 {
		allowed = defaultHosts
	}
	for _, h := range allowed {
		if host == strings.ToLower(h) {
			return true
		}
	}
	return false
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/search", s.handleSearch)
	mux.HandleFunc("/v1/stats", s.handleStats)
	mux.HandleFunc("/v1/watch", s.handleWatch)
	mux.HandleFunc("/v1/feed", s.handleFeed)
	mux.HandleFunc("/healthz", s.handleHealth)
	mux.HandleFunc("/readyz", s.handleReady)
	mux.Handle("/", web.Handler())
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.hostAllowed(r.Host) {
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.WriteHeader(http.StatusMisdirectedRequest)
			w.Write([]byte("unrecognized host\n"))
			return
		}
		corsMiddleware(s.CORSOrigins, gzipMiddleware(mux)).ServeHTTP(w, r)
	})
}

// gate applies the per-IP rate limit and writes the limit headers. It
// returns false when the request was already answered with a 429.
func (s *Server) gate(w http.ResponseWriter, r *http.Request) bool {
	if s.Limiter == nil {
		return true
	}
	key := ClientKey(r, s.TrustedHops)
	rem, ok, retryAfter := s.Limiter.Allow(key)
	w.Header().Set("x-ratelimit-limit", strconv.FormatInt(s.RateLimit, 10))
	w.Header().Set("x-ratelimit-remaining", strconv.FormatInt(rem, 10))
	if !ok {
		w.Header().Set("Retry-After", fmtRetry(retryAfter))
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusTooManyRequests)
		w.Write([]byte("rate limit exceeded\n"))
		return false
	}
	return true
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		s.methodNotAllowed(w)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (s *Server) handleReady(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		s.methodNotAllowed(w)
		return
	}
	if s.ReadyFn != nil && !s.ReadyFn() {
		http.Error(w, "not ready", http.StatusServiceUnavailable)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (s *Server) methodNotAllowed(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusMethodNotAllowed)
	w.Write([]byte("Method Not Allowed\n"))
}

func (s *Server) handleSearch(w http.ResponseWriter, r *http.Request) {
	if !s.gate(w, r) {
		return
	}

	if r.Method != http.MethodGet {
		s.methodNotAllowed(w)
		return
	}

	raw := r.URL.Query().Get("apex")
	if raw == "" {
		http.Error(w, "missing apex parameter", http.StatusBadRequest)
		return
	}
	norm, err := apex.Normalize(raw)
	if err != nil {
		http.Error(w, "invalid apex: "+err.Error(), http.StatusBadRequest)
		return
	}
	a, err := apex.ValidateApex(norm)
	if err != nil {
		http.Error(w, "invalid apex: "+err.Error(), http.StatusBadRequest)
		return
	}

	results, err := s.Store.Scan(a, s.MaxResults)
	if err != nil {
		log.Printf("scan %s: %v", a, err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if c, err := s.Store.Count(a); err == nil {
		w.Header().Set("x-total-count", strconv.FormatUint(c, 10))
	}
	if len(results) > 0 {
		// Scan output is seq-ascending even when capped, so the last row
		// carries the apex's newest sequence number.
		w.Header().Set("x-max-seq", strconv.FormatUint(results[len(results)-1].Seq, 10))
	}

	dates := r.URL.Query().Get("dates") == "1"
	switch {
	case r.URL.Query().Get("format") == "json":
		s.renderJSON(w, results, dates)
	case r.URL.Query().Get("format") == "ndjson":
		s.renderNDJSON(w, results, dates)
	default:
		s.renderText(w, results, dates)
	}
}

// maxStatsTop caps the ?n= parameter on /v1/stats.
const maxStatsTop = 100

// topIterCap bounds how many apex counters a stats request will inspect.
// Beyond it the top list approximates "busiest of the first 250k apexes"
// rather than scanning millions of counters per page load.
const topIterCap = 250_000

type jsonTop struct {
	Apex  string `json:"apex"`
	Count uint64 `json:"count"`
}

type jsonStats struct {
	Total uint64    `json:"total"`
	Top   []jsonTop `json:"top"`
}

func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	if !s.gate(w, r) {
		return
	}
	if r.Method != http.MethodGet {
		s.methodNotAllowed(w)
		return
	}

	n := 10
	if raw := r.URL.Query().Get("n"); raw != "" {
		v, err := strconv.Atoi(raw)
		if err != nil || v < 1 {
			http.Error(w, "invalid n", http.StatusBadRequest)
			return
		}
		if v > maxStatsTop {
			v = maxStatsTop
		}
		n = v
	}

	s.statsMu.Lock()
	body, cached := s.statsCache[n].body, false
	if e, ok := s.statsCache[n]; ok && time.Since(e.at) < statsCacheTTL {
		body, cached = e.body, true
	}
	s.statsMu.Unlock()
	if cached {
		w.Header().Set("Content-Type", "application/json")
		w.Write(body)
		return
	}

	total, err := s.Store.Total()
	if err != nil {
		log.Printf("stats total: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	top, err := s.Store.TopApprox(n, topIterCap)
	if err != nil {
		log.Printf("stats top: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	out := jsonStats{Total: total, Top: make([]jsonTop, 0, len(top))}
	for _, ac := range top {
		out.Top = append(out.Top, jsonTop{Apex: ac.Apex, Count: ac.Count})
	}
	body, err = json.Marshal(out)
	if err != nil {
		log.Printf("stats marshal: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	s.statsMu.Lock()
	if s.statsCache == nil {
		s.statsCache = make(map[int]statsCacheEntry)
	}
	s.statsCache[n] = statsCacheEntry{body: body, at: time.Now()}
	s.statsMu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	w.Write(body)
}

func (s *Server) renderText(w http.ResponseWriter, results []store.Result, dates bool) {
	var b strings.Builder
	for _, r := range results {
		b.WriteString(r.Sub)
		if dates {
			b.WriteByte('\t')
			b.WriteString(formatTS(r.FirstSeen))
		}
		b.WriteByte('\n')
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Write([]byte(b.String()))
}

type jsonSub struct {
	Sub string `json:"sub"`
}

type jsonSubDate struct {
	FirstSeen *string `json:"first_seen"`
	Sub       string  `json:"sub"`
}

func (s *Server) renderJSON(w http.ResponseWriter, results []store.Result, dates bool) {
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	if dates {
		out := make([]jsonSubDate, 0, len(results))
		for _, r := range results {
			rec := jsonSubDate{Sub: r.Sub}
			if r.FirstSeen > 0 {
				ts := formatTS(r.FirstSeen)
				rec.FirstSeen = &ts
			}
			out = append(out, rec)
		}
		enc.Encode(out)
		return
	}
	out := make([]jsonSub, 0, len(results))
	for _, r := range results {
		out = append(out, jsonSub{Sub: r.Sub})
	}
	enc.Encode(out)
}

// renderNDJSON streams one JSON object per line and flushes early and
// often, so clients can render rows as they arrive instead of waiting
// for a multi-megabyte response to finish.
func (s *Server) renderNDJSON(w http.ResponseWriter, results []store.Result, dates bool) {
	w.Header().Set("Content-Type", "application/x-ndjson")
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	flusher, _ := w.(http.Flusher)
	for i, r := range results {
		if dates {
			rec := jsonSubDate{Sub: r.Sub}
			if r.FirstSeen > 0 {
				ts := formatTS(r.FirstSeen)
				rec.FirstSeen = &ts
			}
			if err := enc.Encode(rec); err != nil {
				return
			}
		} else {
			if err := enc.Encode(jsonSub{Sub: r.Sub}); err != nil {
				return
			}
		}
		if flusher != nil && (i == 0 || i&1023 == 1023) {
			flusher.Flush()
		}
	}
}

func formatTS(ms int64) string {
	return time.UnixMilli(ms).UTC().Format("2006-01-02T15:04:05Z")
}
