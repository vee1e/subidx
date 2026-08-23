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
	"time"

	"subidx/internal/apex"
	"subidx/internal/store"
)

type Server struct {
	Store        *store.Store
	Limiter      *Limiter
	TrustedHops  int
	RateLimit    int64
	MaxResults   int
	AllowedHosts []string
	ReadyFn      func() bool
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
	mux.HandleFunc("/healthz", s.handleHealth)
	mux.HandleFunc("/readyz", s.handleReady)
	mux.HandleFunc("/", s.handleRoot)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.hostAllowed(r.Host) {
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.WriteHeader(http.StatusMisdirectedRequest)
			w.Write([]byte("unrecognized host\n"))
			return
		}
		mux.ServeHTTP(w, r)
	})
}

func (s *Server) handleRoot(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/v1/search" || r.URL.Path == "/healthz" || r.URL.Path == "/readyz" {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusMethodNotAllowed)
		w.Write([]byte("Method Not Allowed\n"))
		return
	}
	http.NotFound(w, r)
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
	key := ClientKey(r, s.TrustedHops)
	if s.Limiter != nil {
		rem, ok, retryAfter := s.Limiter.Allow(key)
		w.Header().Set("x-ratelimit-limit", strconv.FormatInt(s.RateLimit, 10))
		w.Header().Set("x-ratelimit-remaining", strconv.FormatInt(rem, 10))
		if !ok {
			w.Header().Set("Retry-After", fmtRetry(retryAfter))
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.WriteHeader(http.StatusTooManyRequests)
			w.Write([]byte("rate limit exceeded\n"))
			return
		}
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

	dates := r.URL.Query().Get("dates") == "1"
	jsonMode := r.URL.Query().Get("format") == "json"

	if jsonMode {
		s.renderJSON(w, results, dates)
		return
	}
	s.renderText(w, results, dates)
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

func formatTS(ms int64) string {
	return time.UnixMilli(ms).UTC().Format("2006-01-02T15:04:05Z")
}
