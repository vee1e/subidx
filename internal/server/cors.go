package server

import (
	"net/http"
)

// exposedHeaders lists the API headers the browser may read on
// cross-origin responses; by default only Cache-Control, Content-Type
// and friends cross the boundary.
const exposedHeaders = "x-ratelimit-limit, x-ratelimit-remaining, retry-after, x-total-count, x-max-seq, x-truncated"

// corsMiddleware answers with CORS headers when the request Origin is in
// the allow list, so a separately hosted dashboard (e.g. on Vercel) can
// call the API. The Origin is echoed back rather than wildcarded, and
// Vary: Origin keeps shared caches correct. Simple GET requests and
// EventSource streams need no preflight, but OPTIONS is answered anyway
// for robustness.
func corsMiddleware(allowed []string, next http.Handler) http.Handler {
	if len(allowed) == 0 {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin != "" {
			for _, o := range allowed {
				if origin == o {
					h := w.Header()
					h.Set("Access-Control-Allow-Origin", origin)
					h.Set("Access-Control-Expose-Headers", exposedHeaders)
					h.Add("Vary", "Origin")
					break
				}
			}
		}
		if r.Method == http.MethodOptions && r.Header.Get("Access-Control-Request-Method") != "" {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}
