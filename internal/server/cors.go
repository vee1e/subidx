package server

import (
	"net/http"
)

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
