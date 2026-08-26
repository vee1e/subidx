package server

import (
	"compress/gzip"
	"net/http"
	"strings"
)

type gzipResponseWriter struct {
	http.ResponseWriter
	gz *gzip.Writer
}

func (g *gzipResponseWriter) Write(b []byte) (int, error) {
	return g.gz.Write(b)
}

func (g *gzipResponseWriter) Flush() {
	g.gz.Flush()
	if f, ok := g.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// gzipMiddleware compresses search and stats responses when the client
// accepts it. Hostname lists are highly repetitive text (5-6x ratios),
// so BestSpeed keeps the CPU cost trivial even while tailers ingest.
func gzipMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet ||
			!strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
			next.ServeHTTP(w, r)
			return
		}
		switch r.URL.Path {
		case "/v1/search", "/v1/stats":
			h := w.Header()
			h.Set("Content-Encoding", "gzip")
			h.Add("Vary", "Accept-Encoding")
			h.Del("Content-Length")
			gz, err := gzip.NewWriterLevel(w, gzip.BestSpeed)
			if err != nil {
				next.ServeHTTP(w, r)
				return
			}
			next.ServeHTTP(&gzipResponseWriter{ResponseWriter: w, gz: gz}, r)
			gz.Close()
		default:
			next.ServeHTTP(w, r)
		}
	})
}
