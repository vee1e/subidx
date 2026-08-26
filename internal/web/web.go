// Package web serves the dashboard UI embedded from ./dist (the Vite
// build output). Assets are immutable-cached by content hash; the HTML
// shell is never cached and ships a strict CSP.
package web

import (
	"embed"
	"io/fs"
	"net/http"
	"path"
	"strings"
)

//go:embed all:dist
var dist embed.FS

const csp = "default-src 'none'; script-src 'self'; style-src 'self'; " +
	"img-src 'self' data:; connect-src 'self'; font-src 'self'; " +
	"base-uri 'none'; form-action 'self'; frame-ancestors 'none'"

// Handler returns a handler serving the built UI. Paths that look like
// API routes but matched nothing fall through to a plain 404; anything
// else unknown serves the HTML shell so the app owns its own states.
func Handler() http.Handler {
	files, err := fs.Sub(dist, "dist")
	if err != nil {
		panic("web: embedded dist missing: " + err.Error())
	}
	fileServer := http.FileServerFS(files)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.WriteHeader(http.StatusMethodNotAllowed)
			w.Write([]byte("Method Not Allowed\n"))
			return
		}

		p := path.Clean(r.URL.Path)
		if strings.HasPrefix(p, "/v1/") || p == "/v1" || p == "/healthz" || p == "/readyz" {
			http.NotFound(w, r)
			return
		}

		name := strings.TrimPrefix(p, "/")
		isShell := name == "" || name == "index.html"
		if !isShell {
			if _, err := fs.Stat(files, name); err != nil {
				name = "index.html"
				isShell = true
			}
		}

		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		if isShell {
			h.Set("Content-Security-Policy", csp)
			h.Set("Cache-Control", "no-cache")
			r.URL.Path = "/"
		} else {
			h.Set("Cache-Control", "public, max-age=31536000, immutable")
		}
		fileServer.ServeHTTP(w, r)
	})
}
