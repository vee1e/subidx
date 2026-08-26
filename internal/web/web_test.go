package web

import (
	"io/fs"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func get(t *testing.T, h http.Handler, target string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, target, nil)
	req.Host = "localhost"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestShellHeaders(t *testing.T) {
	rec := get(t, Handler(), "/")
	if rec.Code != http.StatusOK {
		t.Fatalf("code = %d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, "text/html") {
		t.Errorf("content-type = %q", ct)
	}
	csp := rec.Header().Get("Content-Security-Policy")
	if !strings.Contains(csp, "default-src 'none'") || !strings.Contains(csp, "script-src 'self'") {
		t.Errorf("csp = %q", csp)
	}
	if rec.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Error("missing nosniff")
	}
	if cc := rec.Header().Get("Cache-Control"); cc != "no-cache" {
		t.Errorf("cache-control = %q", cc)
	}
	if !strings.Contains(rec.Body.String(), `id="app"`) {
		t.Error("body is not the app shell")
	}
}

func TestAssetsImmutable(t *testing.T) {
	files, err := fs.Sub(dist, "dist")
	if err != nil {
		t.Fatal(err)
	}
	asset := ""
	err = fs.WalkDir(files, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if asset == "" && !d.IsDir() && strings.HasPrefix(d.Name(), "index-") &&
			(strings.HasSuffix(p, ".js") || strings.HasSuffix(p, ".css")) {
			asset = p
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if asset == "" {
		t.Fatal("no built assets found under dist/assets")
	}

	h := Handler()
	rec := get(t, h, "/"+asset)
	if rec.Code != http.StatusOK {
		t.Fatalf("code = %d", rec.Code)
	}
	if cc := rec.Header().Get("Cache-Control"); !strings.Contains(cc, "immutable") {
		t.Errorf("cache-control = %q", cc)
	}
	if strings.HasSuffix(asset, ".css") {
		if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, "text/css") {
			t.Errorf("css content-type = %q", ct)
		}
	} else {
		// Go resolves .js via the OS mime database, which differs between
		// platforms; both spellings are fine for browsers.
		if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, "javascript") {
			t.Errorf("js content-type = %q", ct)
		}
	}
	if csp := rec.Header().Get("Content-Security-Policy"); csp != "" {
		t.Errorf("csp on hashed asset: %q", csp)
	}
}

func TestFallbackAndReservedPaths(t *testing.T) {
	h := Handler()

	fb := get(t, h, "/some/deep/link")
	if fb.Code != http.StatusOK || !strings.Contains(fb.Body.String(), `id="app"`) {
		t.Errorf("fallback code = %d", fb.Code)
	}

	api := get(t, h, "/v1/nope")
	if api.Code != http.StatusNotFound {
		t.Errorf("/v1/nope code = %d, want 404", api.Code)
	}
	hz := get(t, h, "/healthz")
	if hz.Code != http.StatusNotFound {
		t.Errorf("/healthz code = %d, want 404 (server mux owns it)", hz.Code)
	}

	post := httptest.NewRequest(http.MethodPost, "/", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, post)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("post / code = %d", rec.Code)
	}
}
