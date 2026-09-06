package ui

import (
	"net/http"

	"github.com/marstack-labs/marstack-secrets/internal/platform/httpx"
)

const (
	pathIndex  = "/ui/"
	pathTheme  = "/ui/meridian.css"
	pathStyles = "/ui/app.css"
	pathScript = "/ui/app.js"
)

const contentSecurityPolicy = "default-src 'none'; " +
	"script-src 'self'; " +
	"style-src 'self'; " +
	"connect-src 'self'; " +
	"img-src 'self' data:; " +
	"form-action 'none'; " +
	"frame-ancestors 'none'; " +
	"base-uri 'none'; " +
	"object-src 'none'"

type asset struct {
	file        string
	contentType string
}

var served = map[string]asset{
	pathIndex:  {file: "assets/index.html", contentType: "text/html; charset=utf-8"},
	pathTheme:  {file: "assets/meridian.css", contentType: "text/css; charset=utf-8"},
	pathStyles: {file: "assets/app.css", contentType: "text/css; charset=utf-8"},
	pathScript: {file: "assets/app.js", contentType: "text/javascript; charset=utf-8"},
}

func (m *Module) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET "+pathIndex, m.serve)
	mux.HandleFunc("GET "+pathTheme, m.serve)
	mux.HandleFunc("GET "+pathStyles, m.serve)
	mux.HandleFunc("GET "+pathScript, m.serve)
}

func (m *Module) PathsAllowedWhileSealed() []string {
	return []string{pathIndex, pathTheme, pathStyles, pathScript}
}

func (m *Module) serve(w http.ResponseWriter, r *http.Request) {
	wanted, known := served[r.URL.Path]
	if !known {
		httpx.Problem(w, http.StatusNotFound, "not_found")
		return
	}

	body, err := assets.ReadFile(wanted.file)
	if err != nil {
		m.logger.Error("reading an embedded asset",
			"request_id", httpx.RequestIDFrom(r.Context()), "asset", wanted.file, "error", err)
		httpx.Problem(w, http.StatusInternalServerError, "internal_error")
		return
	}

	header := w.Header()
	header.Set("Content-Type", wanted.contentType)
	header.Set("Content-Security-Policy", contentSecurityPolicy)
	header.Set("Cross-Origin-Opener-Policy", "same-origin")
	header.Set("Cross-Origin-Resource-Policy", "same-origin")
	header.Set("Permissions-Policy", "geolocation=(), camera=(), microphone=(), payment=()")

	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}
