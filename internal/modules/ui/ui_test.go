package ui

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
)

func newTestModule(t *testing.T) http.Handler {
	t.Helper()

	module, err := NewModule(Options{Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if err != nil {
		t.Fatalf("NewModule returned error: %v", err)
	}

	mux := http.NewServeMux()
	module.Register(mux)
	return mux
}

func get(t *testing.T, handler http.Handler, path string) *httptest.ResponseRecorder {
	t.Helper()

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, path, nil))
	return recorder
}

func TestEveryAssetIsServedWithItsOwnContentType(t *testing.T) {
	handler := newTestModule(t)

	for path, wanted := range map[string]string{
		pathIndex:  "text/html",
		pathStyles: "text/css",
		pathScript: "text/javascript",
	} {
		recorder := get(t, handler, path)
		if recorder.Code != http.StatusOK {
			t.Errorf("GET %s returned %d, want 200", path, recorder.Code)
			continue
		}
		if got := recorder.Header().Get("Content-Type"); !strings.HasPrefix(got, wanted) {
			t.Errorf("GET %s served %q, want %s", path, got, wanted)
		}
		if recorder.Body.Len() == 0 {
			t.Errorf("GET %s served nothing", path)
		}
	}
}

func TestTheContentSecurityPolicyForbidsInlineAndRemoteCode(t *testing.T) {
	policy := get(t, newTestModule(t), pathIndex).Header().Get("Content-Security-Policy")
	if policy == "" {
		t.Fatal("no content security policy was set")
	}

	for _, required := range []string{
		"default-src 'none'",
		"script-src 'self'",
		"style-src 'self'",
		"connect-src 'self'",
		"frame-ancestors 'none'",
		"base-uri 'none'",
		"object-src 'none'",
		"form-action 'none'",
	} {
		if !strings.Contains(policy, required) {
			t.Errorf("the policy is missing %q: %s", required, policy)
		}
	}

	for _, forbidden := range []string{"unsafe-inline", "unsafe-eval", "*", "http:", "https:"} {
		if strings.Contains(policy, forbidden) {
			t.Errorf("the policy contains %q, which defeats it: %s", forbidden, policy)
		}
	}
}

func TestThePageCarriesNoInlineScriptOrHandler(t *testing.T) {
	page := get(t, newTestModule(t), pathIndex).Body.String()

	inlineScript := regexp.MustCompile(`(?is)<script(?:\s[^>]*)?>(.*?)</script>`)
	for _, found := range inlineScript.FindAllStringSubmatch(page, -1) {
		if strings.TrimSpace(found[1]) != "" {
			t.Errorf("the page carries inline script, which the policy would block: %s", found[1])
		}
	}

	handler := regexp.MustCompile(`(?i)\son[a-z]+\s*=`)
	if match := handler.FindString(page); match != "" {
		t.Errorf("the page carries an inline event handler, which the policy would block: %s", match)
	}

	inlineStyle := regexp.MustCompile(`(?i)\sstyle\s*=`)
	if match := inlineStyle.FindString(page); match != "" {
		t.Errorf("the page carries an inline style, which the policy would block: %s", match)
	}
}

func TestTheScriptNeverWritesUntrustedMarkup(t *testing.T) {
	script := get(t, newTestModule(t), pathScript).Body.String()

	for _, forbidden := range []string{"innerHTML", "outerHTML", "insertAdjacentHTML",
		"document.write", "eval(", "new Function("} {
		if strings.Contains(script, forbidden) {
			t.Errorf("the script uses %s, which turns a stored value into markup", forbidden)
		}
	}
}

func TestTheScriptKeepsNoTokenOnDisk(t *testing.T) {
	script := get(t, newTestModule(t), pathScript).Body.String()

	for _, forbidden := range []string{"localStorage", "sessionStorage", "document.cookie", "indexedDB"} {
		if strings.Contains(script, forbidden) {
			t.Errorf("the script uses %s; a session token must not outlive the page", forbidden)
		}
	}
}

func TestNothingOutsideTheAssetListIsServed(t *testing.T) {
	handler := newTestModule(t)

	for _, path := range []string{
		"/ui/../app.js",
		"/ui/assets/app.js",
		"/ui/index.html",
		"/ui/nothing",
	} {
		recorder := get(t, handler, path)
		if recorder.Code == http.StatusOK {
			t.Errorf("GET %s was served with %d", path, recorder.Code)
		}
	}
}

func TestTheAssetsLoadWhileTheStoreIsSealed(t *testing.T) {
	module, err := NewModule(Options{Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if err != nil {
		t.Fatalf("NewModule returned error: %v", err)
	}

	allowed := module.PathsAllowedWhileSealed()
	if len(allowed) != len(served) {
		t.Fatalf("%d of %d assets load while sealed; the page would half load", len(allowed), len(served))
	}
	for _, path := range allowed {
		if _, known := served[path]; !known {
			t.Errorf("%q is allowed while sealed but is not an asset", path)
		}
	}
}

func TestAModuleWithoutALoggerIsRefused(t *testing.T) {
	if _, err := NewModule(Options{}); err == nil {
		t.Fatal("NewModule accepted a nil logger")
	}
}
