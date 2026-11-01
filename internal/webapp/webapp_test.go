package webapp

import (
	"io/fs"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
)

// Every script, stylesheet and module a page or script references must be in
// the binary: nothing is read from disk at runtime.
func TestEmbeddedAssetsAreComplete(t *testing.T) {
	sub, err := fs.Sub(content, "static")
	if err != nil {
		t.Fatal(err)
	}
	ref := regexp.MustCompile(`(?:src|href)="([^"#]+\.(?:js|css))"|from "\./([^"]+)"|import "\./([^"]+)"`)
	files, _ := fs.Glob(sub, "*")
	if len(files) < 8 {
		t.Fatalf("only %d embedded files: %v", len(files), files)
	}
	for _, f := range files {
		if !strings.HasSuffix(f, ".html") && !strings.HasSuffix(f, ".js") {
			continue
		}
		raw, _ := fs.ReadFile(sub, f)
		for _, m := range ref.FindAllStringSubmatch(string(raw), -1) {
			name := m[1] + m[2] + m[3]
			if strings.HasPrefix(name, "http") {
				continue
			}
			if _, err := fs.Stat(sub, name); err != nil {
				t.Errorf("%s references %s, which is not embedded", f, name)
			}
		}
	}
}

func TestServesPagesWithStrictHeaders(t *testing.T) {
	h := Handler()
	for _, p := range []string{"/", "/explorer.html", "/pending.html", "/pending.js", "/site.css", "/nav.js", "/explorer.js", "/app.js"} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest("GET", p, nil))
		if rec.Code != http.StatusOK {
			t.Errorf("%s: HTTP %d", p, rec.Code)
		}
		if csp := rec.Header().Get("Content-Security-Policy"); !strings.Contains(csp, "script-src 'self'") || strings.Contains(csp, "unsafe-inline") {
			t.Errorf("%s: weak CSP %q", p, csp)
		}
	}
	// Pages must not use inline scripts or styles: the CSP would block them.
	for _, p := range []string{"index.html", "explorer.html", "pending.html"} {
		sub, _ := fs.Sub(content, "static")
		raw, _ := fs.ReadFile(sub, p)
		if regexp.MustCompile(`<script(?:\s[^>]*)?>[^<]|\sstyle=|\son[a-z]+=`).Match(raw) {
			t.Errorf("%s has inline script, style or event handler", p)
		}
	}
}

// nav.js runs on every page, so this puts the link in every footer.
func TestNavAddsTheSourceLink(t *testing.T) {
	sub, _ := fs.Sub(content, "static")
	raw, _ := fs.ReadFile(sub, "nav.js")
	if !strings.Contains(string(raw), "https://github.com/ivoras/eidchain") || !strings.Contains(string(raw), "addSourceLink();") {
		t.Fatal("nav.js does not add the source link")
	}
	for _, p := range []string{"index.html", "explorer.html", "pending.html"} {
		page, _ := fs.ReadFile(sub, p)
		if !strings.Contains(string(page), `src="nav.js"`) {
			t.Errorf("%s does not load nav.js", p)
		}
	}
}
