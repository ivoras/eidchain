// Package webapp is the example web app served by `eidchain node`: type a
// message, sign it with your eID card in the browser, submit it to the node.
package webapp

import (
	"embed"
	"io/fs"
	"net/http"
)

//go:embed static
var content embed.FS

// Handler serves the embedded app with a strict content security policy: the
// page may only talk to the node it came from.
func Handler() http.Handler {
	sub, err := fs.Sub(content, "static")
	if err != nil {
		panic(err)
	}
	files := http.FileServerFS(sub)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cache-Control", "no-cache")
		files.ServeHTTP(w, r)
	})
}
