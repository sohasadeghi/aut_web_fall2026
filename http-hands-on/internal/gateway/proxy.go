// Package gateway implements the authenticated reverse proxy.
package gateway

import (
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	"example.com/http-jwt-proxy-practical/internal/jwtauth"
)

// New builds an HTTP handler that rejects requests without a valid JWT before
// passing them to the legacy service. The upstream receives no bearer token.
func New(upstream *url.URL, secret []byte) http.Handler {
	proxy := httputil.NewSingleHostReverseProxy(upstream)
	// Rewrite and Director cannot be used together.
	proxy.Director = nil
	proxy.Rewrite = func(pr *httputil.ProxyRequest) {
		// Never leak the JWT or client-supplied proxy credentials upstream.
		pr.Out.Header.Del("Authorization")
		pr.Out.Header.Del("Proxy-Authorization")
		pr.SetURL(upstream)
		pr.Out.Host = upstream.Host
		pr.SetXForwarded()
	}
	proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		log.Printf("backend error: %v", err)
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Disallow caching of authenticated responses in shared caches.
		w.Header().Set("Cache-Control", "no-store")
		values := r.Header.Values("Authorization")
		if len(values) != 1 {
			unauthorized(w)
			return
		}
		fields := strings.Fields(values[0])
		if len(fields) != 2 || !strings.EqualFold(fields[0], "Bearer") {
			unauthorized(w)
			return
		}
		if _, err := jwtauth.Verify(fields[1], secret, time.Now()); err != nil {
			unauthorized(w)
			return
		}
		proxy.ServeHTTP(w, r)
	})
}

func unauthorized(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", `Bearer realm="legacy-httpbin"`)
	http.Error(w, "Unauthorized: valid Bearer JWT required", http.StatusUnauthorized)
}
