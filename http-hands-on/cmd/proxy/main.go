package main

import (
	"log"
	"net/http"
	"net/url"
	"os"
	"time"

	"example.com/http-jwt-proxy-practical/internal/gateway"
)

func main() {
	secret := []byte(os.Getenv("JWT_SECRET"))
	if len(secret) < 32 {
		log.Fatal("JWT_SECRET must contain at least 32 characters; generate it randomly")
	}

	upstreamAddr := os.Getenv("UPSTREAM_URL")
	if upstreamAddr == "" {
		upstreamAddr = "http://legacy:8081"
	}
	upstream, err := url.Parse(upstreamAddr)
	if err != nil || upstream.Scheme != "http" || upstream.Host == "" || upstream.User != nil {
		log.Fatal("UPSTREAM_URL must be an internal http://host:port URL")
	}

	server := &http.Server{
		Addr:              ":8080",
		Handler:           gateway.New(upstream, secret),
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    16 * 1024,
	}
	log.Printf("JWT reverse proxy listening on :8080, forwarding to %s", upstream)
	log.Fatal(server.ListenAndServe())
}
