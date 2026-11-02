// mint is a local-only demonstration CLI, NOT a network-accessible login route.
package main

import (
	"flag"
	"fmt"
	"os"
	"time"

	"example.com/http-jwt-proxy-practical/internal/jwtauth"
)

func main() {
	subject := flag.String("sub", "student", "subject to put in the JWT")
	ttl := flag.Duration("ttl", 15*time.Minute, "lifetime of the JWT, max 1h")
	flag.Parse()
	if *subject == "" || *ttl < time.Second || *ttl > time.Hour {
		fmt.Fprintln(os.Stderr, "-sub must be nonempty and -ttl must be between 1s and 1h")
		os.Exit(2)
	}

	secret := []byte(os.Getenv("JWT_SECRET"))
	now := time.Now()
	claims := jwtauth.Claims{
		Issuer:    jwtauth.Issuer,
		Audience:  jwtauth.Audience,
		Subject:   *subject,
		IssuedAt:  now.Unix(),
		NotBefore: now.Unix(),
		ExpiresAt: now.Add(*ttl).Unix(),
	}
	token, err := jwtauth.Sign(secret, claims)
	if err != nil {
		fmt.Fprintln(os.Stderr, "cannot issue JWT: verify JWT_SECRET and flags")
		os.Exit(1)
	}
	fmt.Println(token)
}
