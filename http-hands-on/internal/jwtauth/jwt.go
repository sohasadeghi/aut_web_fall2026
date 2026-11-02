// Package jwtauth provides a small, strictly HS256-only JWT implementation for
// this course exercise. For production, prefer a maintained JWT/OIDC library
// and centrally managed keys with rotation.
package jwtauth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

const (
	Issuer   = "internet-engineering-lab"
	Audience = "legacy-httpbin"
	MaxSize  = 8192
)

var ErrInvalidToken = errors.New("invalid or expired JWT")

// Claims are the claims supported by this demonstration.
// exp, nbf, and iat are UNIX timestamps in whole seconds.
type Claims struct {
	Issuer    string `json:"iss"`
	Audience  string `json:"aud"`
	Subject   string `json:"sub"`
	ExpiresAt int64  `json:"exp"`
	NotBefore int64  `json:"nbf"`
	IssuedAt  int64  `json:"iat"`
}

type header struct {
	Algorithm string `json:"alg"`
	Type      string `json:"typ"`
}

// Sign creates a compact JWT with a HMAC-SHA256 signature.
func Sign(secret []byte, claims Claims) (string, error) {
	if len(secret) < 32 || claims.Issuer != Issuer || claims.Audience != Audience ||
		claims.Subject == "" || claims.ExpiresAt <= claims.IssuedAt ||
		claims.IssuedAt <= 0 || claims.NotBefore <= 0 || claims.NotBefore > claims.ExpiresAt {
		return "", ErrInvalidToken
	}
	headerPart := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	payloadPart := base64.RawURLEncoding.EncodeToString(payload)
	signingInput := headerPart + "." + payloadPart
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write([]byte(signingInput))
	signature := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return signingInput + "." + signature, nil
}

// Verify validates the signature, allowed algorithm, issuer, audience, and
// mandatory time constraints. All failures intentionally share one error.
func Verify(token string, secret []byte, now time.Time) (Claims, error) {
	var claims Claims
	if len(secret) < 32 || len(token) == 0 || len(token) > MaxSize {
		return claims, ErrInvalidToken
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return claims, ErrInvalidToken
	}

	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || len(signature) != sha256.Size {
		return claims, ErrInvalidToken
	}
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write([]byte(parts[0] + "." + parts[1]))
	if !hmac.Equal(signature, mac.Sum(nil)) {
		return claims, ErrInvalidToken
	}

	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return claims, ErrInvalidToken
	}
	var hdr header
	if err := json.Unmarshal(headerBytes, &hdr); err != nil || hdr.Algorithm != "HS256" || hdr.Type != "JWT" {
		return claims, ErrInvalidToken
	}

	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil || json.Unmarshal(payloadBytes, &claims) != nil {
		return Claims{}, ErrInvalidToken
	}
	current := now.Unix()
	if claims.Issuer != Issuer || claims.Audience != Audience || claims.Subject == "" ||
		claims.IssuedAt <= 0 || claims.NotBefore <= 0 || claims.ExpiresAt <= current ||
		claims.NotBefore > current || claims.IssuedAt > current ||
		claims.ExpiresAt <= claims.IssuedAt {
		return Claims{}, ErrInvalidToken
	}
	return claims, nil
}
