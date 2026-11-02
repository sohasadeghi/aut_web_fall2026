package jwtauth

import (
	"strings"
	"testing"
	"time"
)

func TestSignVerify(t *testing.T) {
	secret := []byte(strings.Repeat("a", 32))
	now := time.Unix(1730000000, 0)
	claims := Claims{
		Issuer: Issuer, Audience: Audience, Subject: "alice",
		IssuedAt: now.Unix(), NotBefore: now.Unix(), ExpiresAt: now.Add(15 * time.Minute).Unix(),
	}
	token, err := Sign(secret, claims)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := Verify(token, secret, now)
	if err != nil || verified.Subject != "alice" {
		t.Fatalf("expected valid token, got claims=%+v err=%v", verified, err)
	}
	if _, err := Verify(token, []byte(strings.Repeat("b", 32)), now); err == nil {
		t.Fatal("different secret should fail")
	}
	if _, err := Verify(token, secret, now.Add(16*time.Minute)); err == nil {
		t.Fatal("expired token should fail")
	}
	if _, err := Verify(token+"xyz", secret, now); err == nil {
		t.Fatal("tampering should fail")
	}
	if _, err := Verify("", secret, now); err == nil {
		t.Fatal("empty token should fail")
	}
}

func TestRejectsIncorrectClaims(t *testing.T) {
	secret := []byte(strings.Repeat("c", 32))
	now := time.Unix(1730000000, 0)
	claims := Claims{Issuer: Issuer, Audience: Audience, Subject: "alice", IssuedAt: now.Unix(), NotBefore: now.Unix(), ExpiresAt: now.Add(time.Minute).Unix()}
	claims.Audience = "wrong-service"
	if _, err := Sign(secret, claims); err == nil {
		t.Fatal("unexpected audience should not be issued")
	}
	claims.Audience = Audience
	claims.NotBefore = now.Add(time.Minute).Unix()
	token, err := Sign(secret, claims)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(token, secret, now); err == nil {
		t.Fatal("token not yet valid should fail")
	}
}
