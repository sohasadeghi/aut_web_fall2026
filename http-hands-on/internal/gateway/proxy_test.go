package gateway

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"example.com/http-jwt-proxy-practical/internal/jwtauth"
)

func TestJWTGateway(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" {
			t.Error("Authorization leaked to backend")
		}
		if r.URL.Path != "/post" || r.URL.Query().Get("x") != "1" || r.Method != http.MethodPost {
			t.Errorf("request was not preserved: %s %s", r.Method, r.URL.String())
		}
		data, _ := io.ReadAll(r.Body)
		if string(data) != "hello" {
			t.Errorf("request body lost: %q", data)
		}
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte("forwarded"))
	}))
	defer upstream.Close()
	u, _ := url.Parse(upstream.URL)
	secret := []byte(strings.Repeat("s", 32))
	proxy := httptest.NewServer(New(u, secret))
	defer proxy.Close()

	client := proxy.Client()
	makeRequest := func(auth string) *http.Response {
		t.Helper()
		req, err := http.NewRequest(http.MethodPost, proxy.URL+"/post?x=1", strings.NewReader("hello"))
		if err != nil {
			t.Fatal(err)
		}
		if auth != "" {
			req.Header.Set("Authorization", auth)
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		return resp
	}

	resp := makeRequest("")
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("without JWT: expected 401, got %d", resp.StatusCode)
	}
	_ = resp.Body.Close()
	resp = makeRequest("Bearer invalid-token")
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("invalid JWT: expected 401, got %d", resp.StatusCode)
	}
	_ = resp.Body.Close()

	now := time.Now()
	token, err := jwtauth.Sign(secret, jwtauth.Claims{
		Issuer: jwtauth.Issuer, Audience: jwtauth.Audience, Subject: "student",
		IssuedAt: now.Unix(), NotBefore: now.Unix(), ExpiresAt: now.Add(15 * time.Minute).Unix(),
	})
	if err != nil {
		t.Fatal(err)
	}
	resp = makeRequest("Bearer " + token)
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusAccepted || string(data) != "forwarded" {
		t.Fatalf("valid JWT: expected forwarding; status=%d body=%q", resp.StatusCode, data)
	}
}
