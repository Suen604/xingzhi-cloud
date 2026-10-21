package sso

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func TestLogtoAuthorizationCodeValidation(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	issuer := ""
	audience := "client"
	nonce := "nonce"
	expired := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			json.NewEncoder(w).Encode(Discovery{Issuer: issuer, AuthorizationEndpoint: issuer + "/authorize", TokenEndpoint: issuer + "/token", JWKSURI: issuer + "/jwks"})
		case "/jwks":
			json.NewEncoder(w).Encode(map[string]any{"keys": []any{map[string]string{"kid": "key", "kty": "RSA", "alg": "RS256", "use": "sig", "n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()), "e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes())}}})
		case "/token":
			if err := r.ParseForm(); err != nil {
				t.Error(err)
			}
			client, secret, ok := r.BasicAuth()
			if !ok || client != "client" || secret != "secret" || r.PostForm.Get("code_verifier") != "verifier" || r.PostForm.Get("redirect_uri") != "https://app.test/callback" {
				t.Error("authorization code was not bound to the expected client and redirect")
			}
			expires := time.Now().Add(time.Minute)
			if expired {
				expires = time.Now().Add(-time.Minute)
			}
			token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{"iss": issuer, "sub": "subject", "aud": audience, "exp": expires.Unix(), "nonce": nonce, "email": "person@example.com", "email_verified": true})
			token.Header["kid"] = "key"
			signed, err := token.SignedString(key)
			if err != nil {
				t.Error(err)
			}
			json.NewEncoder(w).Encode(map[string]string{"id_token": signed})
		default:
			w.WriteHeader(404)
		}
	}))
	defer server.Close()
	issuer = server.URL
	c := Client{HTTP: server.Client()}
	provider := Provider{Enabled: true, ClientID: "client", ClientSecret: "secret", Issuer: issuer}
	redirect, err := c.Begin(t.Context(), "logto", provider, "https://app.test/callback", "state", "nonce", "verifier")
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(redirect)
	if u.Query().Get("state") != "state" || u.Query().Get("code_challenge_method") != "S256" || u.Query().Get("code_challenge") == "" {
		t.Fatal("missing state or PKCE binding")
	}
	identity, err := c.Finish(t.Context(), "logto", provider, "https://app.test/callback", "code", "nonce", "verifier")
	if err != nil || identity.Subject != "subject" || !identity.EmailVerified {
		t.Fatalf("valid OIDC token rejected: %+v %v", identity, err)
	}
	nonce = "wrong"
	if _, err := c.Finish(t.Context(), "logto", provider, "https://app.test/callback", "code", "nonce", "verifier"); err == nil {
		t.Fatal("nonce mismatch accepted")
	}
	nonce = "nonce"
	audience = "another-client"
	if _, err := c.Finish(t.Context(), "logto", provider, "https://app.test/callback", "code", "nonce", "verifier"); err == nil {
		t.Fatal("wrong audience accepted")
	}
	audience = "client"
	expired = true
	if _, err := c.Finish(t.Context(), "logto", provider, "https://app.test/callback", "code", "nonce", "verifier"); err == nil {
		t.Fatal("expired token accepted")
	}
}
