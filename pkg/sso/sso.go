// Package sso implements QQ OAuth and Logto OpenID Connect authorization-code login.
package sso

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"strings"

	"github.com/golang-jwt/jwt/v5"
)

type Provider struct {
	Enabled           bool   `json:"enabled"`
	ClientID          string `json:"client_id"`
	ClientSecret      string `json:"client_secret"`
	Issuer            string `json:"issuer,omitempty"`
	AllowRegistration bool   `json:"allow_registration"`
}

type Identity struct {
	Subject       string
	Name          string
	Email         string
	EmailVerified bool
}

type Discovery struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	JWKSURI               string `json:"jwks_uri"`
}

type Client struct{ HTTP *http.Client }

func secureEndpoint(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.User != nil || u.Fragment != "" {
		return errors.New("invalid SSO endpoint")
	}
	if u.Scheme != "https" && !(u.Scheme == "http" && (u.Hostname() == "localhost" || u.Hostname() == "127.0.0.1" || u.Hostname() == "::1")) {
		return errors.New("SSO endpoints require HTTPS")
	}
	return nil
}

func (c Client) request(ctx context.Context, method, endpoint string, form url.Values, output any, basic ...[2]string) error {
	if err := secureEndpoint(endpoint); err != nil {
		return err
	}
	var body io.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	}
	req, err := http.NewRequestWithContext(ctx, method, endpoint, body)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	if len(basic) > 0 {
		req.SetBasicAuth(url.QueryEscape(basic[0][0]), url.QueryEscape(basic[0][1]))
	}
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("SSO provider returned HTTP %d", resp.StatusCode)
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(output)
}

func (c Client) Discover(ctx context.Context, provider Provider) (*Discovery, error) {
	issuer := strings.TrimSuffix(provider.Issuer, "/")
	var result Discovery
	if err := c.request(ctx, http.MethodGet, issuer+"/.well-known/openid-configuration", nil, &result); err != nil {
		return nil, err
	}
	if result.Issuer != issuer && result.Issuer != provider.Issuer {
		return nil, errors.New("OIDC issuer mismatch")
	}
	for _, endpoint := range []string{result.AuthorizationEndpoint, result.TokenEndpoint, result.JWKSURI} {
		if err := secureEndpoint(endpoint); err != nil {
			return nil, err
		}
	}
	return &result, nil
}

func (c Client) Begin(ctx context.Context, name string, provider Provider, callback, state, nonce, verifier string) (string, error) {
	if !provider.Enabled || provider.ClientID == "" || provider.ClientSecret == "" {
		return "", errors.New("SSO provider is disabled or not configured")
	}
	values := url.Values{"client_id": {provider.ClientID}, "redirect_uri": {callback}, "response_type": {"code"}, "state": {state}}
	endpoint := "https://graph.qq.com/oauth2.0/authorize"
	switch name {
	case "qq":
		values.Set("scope", "get_user_info")
	case "logto":
		discovery, err := c.Discover(ctx, provider)
		if err != nil {
			return "", err
		}
		endpoint = discovery.AuthorizationEndpoint
		values.Set("scope", "openid profile email")
		values.Set("nonce", nonce)
		challenge := sha256.Sum256([]byte(verifier))
		values.Set("code_challenge", base64.RawURLEncoding.EncodeToString(challenge[:]))
		values.Set("code_challenge_method", "S256")
	default:
		return "", errors.New("unknown SSO provider")
	}
	u, err := url.Parse(endpoint)
	if err != nil {
		return "", err
	}
	query := u.Query()
	for k, v := range values {
		query[k] = v
	}
	u.RawQuery = query.Encode()
	return u.String(), nil
}

func (c Client) Finish(ctx context.Context, name string, provider Provider, callback, code, nonce, verifier string) (*Identity, error) {
	if !provider.Enabled || provider.ClientID == "" || provider.ClientSecret == "" || code == "" {
		return nil, errors.New("invalid SSO callback")
	}
	form := url.Values{"grant_type": {"authorization_code"}, "client_id": {provider.ClientID}, "client_secret": {provider.ClientSecret}, "redirect_uri": {callback}, "code": {code}}
	if name == "qq" {
		return c.finishQQ(ctx, provider, form)
	}
	if name != "logto" {
		return nil, errors.New("unknown SSO provider")
	}
	discovery, err := c.Discover(ctx, provider)
	if err != nil {
		return nil, err
	}
	form.Set("code_verifier", verifier)
	form.Del("client_secret")
	var token struct {
		IDToken string `json:"id_token"`
	}
	if err := c.request(ctx, http.MethodPost, discovery.TokenEndpoint, form, &token, [2]string{provider.ClientID, provider.ClientSecret}); err != nil {
		return nil, err
	}
	var keys struct {
		Keys []json.RawMessage `json:"keys"`
	}
	if err := c.request(ctx, http.MethodGet, discovery.JWKSURI, nil, &keys); err != nil {
		return nil, err
	}
	claims := jwt.MapClaims{}
	_, err = jwt.ParseWithClaims(token.IDToken, claims, func(token *jwt.Token) (any, error) {
		kid, _ := token.Header["kid"].(string)
		for _, raw := range keys.Keys {
			var key struct {
				Kid string `json:"kid"`
				Kty string `json:"kty"`
				Alg string `json:"alg"`
				Use string `json:"use"`
				N   string `json:"n"`
				E   string `json:"e"`
				X   string `json:"x"`
				Y   string `json:"y"`
				Crv string `json:"crv"`
			}
			if json.Unmarshal(raw, &key) != nil || key.Kid != kid || (key.Use != "" && key.Use != "sig") || (key.Alg != "" && key.Alg != token.Method.Alg()) {
				continue
			}
			decode := base64.RawURLEncoding.DecodeString
			if key.Kty == "RSA" && token.Method.Alg() == "RS256" {
				n, err := decode(key.N)
				if err != nil {
					return nil, err
				}
				e, err := decode(key.E)
				if err != nil || len(e) > 4 {
					return nil, errors.New("invalid RSA exponent")
				}
				exponent := 0
				for _, b := range e {
					exponent = exponent*256 + int(b)
				}
				if exponent < 3 {
					return nil, errors.New("invalid RSA exponent")
				}
				return &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: exponent}, nil
			}
			if key.Kty == "EC" {
				var curve elliptic.Curve
				if key.Crv == "P-256" && token.Method.Alg() == "ES256" {
					curve = elliptic.P256()
				}
				if key.Crv == "P-384" && token.Method.Alg() == "ES384" {
					curve = elliptic.P384()
				}
				if curve == nil {
					continue
				}
				x, err := decode(key.X)
				if err != nil {
					return nil, err
				}
				y, err := decode(key.Y)
				if err != nil {
					return nil, err
				}
				pub := &ecdsa.PublicKey{Curve: curve, X: new(big.Int).SetBytes(x), Y: new(big.Int).SetBytes(y)}
				if !curve.IsOnCurve(pub.X, pub.Y) {
					return nil, errors.New("invalid EC public key")
				}
				return pub, nil
			}
		}
		return nil, errors.New("OIDC signing key not found")
	}, jwt.WithValidMethods([]string{"RS256", "ES256", "ES384"}), jwt.WithIssuer(discovery.Issuer), jwt.WithAudience(provider.ClientID), jwt.WithExpirationRequired(), jwt.WithIssuedAt())
	if err != nil {
		return nil, fmt.Errorf("invalid OIDC ID token: %w", err)
	}
	if claims["nonce"] != nonce {
		return nil, errors.New("OIDC nonce mismatch")
	}
	if azp, ok := claims["azp"].(string); ok && azp != provider.ClientID {
		return nil, errors.New("OIDC authorized party mismatch")
	}
	if audiences, err := claims.GetAudience(); err != nil || (len(audiences) > 1 && claims["azp"] != provider.ClientID) {
		return nil, errors.New("invalid OIDC authorized party")
	}
	sub, _ := claims["sub"].(string)
	if sub == "" {
		return nil, errors.New("missing OIDC subject")
	}
	email, _ := claims["email"].(string)
	verified, _ := claims["email_verified"].(bool)
	nickname, _ := claims["name"].(string)
	return &Identity{Subject: sub, Name: nickname, Email: email, EmailVerified: verified}, nil
}

func (c Client) finishQQ(ctx context.Context, provider Provider, form url.Values) (*Identity, error) {
	form.Set("fmt", "json")
	var token struct {
		AccessToken string `json:"access_token"`
	}
	if err := c.request(ctx, http.MethodGet, "https://graph.qq.com/oauth2.0/token?"+form.Encode(), nil, &token); err != nil {
		return nil, err
	}
	if token.AccessToken == "" {
		return nil, errors.New("QQ did not issue an access token")
	}
	query := url.Values{"access_token": {token.AccessToken}, "fmt": {"json"}}
	var identity struct {
		ClientID string `json:"client_id"`
		OpenID   string `json:"openid"`
	}
	if err := c.request(ctx, http.MethodGet, "https://graph.qq.com/oauth2.0/me?"+query.Encode(), nil, &identity); err != nil {
		return nil, err
	}
	if identity.ClientID != provider.ClientID || identity.OpenID == "" {
		return nil, errors.New("invalid QQ application or identity")
	}
	query.Set("oauth_consumer_key", provider.ClientID)
	query.Set("openid", identity.OpenID)
	var profile struct {
		Ret      int    `json:"ret"`
		Nickname string `json:"nickname"`
	}
	if err := c.request(ctx, http.MethodGet, "https://graph.qq.com/user/get_user_info?"+query.Encode(), nil, &profile); err != nil {
		return nil, err
	}
	if profile.Ret != 0 {
		return nil, errors.New("QQ profile request failed")
	}
	return &Identity{Subject: identity.OpenID, Name: profile.Nickname}, nil
}
