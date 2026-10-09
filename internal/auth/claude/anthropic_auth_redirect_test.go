package claude

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"testing"
)

// The CLI login (sdk/auth/claude.go) catches the redirect on a local server,
// so its authorization URL and code exchange keep the localhost redirect.
func TestGenerateAuthURLKeepsLocalhostRedirect(t *testing.T) {
	auth := &ClaudeAuth{}
	authURL, state, errURL := auth.GenerateAuthURL("cli-state", &PKCECodes{CodeVerifier: "verifier", CodeChallenge: "challenge"})
	if errURL != nil {
		t.Fatalf("GenerateAuthURL() error = %v", errURL)
	}
	if state != "cli-state" {
		t.Fatalf("state = %q, want cli-state", state)
	}
	parsed, errParse := url.Parse(authURL)
	if errParse != nil {
		t.Fatalf("parse authorization URL: %v", errParse)
	}
	query := parsed.Query()
	want := map[string]string{
		"code":                  "true",
		"client_id":             ClientID,
		"response_type":         "code",
		"redirect_uri":          "http://localhost:54545/callback",
		"scope":                 ClaudeOAuthScope,
		"code_challenge":        "challenge",
		"code_challenge_method": "S256",
		"state":                 "cli-state",
	}
	for key, value := range want {
		if got := query.Get(key); got != value {
			t.Fatalf("authorization URL %s = %q, want %q", key, got, value)
		}
	}
}

func TestExchangeCodeForTokensKeepsLocalhostRedirect(t *testing.T) {
	var body map[string]string
	auth := &ClaudeAuth{
		httpClient: &http.Client{
			Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				switch req.URL.String() {
				case TokenURL:
					raw, errRead := io.ReadAll(req.Body)
					if errRead != nil {
						t.Fatalf("read token request: %v", errRead)
					}
					if errDecode := json.Unmarshal(raw, &body); errDecode != nil {
						t.Fatalf("decode token request %s: %v", raw, errDecode)
					}
					return jsonResponse(req, `{"access_token":"access","refresh_token":"refresh","expires_in":3600}`), nil
				case ProfileURL, RolesURL:
					return jsonResponse(req, `{}`), nil
				default:
					t.Fatalf("unexpected OAuth request URL %s", req.URL)
					return nil, nil
				}
			}),
		},
	}

	if _, errExchange := auth.ExchangeCodeForTokens(context.Background(), "cli-code", "cli-state", &PKCECodes{CodeVerifier: "verifier"}); errExchange != nil {
		t.Fatalf("ExchangeCodeForTokens() error = %v", errExchange)
	}
	if body["redirect_uri"] != "http://localhost:54545/callback" {
		t.Fatalf("token request redirect_uri = %q, want the localhost redirect", body["redirect_uri"])
	}
	if body["code"] != "cli-code" || body["state"] != "cli-state" || body["code_verifier"] != "verifier" {
		t.Fatalf("token request = %v, want the CLI code, state and verifier", body)
	}
}
