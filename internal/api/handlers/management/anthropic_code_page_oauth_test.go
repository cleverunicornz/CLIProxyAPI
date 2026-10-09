package management

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/auth/claude"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
)

// Anthropic's code-display page, the redirect Claude Code uses when nothing
// local can catch the browser (MANUAL_REDIRECT_URL in Claude Code 2.1.295).
const anthropicCodePageRedirect = "https://platform.claude.com/oauth/code/callback"

const anthropicLocalhostRedirect = "http://localhost:54545/callback"

func init() {
	gin.SetMode(gin.TestMode)
}

// fakeAnthropicOAuth answers the token, profile and roles requests a Claude
// login makes, records every token request body, and fails the test on any
// other URL, so no request leaves the process.
type fakeAnthropicOAuth struct {
	t      *testing.T
	mu     sync.Mutex
	tokens []map[string]string
}

func (f *fakeAnthropicOAuth) RoundTrip(req *http.Request) (*http.Response, error) {
	respond := func(body string) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader(body)),
			Header:     make(http.Header),
			Request:    req,
		}, nil
	}
	switch req.URL.String() {
	case claude.TokenURL:
		raw, errRead := io.ReadAll(req.Body)
		if errRead != nil {
			f.t.Errorf("read token request: %v", errRead)
		}
		var body map[string]string
		if errDecode := json.Unmarshal(raw, &body); errDecode != nil {
			f.t.Errorf("decode token request %s: %v", raw, errDecode)
		}
		f.mu.Lock()
		f.tokens = append(f.tokens, body)
		f.mu.Unlock()
		return respond(`{
			"access_token":"access",
			"refresh_token":"refresh",
			"token_type":"Bearer",
			"expires_in":3600,
			"account":{"uuid":"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa","email_address":"code-page@example.test"},
			"organization":{"uuid":"bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb","name":"Example Org"}
		}`)
	case claude.ProfileURL, claude.RolesURL:
		return respond(`{}`)
	default:
		f.t.Errorf("unexpected OAuth request to %s", req.URL)
		return nil, http.ErrNotSupported
	}
}

func (f *fakeAnthropicOAuth) tokenRequests() []map[string]string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]map[string]string(nil), f.tokens...)
}

func useFakeAnthropicOAuth(t *testing.T) *fakeAnthropicOAuth {
	t.Helper()
	fake := &fakeAnthropicOAuth{t: t}
	original := newClaudeAuth
	newClaudeAuth = func(*config.Config) *claude.ClaudeAuth {
		return claude.NewClaudeAuthWithHTTPClient(&http.Client{Transport: fake})
	}
	t.Cleanup(func() { newClaudeAuth = original })
	return fake
}

func newAnthropicLoginRouter(cfg *config.Config) (*gin.Engine, *Handler) {
	handler := NewHandlerWithoutConfigFilePath(cfg, nil)
	router := gin.New()
	router.GET("/v0/management/anthropic-auth-url", handler.RequestAnthropicToken)
	router.POST("/v0/management/oauth-callback", handler.PostOAuthCallback)
	return router, handler
}

// startAnthropicLogin starts a login as the dashboard does and returns the
// parsed authorization URL and the session state.
func startAnthropicLogin(t *testing.T, router http.Handler, query string) (*url.URL, string) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/v0/management/anthropic-auth-url"+query, nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("start login: status %d, body %s", w.Code, w.Body.String())
	}
	var payload struct {
		URL   string `json:"url"`
		State string `json:"state"`
	}
	if errDecode := json.Unmarshal(w.Body.Bytes(), &payload); errDecode != nil {
		t.Fatalf("decode start response: %v", errDecode)
	}
	if payload.State == "" {
		t.Fatalf("start response has no state: %s", w.Body.String())
	}
	t.Cleanup(func() { CancelOAuthSession(payload.State) })
	authURL, errParse := url.Parse(payload.URL)
	if errParse != nil {
		t.Fatalf("parse authorization URL %q: %v", payload.URL, errParse)
	}
	return authURL, payload.State
}

func postOAuthCallback(t *testing.T, router http.Handler, body map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	raw, errMarshal := json.Marshal(body)
	if errMarshal != nil {
		t.Fatalf("marshal callback body: %v", errMarshal)
	}
	req := httptest.NewRequest(http.MethodPost, "/v0/management/oauth-callback", bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	return w
}

func TestRequestAnthropicTokenUsesCodePageRedirect(t *testing.T) {
	useFakeAnthropicOAuth(t)
	router, _ := newAnthropicLoginRouter(&config.Config{AuthDir: t.TempDir()})

	authURL, state := startAnthropicLogin(t, router, "")

	query := authURL.Query()
	if got := query.Get("redirect_uri"); got != anthropicCodePageRedirect {
		t.Fatalf("management login redirect_uri = %q, want the code page %q", got, anthropicCodePageRedirect)
	}
	want := map[string]string{
		"code":                  "true",
		"client_id":             claude.ClientID,
		"response_type":         "code",
		"scope":                 claude.ClaudeOAuthScope,
		"code_challenge_method": "S256",
		"state":                 state,
	}
	for key, value := range want {
		if got := query.Get(key); got != value {
			t.Fatalf("authorization URL %s = %q, want %q", key, got, value)
		}
	}
	if query.Get("code_challenge") == "" {
		t.Fatal("authorization URL has no code_challenge")
	}
}

func TestRequestAnthropicTokenWebUIKeepsLocalhostRedirect(t *testing.T) {
	useFakeAnthropicOAuth(t)
	// is_webui=true starts the local forwarder on 54545 that catches the redirect.
	router, _ := newAnthropicLoginRouter(&config.Config{AuthDir: t.TempDir(), Port: 8317})

	authURL, _ := startAnthropicLogin(t, router, "?is_webui=true")

	if got := authURL.Query().Get("redirect_uri"); got != anthropicLocalhostRedirect {
		t.Fatalf("web UI login redirect_uri = %q, want %q", got, anthropicLocalhostRedirect)
	}
}

// The dashboard pastes back what the code page shows (code#state), splits it
// and posts {provider: "anthropic", state, code, error} to oauth-callback.
func TestAnthropicCodePageCallbackCompletesSession(t *testing.T) {
	fake := useFakeAnthropicOAuth(t)
	authDir := t.TempDir()
	router, _ := newAnthropicLoginRouter(&config.Config{AuthDir: authDir})

	authURL, state := startAnthropicLogin(t, router, "")

	w := postOAuthCallback(t, router, map[string]string{"provider": "anthropic", "state": state, "code": "code-from-page", "error": ""})
	if w.Code != http.StatusOK {
		t.Fatalf("oauth-callback: status %d, body %s", w.Code, w.Body.String())
	}
	waitForAnthropicSessionCompleted(t, state)

	tokens := fake.tokenRequests()
	if len(tokens) != 1 {
		t.Fatalf("token requests = %d, want 1", len(tokens))
	}
	body := tokens[0]
	if body["redirect_uri"] != anthropicCodePageRedirect {
		t.Fatalf("token request redirect_uri = %q, want the authorization URL's %q", body["redirect_uri"], anthropicCodePageRedirect)
	}
	if body["redirect_uri"] != authURL.Query().Get("redirect_uri") {
		t.Fatalf("token request redirect_uri = %q, authorization URL redirect_uri = %q", body["redirect_uri"], authURL.Query().Get("redirect_uri"))
	}
	if body["state"] != state {
		t.Fatalf("token request state = %q, want session state %q", body["state"], state)
	}
	if body["grant_type"] != "authorization_code" || body["code"] != "code-from-page" || body["client_id"] != claude.ClientID {
		t.Fatalf("token request = %v, want the authorization code grant for code-from-page", body)
	}
	hash := sha256.Sum256([]byte(body["code_verifier"]))
	if challenge := base64.RawURLEncoding.EncodeToString(hash[:]); challenge != authURL.Query().Get("code_challenge") {
		t.Fatalf("token request code_verifier does not match the authorization URL's code_challenge")
	}

	saved := filepath.Join(authDir, claude.CredentialFileName("code-page@example.test", "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"))
	if _, errStat := os.Stat(saved); errStat != nil {
		t.Fatalf("saved credential %s: %v", saved, errStat)
	}
}

func TestAnthropicOAuthCallbackRefusesWrongState(t *testing.T) {
	fake := useFakeAnthropicOAuth(t)
	router, _ := newAnthropicLoginRouter(&config.Config{AuthDir: t.TempDir()})

	authURL, state := startAnthropicLogin(t, router, "")
	if got := authURL.Query().Get("redirect_uri"); got != anthropicCodePageRedirect {
		t.Fatalf("management login redirect_uri = %q, want the code page %q", got, anthropicCodePageRedirect)
	}

	w := postOAuthCallback(t, router, map[string]string{"provider": "anthropic", "state": "not-" + state, "code": "code-from-page", "error": ""})
	if w.Code != http.StatusNotFound {
		t.Fatalf("oauth-callback with a wrong state: status %d, body %s; want %d", w.Code, w.Body.String(), http.StatusNotFound)
	}
	if !IsOAuthSessionPending(state, "anthropic") {
		t.Fatal("a wrong state changed the pending session")
	}
	if tokens := fake.tokenRequests(); len(tokens) != 0 {
		t.Fatalf("a wrong state reached the token endpoint: %v", tokens)
	}
}

func waitForAnthropicSessionCompleted(t *testing.T, state string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		_, status, _, _, completed, ok := GetOAuthSessionDetails(state)
		if !ok {
			t.Fatalf("session %s disappeared", state)
		}
		if completed {
			return
		}
		if status != "" {
			t.Fatalf("session %s failed: %s", state, status)
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for anthropic session %s to complete", state)
}
