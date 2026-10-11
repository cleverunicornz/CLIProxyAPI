package management

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
)

// I-000026: the Codex login through the management API is the device code
// only. The browser login with the localhost:1455 redirect, and every
// callback that would complete it, answers 410 and starts nothing.

func assertCodexBrowserLoginRemoved(t *testing.T, rec *httptest.ResponseRecorder, what string) {
	t.Helper()
	if rec.Code != http.StatusGone {
		t.Fatalf("%s = %d %s, want 410", what, rec.Code, rec.Body.String())
	}
	var body map[string]any
	if errDecode := json.Unmarshal(rec.Body.Bytes(), &body); errDecode != nil {
		t.Fatalf("%s body %s: %v", what, rec.Body.String(), errDecode)
	}
	want := map[string]any{
		"status":       "error",
		"error":        "codex_browser_login_removed",
		"message":      "The Codex browser login is removed; use the device login.",
		"device_login": "POST /v0/management/codex-device-login",
	}
	if len(body) != len(want) {
		t.Fatalf("%s body = %v, want %v", what, body, want)
	}
	for key, value := range want {
		if body[key] != value {
			t.Fatalf("%s %s = %v, want %v", what, key, body[key], value)
		}
	}
}

func TestCodexBrowserLoginStartIsRemoved(t *testing.T) {
	store := newOAuthSessionStore(time.Minute)
	replaceOAuthSessionStoreForTest(t, store)
	handler := NewHandlerWithoutConfigFilePath(&config.Config{AuthDir: t.TempDir()}, nil)
	router := gin.New()
	router.GET("/v0/management/codex-auth-url", handler.RequestCodexToken)
	router.GET("/v8/management/oauth/auth-url", handler.StartOAuthV8)

	for _, target := range []string{
		"/v0/management/codex-auth-url",
		"/v0/management/codex-auth-url?is_webui=true",
		"/v8/management/oauth/auth-url?provider=codex",
		"/v8/management/oauth/auth-url?provider=CODEX",
	} {
		req := httptest.NewRequest(http.MethodGet, target, nil)
		req.RemoteAddr = "127.0.0.1:1234"
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)
		assertCodexBrowserLoginRemoved(t, rec, target)
	}

	store.mu.Lock()
	sessions := len(store.sessions)
	store.mu.Unlock()
	if sessions != 0 {
		t.Fatalf("the removed login registered %d OAuth sessions", sessions)
	}
	callbackForwardersMu.Lock()
	_, forwarding := callbackForwarders[codexCallbackPort]
	callbackForwardersMu.Unlock()
	if forwarding {
		t.Fatalf("the removed login started the localhost:%d forwarder", codexCallbackPort)
	}
}

func TestOAuthCallbackRefusesCodex(t *testing.T) {
	store := newOAuthSessionStore(time.Minute)
	replaceOAuthSessionStoreForTest(t, store)
	store.Register("codex-browser-state", "codex")
	store.Register("codex-device-0123456789abcdef0123456789abcdef", "codex")
	store.Register("claude-state", "anthropic")

	authDir := t.TempDir()
	handler := NewHandlerWithoutConfigFilePath(&config.Config{AuthDir: authDir}, nil)
	router := gin.New()
	router.POST("/v0/management/oauth-callback", handler.PostOAuthCallback)
	router.GET("/v0/management/oauth-callback", handler.GetOAuthCallback)

	post := func(body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/v0/management/oauth-callback", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)
		return rec
	}
	get := func(query string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, "/v0/management/oauth-callback?"+query, nil)
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)
		return rec
	}

	assertCodexBrowserLoginRemoved(t, post(`{"provider":"codex","state":"codex-browser-state","code":"c"}`), "POST provider codex")
	assertCodexBrowserLoginRemoved(t, post(`{"provider":"openai","state":"codex-browser-state","code":"c"}`), "POST provider openai")
	assertCodexBrowserLoginRemoved(t, post(`{"state":"codex-browser-state","code":"c"}`), "POST codex state without provider")
	assertCodexBrowserLoginRemoved(t, post(`{"redirect_url":"http://localhost:1455/auth/callback?code=c&state=codex-browser-state"}`), "POST pasted localhost address")
	assertCodexBrowserLoginRemoved(t, post(`{"provider":"codex","state":"never-started","code":"c"}`), "POST codex unknown state")
	assertCodexBrowserLoginRemoved(t, post(`{"state":"codex-device-0123456789abcdef0123456789abcdef","code":"c"}`), "POST device-login state")
	assertCodexBrowserLoginRemoved(t, get("provider=codex&state=codex-browser-state&code=c"), "GET provider codex")
	assertCodexBrowserLoginRemoved(t, get("state=codex-browser-state&code=c"), "GET codex state")

	entries, errRead := os.ReadDir(authDir)
	if errRead != nil {
		t.Fatalf("read auth dir: %v", errRead)
	}
	for _, entry := range entries {
		if strings.Contains(entry.Name(), "codex") {
			t.Fatalf("a refused Codex callback wrote %s", entry.Name())
		}
	}
	if !store.IsPending("codex-device-0123456789abcdef0123456789abcdef", "codex") {
		t.Fatal("a refused callback ended the device login's session")
	}

	// Claude's code-page login keeps its callback.
	if rec := post(`{"provider":"anthropic","state":"claude-state","code":"c"}`); rec.Code != http.StatusOK {
		t.Fatalf("anthropic callback = %d %s, want 200", rec.Code, rec.Body.String())
	}
	if _, errStat := os.Stat(filepath.Join(authDir, ".oauth-anthropic-claude-state.oauth")); errStat != nil {
		t.Fatalf("anthropic callback file: %v", errStat)
	}
}
