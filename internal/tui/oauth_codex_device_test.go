package tui

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
)

// I-000026: the TUI's Codex login is the gateway's device login; it never
// starts the removed browser login with the localhost:1455 redirect.
func TestCodexOAuthStartsTheDeviceLogin(t *testing.T) {
	var mu sync.Mutex
	var calls []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		calls = append(calls, r.Method+" "+r.URL.Path)
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodPost && r.URL.Path == "/v0/management/codex-device-login" {
			_, _ = w.Write([]byte(`{"status":"ok","flow":"device","state":"codex-device-0123456789abcdef0123456789abcdef","verification_uri":"https://auth.openai.com/codex/device","url":"https://auth.openai.com/codex/device","user_code":"ABCD-1234","expires_in":900,"expires_at":"2026-10-11T12:15:00Z"}`))
			return
		}
		w.WriteHeader(http.StatusGone)
		_, _ = w.Write([]byte(`{"status":"error","error":"codex_browser_login_removed"}`))
	}))
	defer server.Close()

	var codex *oauthProvider
	for i := range oauthProviders {
		if oauthProviders[i].name == "Codex (OpenAI)" {
			codex = &oauthProviders[i]
		}
		if oauthProviders[i].apiPath == "codex-auth-url" {
			t.Fatalf("provider %q still uses the removed codex-auth-url", oauthProviders[i].name)
		}
	}
	if codex == nil {
		t.Fatal("no Codex provider in the OAuth tab")
	}

	m := newOAuthTabModel(NewClientWithBaseURL(server.URL, "secret"))
	msg, ok := m.startOAuth(*codex, 1)().(oauthStartMsg)
	if !ok {
		t.Fatal("startOAuth did not return an oauthStartMsg")
	}
	if msg.err != nil {
		t.Fatalf("start Codex login: %v", msg.err)
	}
	if !msg.deviceFlow || msg.userCode != "ABCD-1234" || msg.url != "https://auth.openai.com/codex/device" || msg.expiresIn != 900 || msg.state != "codex-device-0123456789abcdef0123456789abcdef" {
		t.Fatalf("start message = %+v, want the device login's URL, code, state and expiry", msg)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(calls) != 1 || calls[0] != "POST /v0/management/codex-device-login" {
		t.Fatalf("gateway calls = %v, want only POST /v0/management/codex-device-login", calls)
	}
}
