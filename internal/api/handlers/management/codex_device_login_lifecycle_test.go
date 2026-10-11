package management

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	sdkAuth "github.com/router-for-me/CLIProxyAPI/v8/sdk/auth"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/bcrypt"
)

// Beyond the validator's reproductions (a216/W-3): nothing OpenAI sends reaches a
// response or a log, one state machine decides between cancel, expiry and save,
// and polling follows RFC 8628.

const lifecycleMarker = "LIFECYCLE_FAKE_PROVIDER_TEXT"

func captureLogs(t *testing.T) *pr9Buffer {
	t.Helper()
	var logs pr9Buffer
	old := log.StandardLogger().Out
	log.SetOutput(&logs)
	t.Cleanup(func() { log.SetOutput(old) })
	return &logs
}

func useDeviceOptions(t *testing.T, client *http.Client, timeout, slowDownStep time.Duration) {
	t.Helper()
	original := codexDeviceLoginOptions
	codexDeviceLoginOptions = func(*config.Config) sdkAuth.CodexDeviceOptions {
		return sdkAuth.CodexDeviceOptions{HTTPClient: client, Timeout: timeout, PollInterval: 10 * time.Millisecond, SlowDownStep: slowDownStep}
	}
	t.Cleanup(func() { codexDeviceLoginOptions = original })
}

func TestCodexDeviceLoginStartFailureDisclosesNothing(t *testing.T) {
	for _, tc := range []struct {
		status int
		body   string
	}{
		{http.StatusInternalServerError, `{"error":"` + lifecycleMarker + `","device_auth_id":"` + lifecycleMarker + `"}`},
		{http.StatusNotFound, lifecycleMarker},
		{http.StatusBadRequest, `{"error":{"message":"` + lifecycleMarker + `"}}`},
	} {
		t.Run(fmt.Sprint(tc.status), func(t *testing.T) {
			h := newCodexDeviceHarness(t, 0)
			logs := captureLogs(t)
			pr9UseClient(&http.Client{Transport: pr9Transport(func(r *http.Request) (*http.Response, error) {
				return pr9Response(r, tc.status, tc.body)
			})}, 0)
			code, body, raw := h.do(http.MethodPost, "/v0/management/codex-device-login", true)
			if code != http.StatusBadGateway || body["error"] != "device_code_request_failed" {
				t.Fatalf("start = %d %s, want 502 device_code_request_failed", code, raw)
			}
			message, _ := body["message"].(string)
			if !strings.Contains(message, fmt.Sprint(tc.status)) {
				t.Fatalf("message %q does not name the upstream status %d", message, tc.status)
			}
			if strings.Contains(raw, lifecycleMarker) || strings.Contains(logs.String(), lifecycleMarker) {
				t.Fatalf("provider text escaped: response %s; log %s", raw, logs.String())
			}
		})
	}
}

func TestCodexDeviceLoginUnreachableStartDisclosesNothing(t *testing.T) {
	h := newCodexDeviceHarness(t, 0)
	logs := captureLogs(t)
	pr9UseClient(&http.Client{Transport: pr9Transport(func(r *http.Request) (*http.Response, error) {
		return nil, fmt.Errorf("dial %s", lifecycleMarker)
	})}, 0)
	code, body, raw := h.do(http.MethodPost, "/v0/management/codex-device-login", true)
	if code != http.StatusBadGateway || body["error"] != "device_code_request_failed" {
		t.Fatalf("start = %d %s, want 502 device_code_request_failed", code, raw)
	}
	if strings.Contains(raw, lifecycleMarker) || strings.Contains(logs.String(), lifecycleMarker) {
		t.Fatalf("transport detail escaped: response %s; log %s", raw, logs.String())
	}
}

func TestCodexDeviceLoginPollAndExchangeFailuresDiscloseNothing(t *testing.T) {
	for _, tc := range []struct {
		name, url, body, wantError string
		status                     int
	}{
		{"poll denied", fakeOpenAIPollURL, `{"error":"access_denied","error_description":"` + lifecycleMarker + `"}`, "provider_rejected", http.StatusBadRequest},
		{"poll error", fakeOpenAIPollURL, lifecycleMarker, "provider_rejected", http.StatusInternalServerError},
		{"exchange", fakeOpenAITokenURL, `{"error":"invalid_grant","error_description":"` + lifecycleMarker + `"}`, "exchange_failed", http.StatusBadRequest},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newCodexDeviceHarness(t, 0)
			logs := captureLogs(t)
			pr9UseClient(&http.Client{Transport: pr9Transport(func(r *http.Request) (*http.Response, error) {
				if r.URL.String() == tc.url {
					return pr9Response(r, tc.status, tc.body)
				}
				return h.fake.RoundTrip(r)
			})}, 0)
			state := h.start()["state"].(string)
			if tc.url == fakeOpenAITokenURL {
				h.fake.decide("CODE-0001", "approve")
			}
			result := h.waitStatus(state)
			h.waitWatcher(state)
			if result["status"] != "failed" || result["error"] != tc.wantError {
				t.Fatalf("status = %v, want failed/%s", result, tc.wantError)
			}
			_, _, raw := h.status(state)
			if strings.Contains(raw, lifecycleMarker) || strings.Contains(logs.String(), lifecycleMarker) {
				t.Fatalf("provider text escaped: response %s; log %s", raw, logs.String())
			}
			if files := h.authFiles(); len(files) != 0 {
				t.Fatalf("a failed login stored %v", files)
			}
		})
	}
}

// harnessWithSaveHook serves the routes through a handler whose save blocks in
// postAuthHook until released; the hook's own return value is hookResult.
func harnessWithSaveHook(t *testing.T, hookResult func(ctx context.Context) error) (*codexDeviceHarness, <-chan struct{}, chan<- struct{}) {
	t.Helper()
	h := newCodexDeviceHarness(t, 0)
	hash, err := bcrypt.GenerateFromPassword([]byte(codexDeviceTestKey), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{AuthDir: h.authDir}
	cfg.RemoteManagement.SecretKey = string(hash)
	handler := NewHandlerWithoutConfigFilePath(cfg, nil)
	entered := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	handler.postAuthHook = func(ctx context.Context, a *coreauth.Auth) error {
		once.Do(func() { close(entered) })
		<-release
		return hookResult(ctx)
	}
	r := gin.New()
	g := r.Group("/v0/management", handler.Middleware())
	g.POST("/codex-device-login", handler.StartCodexDeviceLogin)
	g.GET("/codex-device-login", handler.GetCodexDeviceLoginStatus)
	g.DELETE("/oauth-session", handler.CancelAuthSession)
	h.router = r
	return h, entered, release
}

// A save that ignores cancellation still completes; the accepted cancel then
// removes what it stored and the login stays cancelled.
func TestCodexDeviceLoginCancelDuringSaveRemovesWhatTheSaveStored(t *testing.T) {
	h, entered, release := harnessWithSaveHook(t, func(context.Context) error { return nil })
	state := h.start()["state"].(string)
	h.fake.decide("CODE-0001", "approve")
	pr9Wait(t, entered)
	code, cancel, raw := h.do(http.MethodDelete, "/v0/management/oauth-session?state="+state, true)
	if code != http.StatusOK || cancel["cancelled"] != true {
		t.Fatalf("cancel during save = %d %s, want cancelled true", code, raw)
	}
	if _, during, _ := h.status(state); during["status"] != "cancelled" {
		t.Fatalf("status right after the cancel = %v, want cancelled", during["status"])
	}
	close(release)
	h.waitWatcher(state)
	if _, after, rawAfter := h.status(state); after["status"] != "cancelled" {
		t.Fatalf("final status = %s, want cancelled", rawAfter)
	}
	if files := h.authFiles(); len(files) != 0 {
		t.Fatalf("a cancelled login left %v stored", files)
	}
}

func TestCodexDeviceLoginCancelAfterDoneIsRefused(t *testing.T) {
	h := newCodexDeviceHarness(t, 0)
	state := h.start()["state"].(string)
	h.fake.decide("CODE-0001", "approve")
	if done := h.waitStatus(state); done["status"] != "done" {
		t.Fatalf("login = %v, want done", done)
	}
	h.waitWatcher(state)
	code, cancel, raw := h.do(http.MethodDelete, "/v0/management/oauth-session?state="+state, true)
	if code != http.StatusOK || cancel["cancelled"] != false {
		t.Fatalf("cancel after done = %d %s, want cancelled false", code, raw)
	}
	if _, after, rawAfter := h.status(state); after["status"] != "done" {
		t.Fatalf("status after a refused cancel = %s, want done", rawAfter)
	}
	if files := h.authFiles(); len(files) != 1 {
		t.Fatalf("stored auths after a refused cancel = %v, want the login's", files)
	}
}

// RFC 8628 section 3.5: authorization_pending continues; slow_down continues
// with the interval raised by 5 seconds; expired_token ends the login as
// expired; access_denied and other errors end it as failed.
func TestCodexDeviceLoginPollAnswersFollowRFC8628(t *testing.T) {
	h := newCodexDeviceHarness(t, 0)
	var mu sync.Mutex
	polls := 0
	answers := []struct {
		status int
		body   string
	}{
		{http.StatusBadRequest, `{"error":"authorization_pending"}`},
		{http.StatusTooManyRequests, `{"error":"slow_down"}`},
		{http.StatusBadRequest, `{"error":{"code":"slow_down","message":"` + lifecycleMarker + `"}}`},
		{http.StatusForbidden, `{"error":"authorization_pending"}`},
	}
	useDeviceOptions(t, &http.Client{Transport: pr9Transport(func(r *http.Request) (*http.Response, error) {
		if r.URL.String() == fakeOpenAIPollURL {
			mu.Lock()
			n := polls
			polls++
			mu.Unlock()
			if n < len(answers) {
				return pr9Response(r, answers[n].status, answers[n].body)
			}
			h.fake.decide("CODE-0001", "approve")
		}
		return h.fake.RoundTrip(r)
	})}, 0, time.Millisecond)
	state := h.start()["state"].(string)
	result := h.waitStatus(state)
	h.waitWatcher(state)
	mu.Lock()
	defer mu.Unlock()
	if result["status"] != "done" || polls != len(answers)+1 {
		t.Fatalf("status = %v after %d polls, want done after %d", result, polls, len(answers)+1)
	}
}

func TestCodexDeviceLoginSlowDownWaitsFiveSecondsMore(t *testing.T) {
	h := newCodexDeviceHarness(t, 0)
	var mu sync.Mutex
	var times []time.Time
	useDeviceOptions(t, &http.Client{Transport: pr9Transport(func(r *http.Request) (*http.Response, error) {
		if r.URL.String() == fakeOpenAIPollURL {
			mu.Lock()
			times = append(times, time.Now())
			n := len(times)
			mu.Unlock()
			if n == 1 {
				return pr9Response(r, http.StatusBadRequest, `{"error":"slow_down"}`)
			}
			h.fake.decide("CODE-0001", "approve")
		}
		return h.fake.RoundTrip(r)
	})}, 0, 0)
	state := h.start()["state"].(string)
	result := h.waitStatus(state)
	h.waitWatcher(state)
	mu.Lock()
	defer mu.Unlock()
	if result["status"] != "done" || len(times) != 2 {
		t.Fatalf("status = %v after %d polls, want done after 2", result, len(times))
	}
	if gap := times[1].Sub(times[0]); gap < 5*time.Second {
		t.Fatalf("second poll %v after slow_down, want the interval raised by 5s", gap)
	}
}

func TestCodexDeviceLoginExpiredTokenAnswerExpires(t *testing.T) {
	h := newCodexDeviceHarness(t, 0)
	pr9UseClient(&http.Client{Transport: pr9Transport(func(r *http.Request) (*http.Response, error) {
		if r.URL.String() == fakeOpenAIPollURL {
			return pr9Response(r, http.StatusBadRequest, `{"error":"expired_token"}`)
		}
		return h.fake.RoundTrip(r)
	})}, 0)
	state := h.start()["state"].(string)
	result := h.waitStatus(state)
	h.waitWatcher(state)
	if result["status"] != "expired" || result["error"] != "expired" {
		t.Fatalf("status = %v, want expired", result)
	}
}

// Every identified Codex callback answers 410 before the legacy validation.
func TestOAuthCallbackRefusesCodexBeforeValidation(t *testing.T) {
	store := newOAuthSessionStore(time.Minute)
	replaceOAuthSessionStoreForTest(t, store)
	store.Register("codex-browser-state", "codex")
	handler := NewHandlerWithoutConfigFilePath(&config.Config{AuthDir: t.TempDir()}, nil)
	router := gin.New()
	router.POST("/v0/management/oauth-callback", handler.PostOAuthCallback)
	router.GET("/v0/management/oauth-callback", handler.GetOAuthCallback)
	for _, tc := range []struct{ method, target, body string }{
		{http.MethodPost, "/v0/management/oauth-callback", `{"provider":"codex"}`},
		{http.MethodPost, "/v0/management/oauth-callback", `{"provider":"openai","state":"../bad"}`},
		{http.MethodPost, "/v0/management/oauth-callback", `{"state":"codex-browser-state"}`},
		{http.MethodGet, "/v0/management/oauth-callback?state=codex-browser-state", ""},
		{http.MethodGet, "/v0/management/oauth-callback?provider=codex&state=../bad", ""},
	} {
		req, _ := http.NewRequest(tc.method, tc.target, strings.NewReader(tc.body))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)
		assertCodexBrowserLoginRemoved(t, rec, tc.method+" "+tc.target+" "+tc.body)
	}
}

// docs/codex-device-login-management.md, Cancel: a pending login past its
// expiry answers cancelled false and reads expired.
func TestCodexDeviceLoginCancelPastExpiryIsRefused(t *testing.T) {
	h := newCodexDeviceHarness(t, 100*time.Millisecond)
	state := h.start()["state"].(string)
	record, ok := codexDeviceLogins.get(state)
	if !ok {
		t.Fatal("missing login")
	}
	<-time.After(time.Until(record.expiresAt) + 10*time.Millisecond)
	code, cancel, raw := h.do(http.MethodDelete, "/v0/management/oauth-session?state="+state, true)
	if code != http.StatusOK || cancel["cancelled"] != false {
		t.Fatalf("cancel past expiry = %d %s, want cancelled false", code, raw)
	}
	h.waitWatcher(state)
	if _, after, rawAfter := h.status(state); after["status"] != "expired" {
		t.Fatalf("status = %s, want expired", rawAfter)
	}
}
