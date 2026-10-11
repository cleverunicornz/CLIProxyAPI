package management

import (
	"context"
	"encoding/json"
	"fmt"
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

// R2-1: a cancelled login whose save writes late, after another login of the
// same account has committed, must leave that login's credential in place.
func TestCodexDeviceLoginLateCancelledWriteRestoresTheCommittedLogin(t *testing.T) {
	h := newCodexDeviceHarness(t, 0)
	hash, err := bcrypt.GenerateFromPassword([]byte(codexDeviceTestKey), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{AuthDir: h.authDir}
	cfg.RemoteManagement.SecretKey = string(hash)
	handler := NewHandlerWithoutConfigFilePath(cfg, nil)
	handler.tokenStore = sdkAuth.NewFileTokenStore()
	entered := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	// The first login stops before its write, so it writes after the second commits.
	handler.postAuthHook = func(ctx context.Context, a *coreauth.Auth) error {
		first := false
		once.Do(func() { first = true })
		if first {
			close(entered)
			<-release
		}
		return nil
	}
	router := gin.New()
	g := router.Group("/v0/management", handler.Middleware())
	g.POST("/codex-device-login", handler.StartCodexDeviceLogin)
	g.GET("/codex-device-login", handler.GetCodexDeviceLoginStatus)
	g.DELETE("/oauth-session", handler.CancelAuthSession)
	h.router = router
	pr9UseClient(&http.Client{Transport: pr9Transport(func(r *http.Request) (*http.Response, error) {
		if r.URL.String() == fakeOpenAITokenURL {
			raw, _ := io.ReadAll(r.Body)
			form, _ := url.ParseQuery(string(raw))
			code := strings.TrimPrefix(form.Get("code"), "authcode-")
			jwt := fakeCodexIDToken("same-account@example.test", "same-account", "pro")
			return pr9Response(r, http.StatusOK, fmt.Sprintf(`{"access_token":"access-%s","refresh_token":"refresh-%s","id_token":%q,"expires_in":3600}`, code, code, jwt))
		}
		return h.fake.RoundTrip(r)
	})}, 0)

	first := h.start()["state"].(string)
	h.fake.decide("CODE-0001", "approve")
	pr9Wait(t, entered)
	second := h.start()["state"].(string)
	h.fake.decide("CODE-0002", "approve")
	if done := h.waitStatus(second); done["status"] != "done" {
		t.Fatalf("second login = %v, want done", done)
	}
	h.waitWatcher(second)
	if _, cancel, raw := h.do(http.MethodDelete, "/v0/management/oauth-session?state="+first, true); cancel["cancelled"] != true {
		t.Fatalf("cancel of the first login = %s, want cancelled true", raw)
	}
	close(release)
	h.waitWatcher(first)

	files := h.authFiles()
	if len(files) != 1 {
		t.Fatalf("stored auths = %v, want the second login's", files)
	}
	data, errRead := os.ReadFile(filepath.Join(h.authDir, files[0]))
	if errRead != nil {
		t.Fatal(errRead)
	}
	var stored map[string]any
	if errDecode := json.Unmarshal(data, &stored); errDecode != nil {
		t.Fatal(errDecode)
	}
	if stored["access_token"] != "access-CODE-0002" {
		t.Fatalf("stored access token = %v, want the committed second login's", stored["access_token"])
	}
	if _, after, raw := h.status(second); after["status"] != "done" {
		t.Fatalf("second login after the first's cancel = %s, want done", raw)
	}
	if _, after, raw := h.status(first); after["status"] != "cancelled" {
		t.Fatalf("first login = %s, want cancelled", raw)
	}
}

// R2-3: a known plugin session named openai keeps its callback even when the
// provider is in the query and its state only in the body.
func TestOAuthCallbackPluginOpenAIStateInBodyKeepsItsCallback(t *testing.T) {
	replaceOAuthSessionStoreForTest(t, newOAuthSessionStore(time.Minute))
	state := "plugin-openai-body-state"
	if err := RegisterPluginOAuthSession(state, "openai", nil); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	handler := NewHandlerWithoutConfigFilePath(&config.Config{AuthDir: dir}, nil)
	router := gin.New()
	router.POST("/oauth-callback", handler.PostOAuthCallback)
	req := httptest.NewRequest(http.MethodPost, "/oauth-callback?provider=openai", strings.NewReader(`{"state":"`+state+`","code":"c"}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("plugin openai callback = %d %s, want 200", rec.Code, rec.Body.String())
	}
	if _, errStat := os.Stat(filepath.Join(dir, ".oauth-openai-"+state+".oauth")); errStat != nil {
		t.Fatalf("plugin callback file: %v", errStat)
	}
	// The built-in Codex flow keeps its 410 with the same query.
	RegisterOAuthSession("builtin-codex-state", "codex")
	req = httptest.NewRequest(http.MethodPost, "/oauth-callback?provider=openai", strings.NewReader(`{"state":"builtin-codex-state","code":"c"}`))
	req.Header.Set("Content-Type", "application/json")
	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	assertCodexBrowserLoginRemoved(t, rec, "POST ?provider=openai with a built-in Codex state")
}

// R4-1: commits queue per account. A login of another account completes while
// one account's store write hangs.
func TestCodexDeviceLoginCommitOfAnotherAccountIsNotQueued(t *testing.T) {
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
	var releaseOnce sync.Once
	releaseStore := func() { releaseOnce.Do(func() { close(release) }) }
	defer releaseStore()
	handler.tokenStore = &hangingSaveStore{FileTokenStore: sdkAuth.NewFileTokenStore(), hang: func(a *coreauth.Auth) bool {
		return strings.Contains(a.FileName, "device-1@")
	}, entered: entered, release: release}
	router := gin.New()
	g := router.Group("/v0/management", handler.Middleware())
	g.POST("/codex-device-login", handler.StartCodexDeviceLogin)
	g.GET("/codex-device-login", handler.GetCodexDeviceLoginStatus)
	g.DELETE("/oauth-session", handler.CancelAuthSession)
	h.router = router

	first := h.start()["state"].(string)
	h.fake.decide("CODE-0001", "approve")
	pr9Wait(t, entered)
	second := h.start()["state"].(string)
	h.fake.decide("CODE-0002", "approve")
	if done := h.waitStatus(second); done["status"] != "done" {
		t.Fatalf("another account's login = %v while the first account's store write hangs, want done", done["status"])
	}
	if _, pending, raw := h.status(first); pending["status"] != "pending" {
		t.Fatalf("the hung login = %s, want pending", raw)
	}
	releaseStore()
	if done := h.waitStatus(first); done["status"] != "done" {
		t.Fatalf("the first login after its store write resumed = %v, want done", done["status"])
	}
}

// hangingSaveStore holds the first Save of a matching auth until released.
type hangingSaveStore struct {
	*sdkAuth.FileTokenStore
	hang    func(*coreauth.Auth) bool
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func (s *hangingSaveStore) Save(ctx context.Context, a *coreauth.Auth) (string, error) {
	if s.hang(a) {
		s.once.Do(func() {
			close(s.entered)
			<-s.release
		})
	}
	return s.FileTokenStore.Save(ctx, a)
}
