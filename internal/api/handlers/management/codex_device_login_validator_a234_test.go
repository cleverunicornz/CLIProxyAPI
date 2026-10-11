// Probes of validator a234 (CLIProxyAPI #9 at 32466e5d, round 2), kept as
// regression tests: R2-1 (a234/G-1), R2-2 (a234/G-2), R2-3 (a234/G-3). Verbatim
// except TestA234CancelCannotDeleteAnotherCompletedLogin's hold point (round 3).
package management

import (
	"bufio"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	sdkAuth "github.com/router-for-me/CLIProxyAPI/v8/sdk/auth"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	"golang.org/x/crypto/bcrypt"
)

// Independent correctness probes. All provider data and credentials are fake.
// This source is added with go -overlay and never changes the PR checkout.
func a234IsolateStore(t *testing.T) *codexDeviceLoginStore {
	t.Helper()
	old := codexDeviceLogins
	s := &codexDeviceLoginStore{now: time.Now, records: make(map[string]*codexDeviceLoginRecord)}
	codexDeviceLogins = s
	t.Cleanup(func() { codexDeviceLogins = old })
	return s
}

func TestA234PublishedExpiryIsTheActualExpiry(t *testing.T) {
	s := a234IsolateStore(t)
	h := newCodexDeviceHarness(t, 15*time.Minute)
	started := h.start()
	state := started["state"].(string)
	defer func() {
		h.do(http.MethodDelete, "/v0/management/oauth-session?state="+state, true)
		h.waitWatcher(state)
	}()
	exposed, err := time.Parse(time.RFC3339Nano, started["expires_at"].(string))
	if err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	actual := s.records[state].expiresAt
	s.now = func() time.Time { return exposed }
	s.mu.Unlock()
	_, atBoundary, _ := h.status(state)
	_, hasCode := atBoundary["user_code"]
	_, cancel, _ := h.do(http.MethodDelete, "/v0/management/oauth-session?state="+state, true)
	t.Logf("internal deadline minus published expiry=%v; at published expiry status=%v code-visible=%t cancel-accepted=%v", actual.Sub(exposed), atBoundary["status"], hasCode, cancel["cancelled"])
	if atBoundary["status"] != "expired" || hasCode || cancel["cancelled"] != false {
		t.Error("the exact published expires_at does not enforce documented status/cancel semantics")
	}
}

func TestA234CancelOutcomeTable(t *testing.T) {
	now := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name, initial, final string
		delta                time.Duration
		accepted             bool
	}{
		{"pending_before", "pending", "cancelled", time.Second, true},
		{"pending_exact", "pending", "expired", 0, false},
		{"pending_after", "pending", "expired", -time.Second, false},
		{"saving_before", "saving", "cancelled", time.Second, true},
		{"saving_after", "saving", "cancelled", -time.Second, true},
		{"done", "done", "done", time.Second, false},
		{"failed", "failed", "failed", time.Second, false},
		{"expired", "expired", "expired", -time.Second, false},
		{"cancelled", "cancelled", "cancelled", time.Second, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := a234IsolateStore(t)
			s.now = func() time.Time { return now }
			h := newCodexDeviceHarness(t, 0)
			state := "a234-table-" + tc.name
			s.add(state, &codexDeviceLoginRecord{status: tc.initial, expiresAt: now.Add(tc.delta), finishedAt: now, userCode: "A234-FAKE", done: make(chan struct{})})
			code, body, _ := h.do(http.MethodDelete, "/v0/management/oauth-session?state="+state, true)
			_, status, _ := h.status(state)
			if code != 200 || body["cancelled"] != tc.accepted || status["status"] != tc.final {
				t.Fatalf("HTTP=%d accepted=%v final=%v; want %t/%s", code, body["cancelled"], status["status"], tc.accepted, tc.final)
			}
		})
	}
	h := newCodexDeviceHarness(t, 0)
	for _, tc := range []struct {
		query string
		code  int
		err   string
	}{
		{"", 400, "missing state"}, {"?state=../bad", 400, "invalid state"}, {"?state=a234-unknown", 200, ""},
	} {
		code, body, _ := h.do(http.MethodDelete, "/v0/management/oauth-session"+tc.query, true)
		if code != tc.code || (tc.err != "" && body["error"] != tc.err) || (tc.err == "" && body["cancelled"] != false) {
			t.Fatalf("cancel table query %s HTTP=%d body=%v", tc.query, code, body)
		}
	}
}

func TestA234ConcurrentCancelAndStatus(t *testing.T) {
	h := newCodexDeviceHarness(t, 0)
	state := h.start()["state"].(string)
	var wg sync.WaitGroup
	var accepted atomic.Int32
	start := make(chan struct{})
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			if i%4 == 0 {
				code, body, _ := h.do(http.MethodDelete, "/v0/management/oauth-session?state="+state, true)
				if code != 200 {
					t.Errorf("cancel HTTP=%d", code)
				}
				if body["cancelled"] == true {
					accepted.Add(1)
				}
			} else {
				code, body, _ := h.status(state)
				if code != 200 || (body["status"] != "pending" && body["status"] != "cancelled") {
					t.Errorf("unexpected status HTTP=%d state=%v", code, body["status"])
				}
				if body["status"] == "cancelled" {
					if _, ok := body["user_code"]; ok {
						t.Error("cancelled status retains user code")
					}
				}
			}
		}(i)
	}
	close(start)
	wg.Wait()
	h.waitWatcher(state)
	_, after, _ := h.status(state)
	if accepted.Load() != 1 || after["status"] != "cancelled" || len(h.authFiles()) != 0 {
		t.Fatalf("accepted=%d final=%v files=%d", accepted.Load(), after["status"], len(h.authFiles()))
	}
}

func TestA234Polling5xxTerminatesSafelyAndNextLoginWorks(t *testing.T) {
	for _, code := range []int{500, 502, 503} {
		t.Run(fmt.Sprint(code), func(t *testing.T) {
			h := newCodexDeviceHarness(t, 0)
			logs := captureLogs(t)
			var failed atomic.Bool
			var pollCount atomic.Int32
			pr9UseClient(&http.Client{Transport: pr9Transport(func(r *http.Request) (*http.Response, error) {
				if r.URL.String() == fakeOpenAIPollURL {
					pollCount.Add(1)
					if failed.CompareAndSwap(false, true) {
						return pr9Response(r, code, `{"error":"server_error","error_description":"A234_FAKE_PRIVATE_PROVIDER_BODY"}`)
					}
				}
				return h.fake.RoundTrip(r)
			})}, 0)
			state := h.start()["state"].(string)
			result := h.waitStatus(state)
			h.waitWatcher(state)
			_, _, raw := h.status(state)
			if result["status"] != "failed" || result["error"] != "provider_rejected" || pollCount.Load() != 1 || len(h.authFiles()) != 0 {
				t.Fatalf("5xx status=%v error=%v polls=%d files=%d", result["status"], result["error"], pollCount.Load(), len(h.authFiles()))
			}
			if strings.Contains(raw, "A234_FAKE_PRIVATE_PROVIDER_BODY") || strings.Contains(logs.String(), "A234_FAKE_PRIVATE_PROVIDER_BODY") {
				t.Fatal("fake provider text escapes")
			}
			second := h.start()["state"].(string)
			h.fake.decide("CODE-0002", "approve")
			if result := h.waitStatus(second); result["status"] != "done" {
				t.Fatalf("fresh login did not recover: %v", result["status"])
			}
			h.waitWatcher(second)
		})
	}
}

func TestA234PluginOpenAIQueryStillWorks(t *testing.T) {
	replaceOAuthSessionStoreForTest(t, newOAuthSessionStore(time.Minute))
	for _, method := range []string{http.MethodGet, http.MethodPost} {
		for _, explicit := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/provider_query_%t", method, explicit), func(t *testing.T) {
				state := "a234-plugin-" + method + fmt.Sprint(explicit)
				if err := RegisterPluginOAuthSession(state, "openai", nil); err != nil {
					t.Fatal(err)
				}
				dir := t.TempDir()
				handler := NewHandlerWithoutConfigFilePath(&config.Config{AuthDir: dir}, nil)
				router := gin.New()
				router.GET("/oauth-callback", handler.GetOAuthCallback)
				router.POST("/oauth-callback", handler.PostOAuthCallback)
				target := "/oauth-callback?state=" + state + "&code=A234_FAKE_CODE"
				if explicit {
					target += "&provider=openai"
				}
				body := fmt.Sprintf(`{"state":%q,"provider":"openai","code":"A234_FAKE_CODE"}`, state)
				req := httptest.NewRequest(method, target, strings.NewReader(body))
				req.Header.Set("Content-Type", "application/json")
				w := httptest.NewRecorder()
				router.ServeHTTP(w, req)
				_, err := os.Stat(filepath.Join(dir, ".oauth-openai-"+state+".oauth"))
				t.Logf("plugin openai method=%s explicit-provider-query=%t HTTP=%d callback-written=%t", method, explicit, w.Code, err == nil)
				if w.Code != 200 || err != nil {
					t.Error("the removed-flow precheck rejects a known plugin session")
				}
			})
		}
	}
}

func TestA234CancelCannotDeleteAnotherCompletedLogin(t *testing.T) {
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
	var hooks atomic.Int32
	// Adapted after round 3: the first login is held at the stage point (its
	// credential ready, before its commit decision) rather than in
	// postAuthPersistHook, the runtime registration that is part of the commit.
	originalStaged := codexDeviceStagedHook
	codexDeviceStagedHook = func(context.Context, *coreauth.Auth) {
		if hooks.Add(1) == 1 {
			close(entered)
			<-release
		}
	}
	t.Cleanup(func() { codexDeviceStagedHook = originalStaged })
	router := gin.New()
	g := router.Group("/v0/management", handler.Middleware())
	g.POST("/codex-device-login", handler.StartCodexDeviceLogin)
	g.GET("/codex-device-login", handler.GetCodexDeviceLoginStatus)
	g.DELETE("/oauth-session", handler.CancelAuthSession)
	h.router = router
	pr9UseClient(&http.Client{Transport: pr9Transport(func(r *http.Request) (*http.Response, error) {
		if r.URL.String() == fakeOpenAITokenURL {
			jwt := fakeCodexIDToken("same-account@example.test", "a234-same-account", "pro")
			return pr9Response(r, 200, fmt.Sprintf(`{"access_token":"A234_FAKE_ACCESS","refresh_token":"A234_FAKE_REFRESH","id_token":%q,"expires_in":3600}`, jwt))
		}
		return h.fake.RoundTrip(r)
	})}, 0)
	first := h.start()["state"].(string)
	h.fake.decide("CODE-0001", "approve")
	pr9Wait(t, entered)
	second := h.start()["state"].(string)
	h.fake.decide("CODE-0002", "approve")
	secondResult := h.waitStatus(second)
	h.waitWatcher(second)
	before := len(h.authFiles())
	_, cancel, _ := h.do(http.MethodDelete, "/v0/management/oauth-session?state="+first, true)
	close(release)
	h.waitWatcher(first)
	_, after, _ := h.status(second)
	files := len(h.authFiles())
	t.Logf("second login status=%v files-before=%d; first cancel=%v; second final=%v files-after=%d", secondResult["status"], before, cancel["cancelled"], after["status"], files)
	if secondResult["status"] != "done" || before != 1 || cancel["cancelled"] != true {
		t.Fatal("controlled ordering not reached")
	}
	if files != 1 || after["status"] != "done" {
		t.Fatal("cancelling one login deleted the credential committed by another done login")
	}
}

// Real process replacement: the old process is killed during a pending fake
// login, then a fresh process queries that state and cancels it.
func TestA234GatewayRestartWorker(t *testing.T) {
	phase := os.Getenv("A234_RESTART_PHASE")
	if phase == "" {
		t.Skip("subprocess helper")
	}
	h := newCodexDeviceHarness(t, 0)
	if phase == "pending" {
		state := h.start()["state"].(string)
		pipe := os.NewFile(3, "ready")
		fmt.Fprintln(pipe, state)
		pipe.Close()
		select {}
	}
	state := os.Getenv("A234_RESTART_STATE")
	code, status, _ := h.status(state)
	_, cancel, _ := h.do(http.MethodDelete, "/v0/management/oauth-session?state="+state, true)
	t.Logf("after process replacement GET=%d error=%v cancel=%v files=%d", code, status["error"], cancel["cancelled"], len(h.authFiles()))
	if code != 404 || status["error"] != "unknown_state" || cancel["cancelled"] != false || len(h.authFiles()) != 0 {
		t.Fatal("restart contract mismatch")
	}
}

func TestA234GatewayRestartMidLogin(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	cmd := exec.Command(executable, "-test.run=^TestA234GatewayRestartWorker$", "-test.v")
	cmd.Env = append(os.Environ(), "A234_RESTART_PHASE=pending")
	cmd.ExtraFiles = []*os.File{w}
	var output pr9Buffer
	cmd.Stdout = &output
	cmd.Stderr = &output
	if err = cmd.Start(); err != nil {
		t.Fatal(err)
	}
	w.Close()
	defer func() {
		if cmd.ProcessState == nil {
			cmd.Process.Kill()
			cmd.Wait()
		}
	}()
	ready := make(chan string, 1)
	go func() {
		scanner := bufio.NewScanner(r)
		if scanner.Scan() {
			ready <- scanner.Text()
		} else {
			ready <- ""
		}
	}()
	var state string
	select {
	case state = <-ready:
	case <-time.After(10 * time.Second):
		t.Fatal("pending process did not become ready")
	}
	if !strings.HasPrefix(state, "codex-device-") {
		t.Fatalf("child did not start fake login: %s", output.String())
	}
	if err = cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	if err = cmd.Wait(); err == nil {
		t.Fatal("expected killed old process")
	}
	next := exec.Command(executable, "-test.run=^TestA234GatewayRestartWorker$", "-test.v")
	next.Env = append(os.Environ(), "A234_RESTART_PHASE=query", "A234_RESTART_STATE="+state)
	result, err := next.CombinedOutput()
	t.Logf("replacement process: %s", result)
	if err != nil {
		t.Fatal(err)
	}
}
