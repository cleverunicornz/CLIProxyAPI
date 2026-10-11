// Reproductions of validator a216/W-3 (CLIProxyAPI #9 at cbc34023), kept verbatim
// as regression tests: findings F1-F5 (a216/G-2..G-6).
package management

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	sdkAuth "github.com/router-for-me/CLIProxyAPI/v8/sdk/auth"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/bcrypt"
)

type pr9Transport func(*http.Request) (*http.Response, error)

func (f pr9Transport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func pr9Response(r *http.Request, status int, body string) (*http.Response, error) {
	return &http.Response{StatusCode: status, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(strings.NewReader(body)), Request: r}, nil
}

type pr9Buffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (b *pr9Buffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.b.Write(p)
}
func (b *pr9Buffer) String() string { b.mu.Lock(); defer b.mu.Unlock(); return b.b.String() }
func pr9UseClient(client *http.Client, timeout time.Duration) {
	codexDeviceLoginOptions = func(*config.Config) sdkAuth.CodexDeviceOptions {
		return sdkAuth.CodexDeviceOptions{HTTPClient: client, Timeout: timeout, PollInterval: 10 * time.Millisecond}
	}
}
func pr9Wait(t *testing.T, c <-chan struct{}) {
	t.Helper()
	select {
	case <-c:
	case <-time.After(5 * time.Second):
		t.Fatal("fake synchronization did not arrive")
	}
}

func TestValidatorPR9StartErrorDoesNotDiscloseFakeMaterial(t *testing.T) {
	h := newCodexDeviceHarness(t, 0)
	var logs pr9Buffer
	old := log.StandardLogger().Out
	log.SetOutput(&logs)
	defer log.SetOutput(old)
	marker := "PR9_FAKE_PRIVATE_MATERIAL"
	payload := fmt.Sprintf("{\"error\":\"refused\",\"device_auth_id\":%q,\"user_code\":%q,\"authorization_code\":%q,\"code_verifier\":%q,\"access_token\":%q}", marker, marker, marker, marker, marker)
	pr9UseClient(&http.Client{Transport: pr9Transport(func(r *http.Request) (*http.Response, error) {
		if r.URL.String() != fakeOpenAIUserCodeURL {
			t.Error("unexpected request")
		}
		return pr9Response(r, 500, payload)
	})}, 0)
	status, _, raw := h.do(http.MethodPost, "/v0/management/codex-device-login", true)
	responseLeak := strings.Contains(raw, marker)
	logLeak := strings.Contains(logs.String(), marker)
	t.Logf("HTTP=%d fake-private-material-in-response=%t in-log=%t", status, responseLeak, logLeak)
	if responseLeak || logLeak {
		t.Fatal("contract breach: upstream private material escapes on failed start")
	}
}

func TestValidatorPR9CancelBeforeSaveCannotPersistOrBecomeDone(t *testing.T) {
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
	handler.postAuthHook = func(ctx context.Context, a *coreauth.Auth) error {
		close(entered)
		<-release
		return ctx.Err()
	}
	r := gin.New()
	g := r.Group("/v0/management", handler.Middleware())
	g.POST("/codex-device-login", handler.StartCodexDeviceLogin)
	g.GET("/codex-device-login", handler.GetCodexDeviceLoginStatus)
	g.DELETE("/oauth-session", handler.CancelAuthSession)
	h.router = r
	state := h.start()["state"].(string)
	h.fake.decide("CODE-0001", "approve")
	pr9Wait(t, entered)
	code, cancel, _ := h.do(http.MethodDelete, "/v0/management/oauth-session?state="+state, true)
	_, during, _ := h.status(state)
	close(release)
	h.waitWatcher(state)
	_, after, _ := h.status(state)
	files := h.authFiles()
	t.Logf("cancel HTTP=%d accepted=%v status-before-save-resumes=%v final=%v stored-files=%d", code, cancel["cancelled"], during["status"], after["status"], len(files))
	if cancel["cancelled"] != true {
		t.Fatal("fake did not cancel a pending save")
	}
	if len(files) != 0 || after["status"] != "cancelled" {
		t.Fatal("accepted cancellation was followed by credential persistence or success")
	}
}

func TestValidatorPR9InflightPollCannotOutliveExpiry(t *testing.T) {
	h := newCodexDeviceHarness(t, 150*time.Millisecond)
	entered := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	pr9UseClient(&http.Client{Transport: pr9Transport(func(r *http.Request) (*http.Response, error) {
		if r.URL.String() == fakeOpenAIPollURL {
			once.Do(func() { close(entered) })
			select {
			case <-release:
			case <-r.Context().Done():
				return nil, r.Context().Err()
			}
		}
		return h.fake.RoundTrip(r)
	})}, 150*time.Millisecond)
	state := h.start()["state"].(string)
	pr9Wait(t, entered)
	rec, ok := codexDeviceLogins.get(state)
	if !ok {
		t.Fatal("missing fake login")
	}
	timer := time.NewTimer(time.Until(rec.expiresAt) + 10*time.Millisecond)
	<-timer.C
	if time.Now().Before(rec.expiresAt) {
		t.Fatal("probe did not cross expiry")
	}
	_, atExpiry, _ := h.status(state)
	_, stillCode := atExpiry["user_code"]
	h.fake.decide("CODE-0001", "approve")
	close(release)
	h.waitWatcher(state)
	_, after, _ := h.status(state)
	files := h.authFiles()
	t.Logf("after-deadline status=%v user-code-visible=%t; delayed approval final=%v stored-files=%d", atExpiry["status"], stillCode, after["status"], len(files))
	if atExpiry["status"] != "expired" || stillCode || after["status"] != "expired" || len(files) != 0 {
		t.Fatal("expired device login stays pending or persists a late successful response")
	}
}

func TestValidatorPR9SlowDownRetriesRatherThanFails(t *testing.T) {
	for _, status := range []int{400, 429} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			h := newCodexDeviceHarness(t, 0)
			var polls atomic.Int32
			pr9UseClient(&http.Client{Transport: pr9Transport(func(r *http.Request) (*http.Response, error) {
				if r.URL.String() == fakeOpenAIPollURL {
					if polls.Add(1) == 1 {
						return pr9Response(r, status, "{\"error\":\"slow_down\"}")
					}
					h.fake.decide("CODE-0001", "approve")
				}
				return h.fake.RoundTrip(r)
			})}, 0)
			state := h.start()["state"].(string)
			result := h.waitStatus(state)
			h.waitWatcher(state)
			t.Logf("slow_down HTTP=%d final=%v error=%v polls=%d", status, result["status"], result["error"], polls.Load())
			if result["status"] != "done" || polls.Load() < 2 {
				t.Fatal("slow_down ends the login instead of applying polling backoff")
			}
		})
	}
}

func TestValidatorPR9RemovedCallbackMatchesPublishedContract(t *testing.T) {
	handler := NewHandlerWithoutConfigFilePath(&config.Config{AuthDir: t.TempDir()}, nil)
	for _, provider := range []string{"codex", "openai"} {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = httptest.NewRequest(http.MethodGet, "/v0/management/oauth-callback?provider="+provider, nil)
		handler.GetOAuthCallback(c)
		var body map[string]any
		_ = json.Unmarshal(w.Body.Bytes(), &body)
		t.Logf("provider=%s HTTP=%d error=%v", provider, w.Code, body["error"])
		if w.Code != 410 || body["error"] != "codex_browser_login_removed" {
			t.Error("identified removed Codex callback still takes the legacy validation path")
		}
	}
}
