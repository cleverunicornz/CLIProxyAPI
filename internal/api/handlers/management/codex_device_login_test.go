package management

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	sdkAuth "github.com/router-for-me/CLIProxyAPI/v8/sdk/auth"
	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/bcrypt"
)

const (
	fakeOpenAIUserCodeURL = "https://auth.openai.com/api/accounts/deviceauth/usercode"
	fakeOpenAIPollURL     = "https://auth.openai.com/api/accounts/deviceauth/token"
	fakeOpenAITokenURL    = "https://auth.openai.com/oauth/token"
	codexDeviceVerifyURL  = "https://auth.openai.com/codex/device"
	codexDeviceRedirect   = "https://auth.openai.com/deviceauth/callback"
	codexDeviceTestKey    = "device-test-key"
)

var codexDeviceStatePattern = regexp.MustCompile(`^codex-device-[0-9a-f]{32}$`)

// fakeOpenAIDevice plays OpenAI's device-login endpoints: the user-code
// request, the device-token poll and the authorization-code exchange. Each
// device stays pending (403) until the test approves or denies it. Any other
// URL fails the test, so no request leaves the process.
type fakeOpenAIDevice struct {
	t *testing.T

	mu            sync.Mutex
	issued        int
	userCodeFails int
	devices       map[string]*fakeDevice // by device_auth_id
	exchanges     []url.Values
}

type fakeDevice struct {
	userCode string
	email    string
	decision string // "", "approve", "deny"
	polls    int
}

func newFakeOpenAIDevice(t *testing.T) *fakeOpenAIDevice {
	return &fakeOpenAIDevice{t: t, devices: make(map[string]*fakeDevice)}
}

func (f *fakeOpenAIDevice) client() *http.Client { return &http.Client{Transport: f} }

func (f *fakeOpenAIDevice) deviceAuthID(n int) string { return fmt.Sprintf("dev-secret-%d", n) }

func (f *fakeOpenAIDevice) decide(userCode, decision string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, device := range f.devices {
		if device.userCode == userCode {
			device.decision = decision
			return
		}
	}
	f.t.Fatalf("no device with user code %q", userCode)
}

func (f *fakeOpenAIDevice) pollCount(userCode string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, device := range f.devices {
		if device.userCode == userCode {
			return device.polls
		}
	}
	return 0
}

func (f *fakeOpenAIDevice) RoundTrip(req *http.Request) (*http.Response, error) {
	respond := func(status int, body string) (*http.Response, error) {
		return &http.Response{
			StatusCode: status,
			Body:       io.NopCloser(strings.NewReader(body)),
			Header:     http.Header{"Content-Type": []string{"application/json"}},
			Request:    req,
		}, nil
	}
	raw, errRead := io.ReadAll(req.Body)
	if errRead != nil {
		f.t.Errorf("read request body: %v", errRead)
	}
	f.mu.Lock()
	defer f.mu.Unlock()

	switch req.URL.String() {
	case fakeOpenAIUserCodeURL:
		var body map[string]string
		if errDecode := json.Unmarshal(raw, &body); errDecode != nil || body["client_id"] == "" {
			f.t.Errorf("user-code request body %s: %v", raw, errDecode)
		}
		if f.userCodeFails > 0 {
			return respond(http.StatusInternalServerError, `{"error":"server_error"}`)
		}
		f.issued++
		n := f.issued
		f.devices[f.deviceAuthID(n)] = &fakeDevice{
			userCode: fmt.Sprintf("CODE-%04d", n),
			email:    fmt.Sprintf("device-%d@example.test", n),
		}
		return respond(http.StatusOK, fmt.Sprintf(`{"device_auth_id":%q,"user_code":"CODE-%04d","interval":"5"}`, f.deviceAuthID(n), n))
	case fakeOpenAIPollURL:
		var body map[string]string
		if errDecode := json.Unmarshal(raw, &body); errDecode != nil {
			f.t.Errorf("poll request body %s: %v", raw, errDecode)
		}
		device, ok := f.devices[body["device_auth_id"]]
		if !ok || device.userCode != body["user_code"] {
			f.t.Errorf("poll for unknown device %s", raw)
			return respond(http.StatusBadRequest, `{"error":"unknown_device"}`)
		}
		device.polls++
		switch device.decision {
		case "approve":
			return respond(http.StatusOK, fmt.Sprintf(`{"authorization_code":"authcode-%s","code_verifier":"verifier-%s","code_challenge":"challenge-%s"}`, device.userCode, device.userCode, device.userCode))
		case "deny":
			return respond(http.StatusBadRequest, `{"error":"access_denied","error_description":"denied by dev-secret"}`)
		default:
			return respond(http.StatusForbidden, `{"error":"authorization_pending"}`)
		}
	case fakeOpenAITokenURL:
		form, errParse := url.ParseQuery(string(raw))
		if errParse != nil {
			f.t.Errorf("parse exchange body: %v", errParse)
		}
		f.exchanges = append(f.exchanges, form)
		userCode := strings.TrimPrefix(form.Get("code"), "authcode-")
		var device *fakeDevice
		for _, candidate := range f.devices {
			if candidate.userCode == userCode {
				device = candidate
			}
		}
		if device == nil || form.Get("code_verifier") != "verifier-"+userCode {
			f.t.Errorf("exchange for unknown code: %v", form)
			return respond(http.StatusBadRequest, `{"error":"invalid_grant"}`)
		}
		idToken := fakeCodexIDToken(device.email, "acct-"+userCode, "pro")
		return respond(http.StatusOK, fmt.Sprintf(`{"access_token":"access-%s","refresh_token":"refresh-%s","id_token":%q,"token_type":"Bearer","expires_in":3600}`, userCode, userCode, idToken))
	default:
		f.t.Errorf("unexpected request to %s", req.URL)
		return respond(http.StatusNotFound, `{}`)
	}
}

func sha8(value string) string {
	digest := sha256.Sum256([]byte(value))
	return hex.EncodeToString(digest[:])[:8]
}

func fakeCodexIDToken(email, accountID, plan string) string {
	claims, _ := json.Marshal(map[string]any{
		"email": email,
		"https://api.openai.com/auth": map[string]any{
			"chatgpt_account_id": accountID,
			"chatgpt_plan_type":  plan,
		},
	})
	enc := base64.RawURLEncoding
	return enc.EncodeToString([]byte(`{"alg":"none"}`)) + "." + enc.EncodeToString(claims) + ".sig"
}

type codexDeviceHarness struct {
	t       *testing.T
	fake    *fakeOpenAIDevice
	authDir string
	router  *gin.Engine
}

// newCodexDeviceHarness serves the device-login routes behind the management
// key middleware, with OpenAI replaced by the fake and the given timings.
func newCodexDeviceHarness(t *testing.T, timeout time.Duration) *codexDeviceHarness {
	t.Helper()
	fake := newFakeOpenAIDevice(t)
	original := codexDeviceLoginOptions
	codexDeviceLoginOptions = func(*config.Config) sdkAuth.CodexDeviceOptions {
		return sdkAuth.CodexDeviceOptions{HTTPClient: fake.client(), Timeout: timeout, PollInterval: 10 * time.Millisecond}
	}
	t.Cleanup(func() { codexDeviceLoginOptions = original })

	authDir := filepath.Join(t.TempDir(), "auths")
	keyHash, errHash := bcrypt.GenerateFromPassword([]byte(codexDeviceTestKey), bcrypt.MinCost)
	if errHash != nil {
		t.Fatalf("hash management key: %v", errHash)
	}
	cfg := &config.Config{AuthDir: authDir}
	cfg.RemoteManagement.SecretKey = string(keyHash)
	handler := NewHandlerWithoutConfigFilePath(cfg, nil)
	router := gin.New()
	mgmt := router.Group("/v0/management", handler.Middleware())
	mgmt.POST("/codex-device-login", handler.StartCodexDeviceLogin)
	mgmt.GET("/codex-device-login", handler.GetCodexDeviceLoginStatus)
	mgmt.GET("/get-auth-status", handler.GetAuthStatus)
	mgmt.DELETE("/oauth-session", handler.CancelAuthSession)
	return &codexDeviceHarness{t: t, fake: fake, authDir: authDir, router: router}
}

func (h *codexDeviceHarness) do(method, target string, authorized bool) (int, map[string]any, string) {
	h.t.Helper()
	req := httptest.NewRequest(method, target, bytes.NewReader(nil))
	req.RemoteAddr = "127.0.0.1:1234"
	if authorized {
		req.Header.Set("Authorization", "Bearer "+codexDeviceTestKey)
	}
	rec := httptest.NewRecorder()
	h.router.ServeHTTP(rec, req)
	var body map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	return rec.Code, body, rec.Body.String()
}

func (h *codexDeviceHarness) start() map[string]any {
	h.t.Helper()
	code, body, raw := h.do(http.MethodPost, "/v0/management/codex-device-login", true)
	if code != http.StatusOK {
		h.t.Fatalf("start status = %d, body %s", code, raw)
	}
	state, _ := body["state"].(string)
	h.t.Cleanup(func() { CancelOAuthSession(state) })
	return body
}

func (h *codexDeviceHarness) status(state string) (int, map[string]any, string) {
	h.t.Helper()
	return h.do(http.MethodGet, "/v0/management/codex-device-login?state="+url.QueryEscape(state), true)
}

// waitStatus polls the status route until the login leaves pending.
func (h *codexDeviceHarness) waitStatus(state string) map[string]any {
	h.t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		code, body, raw := h.status(state)
		if code != http.StatusOK {
			h.t.Fatalf("status code = %d, body %s", code, raw)
		}
		if body["status"] != "pending" {
			return body
		}
		if time.Now().After(deadline) {
			h.t.Fatalf("login %s still pending: %s", state, raw)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// waitWatcher waits until the gateway's background poller for state exits.
func (h *codexDeviceHarness) waitWatcher(state string) {
	h.t.Helper()
	select {
	case <-codexDeviceLogins.watcherDone(state):
	case <-time.After(10 * time.Second):
		h.t.Fatalf("device-login watcher for %s did not finish", state)
	}
}

func (h *codexDeviceHarness) authFiles() []string {
	h.t.Helper()
	entries, errRead := os.ReadDir(h.authDir)
	if errRead != nil && !os.IsNotExist(errRead) {
		h.t.Fatalf("read auth dir: %v", errRead)
	}
	var names []string
	for _, entry := range entries {
		if strings.HasSuffix(entry.Name(), ".json") {
			names = append(names, entry.Name())
		}
	}
	return names
}

// assertNoSecrets fails when a response carries the device code, the
// authorization code, PKCE values or a token.
func assertNoSecrets(t *testing.T, raw string) {
	t.Helper()
	for _, secret := range []string{"dev-secret", "device_auth_id", "authcode-", "verifier-", "challenge-", "access-CODE", "refresh-CODE", "access_token", "refresh_token", "id_token"} {
		if strings.Contains(raw, secret) {
			t.Fatalf("response leaks %q: %s", secret, raw)
		}
	}
}

func TestCodexDeviceLoginStartReturnsCodeWithoutDeviceSecret(t *testing.T) {
	h := newCodexDeviceHarness(t, 0)
	var logs bytes.Buffer
	originalOut := log.StandardLogger().Out
	log.SetOutput(&logs)
	t.Cleanup(func() { log.SetOutput(originalOut) })

	before := time.Now()
	code, body, raw := h.do(http.MethodPost, "/v0/management/codex-device-login", true)
	if code != http.StatusOK {
		t.Fatalf("start status = %d, body %s", code, raw)
	}
	state, _ := body["state"].(string)
	t.Cleanup(func() { CancelOAuthSession(state) })
	assertNoSecrets(t, raw)
	if !codexDeviceStatePattern.MatchString(state) {
		t.Fatalf("state = %q, want codex-device-<32 hex>", state)
	}
	for key, want := range map[string]any{
		"status":           "ok",
		"flow":             "device",
		"verification_uri": codexDeviceVerifyURL,
		"url":              codexDeviceVerifyURL,
		"user_code":        "CODE-0001",
		"expires_in":       float64(900),
	} {
		if body[key] != want {
			t.Fatalf("%s = %v, want %v (body %s)", key, body[key], want, raw)
		}
	}
	expiresAt, errParse := time.Parse(time.RFC3339, fmt.Sprint(body["expires_at"]))
	if errParse != nil {
		t.Fatalf("expires_at %v: %v", body["expires_at"], errParse)
	}
	if expiresAt.Before(before.Add(899*time.Second)) || expiresAt.After(time.Now().Add(901*time.Second)) {
		t.Fatalf("expires_at = %v, want about 15 minutes from now", expiresAt)
	}
	if strings.Contains(logs.String(), "CODE-0001") || strings.Contains(logs.String(), "dev-secret") {
		t.Fatalf("gateway log carries the user or device code: %s", logs.String())
	}

	code, pending, rawPending := h.status(state)
	if code != http.StatusOK || pending["status"] != "pending" || pending["user_code"] != "CODE-0001" || pending["verification_uri"] != codexDeviceVerifyURL {
		t.Fatalf("pending status = %d %s", code, rawPending)
	}
	if pending["expires_at"] != body["expires_at"] {
		t.Fatalf("pending expires_at = %v, start said %v", pending["expires_at"], body["expires_at"])
	}
	assertNoSecrets(t, rawPending)
	if _, _, legacy := h.do(http.MethodGet, "/v0/management/get-auth-status?state="+state, true); !strings.Contains(legacy, `"wait"`) {
		t.Fatalf("get-auth-status for a pending device login = %s, want wait", legacy)
	}
}

func TestCodexDeviceLoginSuccessStoresAuthLikeTheCLI(t *testing.T) {
	h := newCodexDeviceHarness(t, 0)
	started := h.start()
	state := started["state"].(string)

	h.fake.decide("CODE-0001", "approve")
	done := h.waitStatus(state)
	raw, _ := json.Marshal(done)
	assertNoSecrets(t, string(raw))
	if done["status"] != "done" {
		t.Fatalf("status = %s, want done", raw)
	}
	if _, has := done["user_code"]; has {
		t.Fatalf("finished login still shows the user code: %s", raw)
	}
	account, _ := done["account"].(map[string]any)
	wantName := "codex-" + sha8("acct-CODE-0001") + "-device-1@example.test-pro.json"
	if account["email"] != "device-1@example.test" || account["plan_type"] != "pro" || account["name"] != wantName {
		t.Fatalf("account = %v, want email device-1@example.test, plan pro, name %s", account, wantName)
	}

	h.fake.mu.Lock()
	exchanges := append([]url.Values(nil), h.fake.exchanges...)
	h.fake.mu.Unlock()
	if len(exchanges) != 1 || exchanges[0].Get("redirect_uri") != codexDeviceRedirect || exchanges[0].Get("code") != "authcode-CODE-0001" {
		t.Fatalf("token exchanges = %v, want one with redirect_uri %s", exchanges, codexDeviceRedirect)
	}

	data, errRead := os.ReadFile(filepath.Join(h.authDir, wantName))
	if errRead != nil {
		t.Fatalf("stored auth %s: %v (files %v)", wantName, errRead, h.authFiles())
	}
	var stored map[string]any
	if errDecode := json.Unmarshal(data, &stored); errDecode != nil {
		t.Fatalf("decode stored auth: %v", errDecode)
	}
	for key, want := range map[string]any{
		"type":          "codex",
		"email":         "device-1@example.test",
		"plan_type":     "pro",
		"access_token":  "access-CODE-0001",
		"refresh_token": "refresh-CODE-0001",
		"account_id":    "acct-CODE-0001",
	} {
		if stored[key] != want {
			t.Fatalf("stored %s = %v, want %v", key, stored[key], want)
		}
	}
	if _, _, legacy := h.do(http.MethodGet, "/v0/management/get-auth-status?state="+state, true); !strings.Contains(legacy, `"ok"`) {
		t.Fatalf("get-auth-status after success = %s, want ok", legacy)
	}
}

func TestCodexDeviceLoginExpires(t *testing.T) {
	h := newCodexDeviceHarness(t, 150*time.Millisecond)
	started := h.start()
	state := started["state"].(string)
	if started["expires_in"] != float64(1) {
		t.Fatalf("expires_in = %v for a 150ms timeout, want it rounded up to 1", started["expires_in"])
	}

	expired := h.waitStatus(state)
	raw, _ := json.Marshal(expired)
	if expired["status"] != "expired" || expired["error"] != "expired" || expired["message"] == "" {
		t.Fatalf("status = %s, want expired with a message", raw)
	}
	if _, has := expired["user_code"]; has {
		t.Fatalf("expired login still shows the user code: %s", raw)
	}
	h.waitWatcher(state)
	if files := h.authFiles(); len(files) != 0 {
		t.Fatalf("expired login stored %v", files)
	}
	if _, _, legacy := h.do(http.MethodGet, "/v0/management/get-auth-status?state="+state, true); !strings.Contains(legacy, `"error"`) {
		t.Fatalf("get-auth-status after expiry = %s, want error", legacy)
	}
}

func TestCodexDeviceLoginDeniedFails(t *testing.T) {
	h := newCodexDeviceHarness(t, 0)
	state := h.start()["state"].(string)

	h.fake.decide("CODE-0001", "deny")
	failed := h.waitStatus(state)
	raw, _ := json.Marshal(failed)
	if failed["status"] != "failed" || failed["error"] != "provider_rejected" {
		t.Fatalf("status = %s, want failed/provider_rejected", raw)
	}
	message, _ := failed["message"].(string)
	if !strings.Contains(message, "400") || strings.Contains(message, "dev-secret") || strings.Contains(message, "access_denied") {
		t.Fatalf("message = %q, want the status code and no provider body", message)
	}
	h.waitWatcher(state)
	if files := h.authFiles(); len(files) != 0 {
		t.Fatalf("denied login stored %v", files)
	}
}

func TestCodexDeviceLoginCancelStopsPollingAndStoresNothing(t *testing.T) {
	h := newCodexDeviceHarness(t, 0)
	state := h.start()["state"].(string)

	code, body, raw := h.do(http.MethodDelete, "/v0/management/oauth-session?state="+state, true)
	if code != http.StatusOK || body["cancelled"] != true {
		t.Fatalf("cancel = %d %s, want cancelled true", code, raw)
	}
	_, cancelled, rawCancelled := h.status(state)
	if cancelled["status"] != "cancelled" {
		t.Fatalf("status after cancel = %s", rawCancelled)
	}
	if _, has := cancelled["user_code"]; has {
		t.Fatalf("cancelled login still shows the user code: %s", rawCancelled)
	}
	h.waitWatcher(state)
	polls := h.fake.pollCount("CODE-0001")

	// The poller has exited; OpenAI confirming after the cancel changes nothing.
	h.fake.decide("CODE-0001", "approve")
	if after := h.fake.pollCount("CODE-0001"); after != polls {
		t.Fatalf("gateway polled OpenAI %d more times after cancel", after-polls)
	}
	if files := h.authFiles(); len(files) != 0 {
		t.Fatalf("cancelled login stored %v", files)
	}
	if _, again, rawAgain := h.status(state); again["status"] != "cancelled" {
		t.Fatalf("status later = %s, want still cancelled", rawAgain)
	}
	if _, second, rawSecond := h.do(http.MethodDelete, "/v0/management/oauth-session?state="+state, true); second["cancelled"] != false {
		t.Fatalf("second cancel = %s, want cancelled false", rawSecond)
	}
}

func TestCodexDeviceLoginConcurrentLoginsAreIndependent(t *testing.T) {
	h := newCodexDeviceHarness(t, 0)
	first := h.start()
	second := h.start()
	firstState, secondState := first["state"].(string), second["state"].(string)
	if firstState == secondState || first["user_code"] == second["user_code"] {
		t.Fatalf("two logins share state or code: %v / %v", first, second)
	}

	h.fake.decide("CODE-0002", "approve")
	done := h.waitStatus(secondState)
	if done["status"] != "done" {
		t.Fatalf("second login = %v, want done", done)
	}
	if _, pending, raw := h.status(firstState); pending["status"] != "pending" || pending["user_code"] != "CODE-0001" {
		t.Fatalf("first login after second finished = %s, want still pending", raw)
	}

	h.fake.decide("CODE-0001", "deny")
	if failed := h.waitStatus(firstState); failed["status"] != "failed" {
		t.Fatalf("first login = %v, want failed", failed)
	}
	if _, still, raw := h.status(secondState); still["status"] != "done" {
		t.Fatalf("second login after first failed = %s, want still done", raw)
	}
	if files := h.authFiles(); len(files) != 1 || !strings.Contains(files[0], "device-2@example.test") {
		t.Fatalf("stored auths = %v, want only device-2's", files)
	}
}

func TestCodexDeviceLoginRequiresManagementKey(t *testing.T) {
	h := newCodexDeviceHarness(t, 0)
	if code, _, raw := h.do(http.MethodPost, "/v0/management/codex-device-login", false); code != http.StatusUnauthorized {
		t.Fatalf("start without key = %d %s, want 401", code, raw)
	}
	h.fake.mu.Lock()
	issued := h.fake.issued
	h.fake.mu.Unlock()
	if issued != 0 {
		t.Fatalf("a start without key asked OpenAI for %d codes", issued)
	}
	state := h.start()["state"].(string)
	if code, _, raw := h.do(http.MethodGet, "/v0/management/codex-device-login?state="+state, false); code != http.StatusUnauthorized || strings.Contains(raw, "CODE-") {
		t.Fatalf("status without key = %d %s, want 401 without the code", code, raw)
	}
}

func TestCodexDeviceLoginStatusErrors(t *testing.T) {
	h := newCodexDeviceHarness(t, 0)
	for _, tc := range []struct {
		target string
		code   int
		err    string
	}{
		{"/v0/management/codex-device-login", http.StatusBadRequest, "missing_state"},
		{"/v0/management/codex-device-login?state=../x", http.StatusBadRequest, "invalid_state"},
		{"/v0/management/codex-device-login?state=codex-device-00000000000000000000000000000000", http.StatusNotFound, "unknown_state"},
	} {
		code, body, raw := h.do(http.MethodGet, tc.target, true)
		if code != tc.code || body["status"] != "error" || body["error"] != tc.err {
			t.Fatalf("%s = %d %s, want %d %s", tc.target, code, raw, tc.code, tc.err)
		}
	}

	// A non-device login's state is not a device login.
	RegisterOAuthSession("codex-plain-state", "codex")
	t.Cleanup(func() { CancelOAuthSession("codex-plain-state") })
	if code, body, raw := h.status("codex-plain-state"); code != http.StatusNotFound || body["error"] != "unknown_state" {
		t.Fatalf("browser-login state = %d %s, want 404 unknown_state", code, raw)
	}
}

func TestCodexDeviceLoginStartFailsWhenOpenAIRefuses(t *testing.T) {
	h := newCodexDeviceHarness(t, 0)
	h.fake.userCodeFails = 1
	code, body, raw := h.do(http.MethodPost, "/v0/management/codex-device-login", true)
	if code != http.StatusBadGateway || body["status"] != "error" || body["error"] != "device_code_request_failed" || body["message"] == "" {
		t.Fatalf("start = %d %s, want 502 device_code_request_failed", code, raw)
	}
	if _, has := body["state"]; has {
		t.Fatalf("failed start returned a state: %s", raw)
	}
}

func TestCodexDeviceLoginFinishedLoginIsForgottenAfterRetention(t *testing.T) {
	h := newCodexDeviceHarness(t, 0)
	state := h.start()["state"].(string)
	h.fake.decide("CODE-0001", "approve")
	if done := h.waitStatus(state); done["status"] != "done" {
		t.Fatalf("login = %v, want done", done)
	}
	h.waitWatcher(state)

	originalNow := codexDeviceLogins.now
	codexDeviceLogins.now = func() time.Time { return time.Now().Add(14 * time.Minute) }
	if code, body, raw := h.status(state); code != http.StatusOK || body["status"] != "done" {
		t.Fatalf("14 minutes after finishing = %d %s, want still done", code, raw)
	}
	codexDeviceLogins.now = func() time.Time { return time.Now().Add(16 * time.Minute) }
	t.Cleanup(func() { codexDeviceLogins.now = originalNow })
	if code, body, raw := h.status(state); code != http.StatusNotFound || body["error"] != "unknown_state" {
		t.Fatalf("16 minutes after finishing = %d %s, want 404 unknown_state", code, raw)
	}
}
