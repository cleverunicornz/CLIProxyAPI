package api

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/api/handlers/management"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/logging"
	log "github.com/sirupsen/logrus"
)

// The device-login routes are management routes: registered under
// /v0/management and refused without the management key.
func TestCodexDeviceLoginRoutesRequireManagementKey(t *testing.T) {
	gin.SetMode(gin.TestMode)
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte("port: 8317\nremote-management: {secret-key: test-password}\n"), 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Plugins.Dir = filepath.Dir(path)
	h := management.NewHandler(cfg, path, nil)
	h.SetLocalPassword("test-password")
	s := &Server{cfg: cfg, engine: gin.New(), mgmt: h}
	s.managementRoutesEnabled.Store(true)
	s.registerManagementRoutes()

	for _, tc := range []struct {
		method, target string
		authorized     bool
		want           int
	}{
		{http.MethodPost, "/v0/management/codex-device-login", false, http.StatusUnauthorized},
		{http.MethodGet, "/v0/management/codex-device-login?state=codex-device-00000000000000000000000000000000", false, http.StatusUnauthorized},
		{http.MethodGet, "/v0/management/codex-device-login?state=codex-device-00000000000000000000000000000000", true, http.StatusNotFound},
		{http.MethodGet, "/v0/management/codex-device-login", true, http.StatusBadRequest},
	} {
		req := httptest.NewRequest(tc.method, tc.target, nil)
		req.RemoteAddr = "127.0.0.1:1234"
		if tc.authorized {
			req.Header.Set("Authorization", "Bearer test-password")
		}
		rec := httptest.NewRecorder()
		s.engine.ServeHTTP(rec, req)
		if rec.Code != tc.want {
			t.Fatalf("%s %s (key %v) = %d %s, want %d", tc.method, tc.target, tc.authorized, rec.Code, rec.Body.String(), tc.want)
		}
		if tc.want == http.StatusNotFound && rec.Body.Len() == 0 {
			t.Fatalf("%s %s answered an empty 404: the route is not registered", tc.method, tc.target)
		}
	}
}

// I-000026: the localhost:1455 callback of the removed Codex browser login
// answers 410 and writes nothing, even for a pending Codex session.
func TestCodexLocalhostCallbackIsRemoved(t *testing.T) {
	s := newTestServer(t)
	state := "codex-callback-removed-state"
	management.RegisterOAuthSession(state, "codex")
	t.Cleanup(func() { management.CancelOAuthSession(state) })

	req := httptest.NewRequest(http.MethodGet, "/codex/callback?code=c&state="+state, nil)
	rec := httptest.NewRecorder()
	s.engine.ServeHTTP(rec, req)
	if rec.Code != http.StatusGone || !strings.Contains(rec.Body.String(), `"error":"codex_browser_login_removed"`) {
		t.Fatalf("GET /codex/callback = %d %s, want 410 codex_browser_login_removed", rec.Code, rec.Body.String())
	}
	if _, errStat := os.Stat(filepath.Join(s.cfg.AuthDir, ".oauth-codex-"+state+".oauth")); !os.IsNotExist(errStat) {
		t.Fatalf("the removed callback wrote a callback file: %v", errStat)
	}
	if !management.IsOAuthSessionPending(state, "codex") {
		t.Fatal("the removed callback ended the session")
	}
}

// The removed Codex routes answer 410 and their access-log lines carry no query
// string: a pasted callback's authorization code never reaches a log.
func TestCodexBrowserLoginRemovedRoutesLogNoQuery(t *testing.T) {
	gin.SetMode(gin.TestMode)
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte("port: 8317\nremote-management: {secret-key: test-password}\n"), 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Plugins.Dir = filepath.Dir(path)
	h := management.NewHandler(cfg, path, nil)
	h.SetLocalPassword("test-password")
	engine := gin.New()
	engine.Use(logging.GinLogrusLogger())
	s := &Server{cfg: cfg, engine: engine, mgmt: h}
	s.managementRoutesEnabled.Store(true)
	s.registerManagementRoutes()

	var captured bytes.Buffer
	old := log.StandardLogger().Out
	log.SetOutput(&captured)
	t.Cleanup(func() { log.SetOutput(old) })

	const marker = "REMOVED_ROUTE_FAKE_CODE"
	for _, tc := range []struct{ method, target, body string }{
		{http.MethodGet, "/v0/management/codex-auth-url?is_webui=true&code=" + marker, ""},
		{http.MethodGet, "/v8/management/oauth/auth-url?provider=codex&code=" + marker, ""},
		{http.MethodGet, "/v0/management/oauth-callback?provider=codex&code=" + marker + "&state=codex-fake-state", ""},
		{http.MethodGet, "/v8/management/oauth/callback?provider=openai&code=" + marker, ""},
		{http.MethodPost, "/v0/management/oauth-callback?code=" + marker, `{"provider":"codex","code":"` + marker + `"}`},
	} {
		req := httptest.NewRequest(tc.method, tc.target, strings.NewReader(tc.body))
		req.RemoteAddr = "127.0.0.1:1234"
		req.Header.Set("Authorization", "Bearer test-password")
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		s.engine.ServeHTTP(rec, req)
		if rec.Code != http.StatusGone {
			t.Fatalf("%s %s = %d %s, want 410", tc.method, tc.target, rec.Code, rec.Body.String())
		}
	}
	if strings.Contains(captured.String(), marker) {
		t.Fatalf("a removed route logged its query or body: %s", captured.String())
	}
	if !strings.Contains(captured.String(), "/v0/management/codex-auth-url") {
		t.Fatalf("the removed routes were not access-logged at all: %s", captured.String())
	}
}
