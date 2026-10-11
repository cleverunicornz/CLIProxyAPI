package api

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/api/handlers/management"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
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
