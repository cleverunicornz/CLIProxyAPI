// Verbatim probe of validator a232 (CLIProxyAPI #9 at cda83cdf, round 3).
package management

import (
	"fmt"
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

// POST accepts redirect_url, including its state, for a known plugin flow.
// The fixture callback is HTTPS on example.test; no real code or localhost
// paste-back login is used.
func TestA232PluginRedirectStateExemption(t *testing.T) {
	for _, explicit := range []bool{false, true} {
		t.Run(fmt.Sprintf("provider_query_%t", explicit), func(t *testing.T) {
			replaceOAuthSessionStoreForTest(t, newOAuthSessionStore(time.Minute))
			state := "a232-fake-plugin-redirect"
			if e := RegisterPluginOAuthSession(state, "openai", nil); e != nil {
				t.Fatal(e)
			}
			dir := t.TempDir()
			handler := NewHandlerWithoutConfigFilePath(&config.Config{AuthDir: dir}, nil)
			router := gin.New()
			router.POST("/oauth-callback", handler.PostOAuthCallback)
			target := "/oauth-callback"
			if explicit {
				target += "?provider=openai"
			}
			body := `{"provider":"openai","redirect_url":"https://plugin.example.test/callback?state=` + state + `&code=A232_FAKE_CODE"}`
			req := httptest.NewRequest(http.MethodPost, target, strings.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()
			router.ServeHTTP(rec, req)
			_, e := os.Stat(filepath.Join(dir, ".oauth-openai-"+state+".oauth"))
			t.Logf("known-plugin state-in-redirect query-provider=%t HTTP=%d callback-written=%t", explicit, rec.Code, e == nil)
			if rec.Code != 200 || e != nil {
				t.Error("known plugin redirected state is classified as removed built-in flow")
			}
		})
	}
}
