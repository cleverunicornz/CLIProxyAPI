// Reproduction of validator a216/W-3 (CLIProxyAPI #9 at cbc34023), kept verbatim
// as a regression test: finding F6 (a216/G-7).
package api

import (
	"bytes"
	log "github.com/sirupsen/logrus"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestValidatorPR9RemovedCallbackDoesNotLogFakeCode(t *testing.T) {
	s := newTestServer(t)
	var captured bytes.Buffer
	old := log.StandardLogger().Out
	log.SetOutput(&captured)
	defer log.SetOutput(old)
	marker := "PR9_FAKE_AUTHORIZATION_CODE"
	req := httptest.NewRequest(http.MethodGet, "/codex/callback?code="+marker+"&state=codex-fake-state", nil)
	rec := httptest.NewRecorder()
	s.engine.ServeHTTP(rec, req)
	leaked := strings.Contains(captured.String(), marker)
	t.Logf("removed callback HTTP=%d fake-authorization-code-in-log=%t", rec.Code, leaked)
	if leaked {
		t.Fatal("removed callback logs the supplied authorization-code query")
	}
}
