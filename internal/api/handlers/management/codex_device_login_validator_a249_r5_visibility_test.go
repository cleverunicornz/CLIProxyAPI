// Probe of validator a249, round 5 (CLIProxyAPI #9 at 3cd6d079), kept as a
// regression test. Verbatim except its final assertion follows contract
// revision 5: auth-files lists what the running gateway holds, so a done
// credential appears there once registered, in the commit or at the next load.
package management

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
)

// Revision 4 correctly makes done independent of runtime registration, but
// its preceding Storage paragraph still promises immediate auth-files visibility.
func TestA249R5DoneAuthFilesVisibilityAfterRegistrationFailure(t *testing.T) {
	for _, reject := range []bool{false, true} {
		t.Run(fmt.Sprintf("reject=%t", reject), func(t *testing.T) {
			f := a249Fixture(t)
			manager := coreauth.NewManager(f.handler.tokenStoreWithBaseDir(), nil, nil)
			f.handler.authManager = manager
			f.handler.postAuthPersistHook = func(ctx context.Context, a *coreauth.Auth) error {
				if reject {
					return errors.New("R5_FAKE_REGISTRATION_FAILURE")
				}
				_, err := manager.Register(ctx, a)
				return err
			}
			state := f.start(t, 1)
			f.h.waitWatcher(state)
			_, status, _ := f.h.status(state)
			_, stored := f.stored(t)
			list := func() int {
				w := httptest.NewRecorder()
				c, _ := gin.CreateTestContext(w)
				c.Request = httptest.NewRequest(http.MethodGet, "/v0/management/auth-files", nil)
				f.handler.ListAuthFiles(c)
				if w.Code != 200 {
					t.Fatalf("auth-files HTTP=%d", w.Code)
				}
				var body struct {
					Files []json.RawMessage `json:"files"`
				}
				if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
					t.Fatal(err)
				}
				return len(body.Files)
			}
			before := list()
			if err := manager.Load(context.Background()); err != nil {
				t.Fatal(err)
			}
			after := list()
			t.Logf("done=%t stored=%d auth-files-before-load=%d auth-files-after-load=%d", status["status"] == "done", stored, before, after)
			if status["status"] != "done" || stored != 1 || after != 1 {
				t.Fatal("stored-and-loadable contract control failed")
			}
			if !reject && before != 1 {
				t.Error("a registered done credential is not listed by auth-files")
			}
			if reject && before != 0 {
				t.Error("an unregistered credential is listed before the next load")
			}
		})
	}
}
