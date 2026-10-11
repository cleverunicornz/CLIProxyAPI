// Verbatim probes of validator a249 (CLIProxyAPI #9 at 95274db0, round 4).
package management

import (
	"context"
	"errors"
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
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
)

// The legacy store's real TTL continues running while device storage hangs.
// Expire its timestamp directly instead of sleeping for thirty minutes.
func TestA249LegacyOutcomeAfterLongCommit(t *testing.T) {
	for _, fail := range []bool{false, true} {
		t.Run(fmt.Sprintf("fail=%t", fail), func(t *testing.T) {
			f := a249Fixture(t)
			gate := a232NewGate()
			defer gate.open()
			f.handler.tokenStore = &a249Store{a232Store: f.store, before: func(context.Context, *coreauth.Auth) error {
				gate.hold()
				if fail {
					return errors.New("A249_FAKE_STORE_REFUSED")
				}
				return nil
			}}
			state := f.start(t, 1)
			pr9Wait(t, gate.reached)
			oauthSessions.mu.Lock()
			entry := oauthSessions.sessions[state]
			entry.ExpiresAt = time.Now().Add(-time.Nanosecond)
			oauthSessions.sessions[state] = entry
			oauthSessions.mu.Unlock()
			_, pending, _ := f.h.status(state)
			during := a249Legacy(f.handler, state)
			gate.open()
			f.h.waitWatcher(state)
			_, final, _ := f.h.status(state)
			legacy := a249Legacy(f.handler, state)
			t.Logf("after original session TTL: device-during=%v legacy-during=%v device-final=%v legacy-final=%v/%v", pending["status"], during["status"], final["status"], legacy["status"], legacy["error"])
			if pending["status"] != "pending" {
				t.Fatal("did not hold an in-progress commit")
			}
			if !fail && legacy["status"] != "ok" {
				t.Error("done device login is not legacy ok for one minute after completion")
			}
			if fail && legacy["error"] != "Failed to save authentication tokens" {
				t.Error("legacy status lost the store failure outcome")
			}
		})
	}
}

// The existing POST parser uses body.state before redirect_url.state and does
// not accept query.state as a replacement. The removal shortcut must use the
// same state as the eventual plugin callback handling.
func TestA249PluginCallbackEffectiveState(t *testing.T) {
	for _, shape := range []string{"body", "redirect"} {
		for _, query := range []string{"", "&state=a249-unrelated-query"} {
			t.Run(shape+query, func(t *testing.T) {
				replaceOAuthSessionStoreForTest(t, newOAuthSessionStore(time.Minute))
				state := "a249-fake-plugin-state"
				if err := RegisterPluginOAuthSession(state, "openai", nil); err != nil {
					t.Fatal(err)
				}
				dir := t.TempDir()
				h := NewHandlerWithoutConfigFilePath(&config.Config{AuthDir: dir}, nil)
				router := gin.New()
				router.POST("/callback", h.PostOAuthCallback)
				body := `{"provider":"openai","state":"` + state + `","code":"A249_FAKE_CODE"}`
				if shape == "redirect" {
					body = `{"provider":"openai","redirect_url":"https://plugin.example.test/callback?state=` + state + `&code=A249_FAKE_CODE"}`
				}
				request := httptest.NewRequest(http.MethodPost, "/callback?provider=openai"+query, strings.NewReader(body))
				request.Header.Set("Content-Type", "application/json")
				rec := httptest.NewRecorder()
				router.ServeHTTP(rec, request)
				_, err := os.Stat(filepath.Join(dir, ".oauth-openai-"+state+".oauth"))
				t.Logf("shape=%s unrelated-query=%t status=%d callback=%t", shape, query != "", rec.Code, err == nil)
				if rec.Code != 200 || err != nil {
					t.Error("query state overrides effective plugin body state only in removal classification")
				}
			})
		}
	}
}

// Replacement for R3's refresh and non-atomic rollback probes: refresh the
// previous committed auth through the ordinary save path while A is staged.
// An accepted A cancel must never erase or roll that real external write back.
func TestA249CancelledStagedLoginPreservesNormalRefresh(t *testing.T) {
	f := a249Fixture(t)
	first := f.start(t, 1)
	f.h.waitWatcher(first)
	gate := a232NewGate()
	defer gate.open()
	original := codexDeviceStagedHook
	codexDeviceStagedHook = func(_ context.Context, a *coreauth.Auth) {
		if a232Label(a) == a232FakeLabel(2) {
			gate.hold()
		}
	}
	defer func() { codexDeviceStagedHook = original }()
	second := f.start(t, 2)
	pr9Wait(t, gate.reached)
	auths, err := f.store.inner.List(context.Background())
	if err != nil || len(auths) != 1 {
		t.Fatal("initial committed credential missing")
	}
	record := auths[0]
	record.Metadata["access_token"] = "A249_FAKE_REFRESHED_ACCESS"
	record.Metadata["refresh_token"] = "A249_FAKE_REFRESHED_REFRESH"
	if _, err = f.handler.saveTokenRecord(context.Background(), record); err != nil {
		t.Fatal(err)
	}
	if !f.cancel(t, second) {
		t.Fatal("staged cancel refused")
	}
	gate.open()
	f.h.waitWatcher(second)
	label, count := f.stored(t)
	t.Logf("cancelled staged login; normal refreshed credential preserved=%t count=%d", label == "A249_FAKE_REFRESHED_REFRESH", count)
	if count != 1 || label != "A249_FAKE_REFRESHED_REFRESH" {
		t.Error("cancelled staging changed the independent normal refresh")
	}
}

func TestA249TwoLoginCancelMatrix(t *testing.T) {
	for _, same := range []bool{false, true} {
		for mask := 0; mask < 4; mask++ {
			for _, order := range [][]int{{0, 1}, {1, 0}} {
				t.Run(fmt.Sprintf("sameAccess=%t/cancel=%02b/order=%d%d", same, mask, order[0]+1, order[1]+1), func(t *testing.T) {
					a234IsolateStore(t)
					replaceOAuthSessionStoreForTest(t, newOAuthSessionStore(time.Minute))
					f := a232NewFixture(t, same, "")
					gates := []*a232Gate{a232NewGate(), a232NewGate()}
					defer func() {
						for _, g := range gates {
							g.open()
						}
					}()
					a232HoldStaged(t, gates...)
					st := &a249Store{a232Store: f.store}
					f.handler.tokenStore = st
					states := make([]string, 2)
					for i := range states {
						states[i] = f.start(t, i+1)
						pr9Wait(t, gates[i].reached)
					}
					for i, state := range states {
						if mask&(1<<i) != 0 && !f.cancel(t, state) {
							t.Fatal("staged cancel refused")
						}
					}
					want := ""
					for _, i := range order {
						gates[i].open()
						f.h.waitWatcher(states[i])
						if mask&(1<<i) == 0 {
							want = a232FakeLabel(i + 1)
						}
					}
					actual, count := f.stored(t)
					if actual != want || (want == "" && count != 0) {
						t.Error("last committed credential mismatch")
					}
					for _, label := range st.snapshot() {
						for i := range states {
							if mask&(1<<i) != 0 && label == a232FakeLabel(i+1) {
								t.Error("cancelled credential was stored")
							}
						}
					}
				})
			}
		}
	}
}
