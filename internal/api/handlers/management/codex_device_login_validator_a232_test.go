// Probes of validator a232 (CLIProxyAPI #9 at cda83cdf, round 3), kept as
// regression tests. R3-5 (TestA232PluginRedirectStateExemption) and R3-6
// (TestA232ExpiryRaceLeavesLegacyWaiting) are verbatim. The ownership probes
// keep the validator's fixture, scenarios and assertions, but hold a login at
// codexDeviceStagedHook - its credential ready, before the commit decision -
// instead of in postAuthPersistHook, the runtime registration, which is part
// of the commit since logins stage their credential until they commit. The
// validator's List-count gates had no counterpart once rollbacks were gone.
package management

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/auth/codex"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	sdkAuth "github.com/router-for-me/CLIProxyAPI/v8/sdk/auth"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	"golang.org/x/crypto/bcrypt"
)

// All credentials, codes, accounts and providers below are local fake fixtures.
type a232Gate struct {
	reached, release chan struct{}
	entered          atomic.Bool
	once             sync.Once
}

func a232NewGate() *a232Gate {
	return &a232Gate{reached: make(chan struct{}), release: make(chan struct{})}
}
func (g *a232Gate) hold() {
	if g.entered.CompareAndSwap(false, true) {
		close(g.reached)
		<-g.release
	}
}
func (g *a232Gate) open() { g.once.Do(func() { close(g.release) }) }

type a232Store struct {
	inner     *sdkAuth.FileTokenStore
	lists     atomic.Int64
	afterList func(int64, []*coreauth.Auth, error) ([]*coreauth.Auth, error)
}

func (s *a232Store) SetBaseDir(dir string) { s.inner.SetBaseDir(dir) }
func (s *a232Store) Save(ctx context.Context, a *coreauth.Auth) (string, error) {
	return s.inner.Save(ctx, a)
}
func (s *a232Store) Delete(ctx context.Context, id string) error { return s.inner.Delete(ctx, id) }
func (s *a232Store) List(ctx context.Context) ([]*coreauth.Auth, error) {
	n := s.lists.Add(1)
	a, e := s.inner.List(ctx)
	if s.afterList != nil {
		return s.afterList(n, a, e)
	}
	return a, e
}

type a232Fixture struct {
	h       *codexDeviceHarness
	handler *Handler
	store   *a232Store
}

func a232Label(a *coreauth.Auth) string {
	if a == nil {
		return ""
	}
	if s, ok := a.Storage.(*codex.CodexTokenStorage); ok && s != nil {
		return s.RefreshToken
	}
	v, _ := a.Metadata["refresh_token"].(string)
	return v
}
func a232FakeLabel(index int) string { return fmt.Sprintf("A232_FAKE_REFRESH_CODE-%04d", index) }
func a232NewFixture(t *testing.T, sameAccess bool, dir string) *a232Fixture {
	t.Helper()
	h := newCodexDeviceHarness(t, 0)
	if dir != "" {
		h.authDir = dir
	}
	if e := os.MkdirAll(h.authDir, 0700); e != nil {
		t.Fatal(e)
	}
	hash, e := bcrypt.GenerateFromPassword([]byte(codexDeviceTestKey), bcrypt.MinCost)
	if e != nil {
		t.Fatal(e)
	}
	cfg := &config.Config{AuthDir: h.authDir}
	cfg.RemoteManagement.SecretKey = string(hash)
	handler := NewHandlerWithoutConfigFilePath(cfg, nil)
	store := &a232Store{inner: sdkAuth.NewFileTokenStore()}
	handler.tokenStore = store
	store.SetBaseDir(h.authDir)
	router := gin.New()
	group := router.Group("/v0/management", handler.Middleware())
	group.POST("/codex-device-login", handler.StartCodexDeviceLogin)
	group.GET("/codex-device-login", handler.GetCodexDeviceLoginStatus)
	group.DELETE("/oauth-session", handler.CancelAuthSession)
	h.router = router
	account := t.Name()
	pr9UseClient(&http.Client{Transport: pr9Transport(func(r *http.Request) (*http.Response, error) {
		if r.URL.String() == fakeOpenAITokenURL {
			data, _ := io.ReadAll(r.Body)
			form, _ := url.ParseQuery(string(data))
			label := strings.TrimPrefix(form.Get("code"), "authcode-")
			access := "A232_FAKE_ACCESS_" + label
			if sameAccess {
				access = "A232_SHARED_FAKE_ACCESS"
			}
			jwt := fakeCodexIDToken("a232-fake@example.test", account, "pro")
			return pr9Response(r, 200, fmt.Sprintf(`{"access_token":%q,"refresh_token":%q,"id_token":%q,"expires_in":3600}`, access, "A232_FAKE_REFRESH_"+label, jwt))
		}
		return h.fake.RoundTrip(r)
	})}, 0)
	return &a232Fixture{h, handler, store}
}
func (f *a232Fixture) start(t *testing.T, index int) string {
	t.Helper()
	state := f.h.start()["state"].(string)
	f.h.fake.decide(fmt.Sprintf("CODE-%04d", index), "approve")
	return state
}
func (f *a232Fixture) cancel(t *testing.T, state string) bool {
	t.Helper()
	code, body, _ := f.h.do(http.MethodDelete, "/v0/management/oauth-session?state="+state, true)
	if code != 200 {
		t.Fatalf("cancel HTTP=%d", code)
	}
	return body["cancelled"] == true
}
func (f *a232Fixture) stored(t *testing.T) (string, int) {
	t.Helper()
	auths, e := f.store.inner.List(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	if len(auths) == 0 {
		return "", 0
	}
	return a232Label(auths[0]), len(auths)
}

// a232HoldStaged holds each login whose credential carries one of the gates'
// fake labels at the stage point, before its commit decision.
func a232HoldStaged(t *testing.T, gates ...*a232Gate) {
	t.Helper()
	original := codexDeviceStagedHook
	codexDeviceStagedHook = func(_ context.Context, a *coreauth.Auth) {
		for i, g := range gates {
			if g != nil && a232Label(a) == a232FakeLabel(i+1) {
				g.hold()
			}
		}
	}
	t.Cleanup(func() { codexDeviceStagedHook = original })
}

// R3-1, R3-2: exhaustive cancellation subsets and completion orders for three
// logins of one account held before their commit, with distinct and with
// equal access tokens. The last uncancelled login to complete owns the stored
// credential; a cancelled login's credential is never stored.
func TestA232ThreeLoginCancelMatrix(t *testing.T) {
	orders := [][]int{{0, 1, 2}, {0, 2, 1}, {1, 0, 2}, {1, 2, 0}, {2, 0, 1}, {2, 1, 0}}
	for _, same := range []bool{false, true} {
		for mask := 0; mask < 8; mask++ {
			for _, order := range orders {
				t.Run(fmt.Sprintf("sameAccess=%t/cancel=%03b/order=%d%d%d", same, mask, order[0]+1, order[1]+1, order[2]+1), func(t *testing.T) {
					f := a232NewFixture(t, same, "")
					gates := []*a232Gate{a232NewGate(), a232NewGate(), a232NewGate()}
					defer func() {
						for _, g := range gates {
							g.open()
						}
					}()
					a232HoldStaged(t, gates...)
					states := make([]string, 3)
					for i := range states {
						states[i] = f.start(t, i+1)
						pr9Wait(t, gates[i].reached)
					}
					for i, state := range states {
						if mask&(1<<i) != 0 && !f.cancel(t, state) {
							t.Fatalf("cancel %d was not accepted", i+1)
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
					statuses := make([]any, 3)
					for i, state := range states {
						_, s, _ := f.h.status(state)
						statuses[i] = s["status"]
					}
					if actual != want || (want == "" && count != 0) {
						t.Errorf("ownership mismatch: statuses=%v file-count=%d stored-cancelled=%t expected-last-commit-match=%t", statuses, count, want == "" && count > 0, actual == want)
					}
				})
			}
		}
	}
}

// A cancel is accepted until the commit decision and refused from then on.
// The commit phase holds the login in postAuthPersistHook, its runtime
// registration, which follows the store write inside the commit.
func TestA232CancelAtEachSaveBoundary(t *testing.T) {
	for _, phase := range []string{"pending", "before-stage", "staged", "commit", "done"} {
		t.Run(phase, func(t *testing.T) {
			f := a232NewFixture(t, false, "")
			gate := a232NewGate()
			defer gate.open()
			switch phase {
			case "before-stage":
				f.handler.postAuthHook = func(context.Context, *coreauth.Auth) error { gate.hold(); return nil }
			case "staged":
				a232HoldStaged(t, gate)
			case "commit":
				f.handler.postAuthPersistHook = func(context.Context, *coreauth.Auth) error { gate.hold(); return nil }
			}
			state := f.h.start()["state"].(string)
			if phase != "pending" {
				f.h.fake.decide("CODE-0001", "approve")
			}
			if phase == "done" {
				f.h.waitStatus(state)
				f.h.waitWatcher(state)
			} else if phase != "pending" {
				pr9Wait(t, gate.reached)
			}
			_, before, _ := f.h.status(state)
			accepted := f.cancel(t, state)
			gate.open()
			f.h.waitWatcher(state)
			actual, count := f.stored(t)
			_, after, _ := f.h.status(state)
			wantAccepted := phase != "commit" && phase != "done"
			t.Logf("phase=%s status-at-cancel=%v accepted=%t final=%v files=%d", phase, before["status"], accepted, after["status"], count)
			if accepted != wantAccepted {
				t.Error("cancel boundary mismatch")
			}
			if accepted && (count != 0 || after["status"] != "cancelled") {
				t.Error("cancelled credential remains")
			}
			if !accepted && (count != 1 || actual != a232FakeLabel(1) || after["status"] != "done") {
				t.Error("committed credential changed")
			}
		})
	}
}

// R3-2: nothing of a login is in the store before it commits, so no refresh
// can change a cancelled login's credential and leave it behind.
func TestA232StagedLoginIsNotLiveBeforeCommit(t *testing.T) {
	f := a232NewFixture(t, false, "")
	gate := a232NewGate()
	defer gate.open()
	a232HoldStaged(t, gate)
	state := f.start(t, 1)
	pr9Wait(t, gate.reached)
	_, staged := f.stored(t)
	if !f.cancel(t, state) {
		t.Fatal("cancel not accepted")
	}
	gate.open()
	f.h.waitWatcher(state)
	_, count := f.stored(t)
	_, status, _ := f.h.status(state)
	t.Logf("stored while staged=%d; cancelled status=%v; stored after=%d", staged, status["status"], count)
	if staged != 0 {
		t.Error("a login's credential is in the store before its commit")
	}
	if count != 0 || status["status"] != "cancelled" {
		t.Error("an accepted cancel left a credential")
	}
}

// R3-3: a cancelled login never removes a concurrent login's write; the
// concurrent login completes with its credential stored.
func TestA232ConcurrentWriterSurvivesACancelledLogin(t *testing.T) {
	for _, same := range []bool{false, true} {
		t.Run(fmt.Sprintf("sameAccess=%t", same), func(t *testing.T) {
			f := a232NewFixture(t, same, "")
			gate := a232NewGate()
			defer gate.open()
			a232HoldStaged(t, gate)
			first := f.start(t, 1)
			pr9Wait(t, gate.reached)
			if !f.cancel(t, first) {
				t.Fatal("cancel A refused")
			}
			second := f.start(t, 2)
			if done := f.h.waitStatus(second); done["status"] != "done" {
				t.Fatalf("B = %v, want done", done["status"])
			}
			f.h.waitWatcher(second)
			gate.open()
			f.h.waitWatcher(first)
			final, count := f.stored(t)
			if count != 1 || final != a232FakeLabel(2) {
				t.Errorf("stored=%q count=%d, want B's credential alone", final, count)
			}
		})
	}
}

// R3-3: done means persisted. A login whose final store write fails ends
// failed, never done without its credential.
func TestA232FailedFinalPersistenceIsNotDone(t *testing.T) {
	for _, rejectFirst := range []bool{false, true} {
		t.Run(fmt.Sprintf("rejectFirstWrite=%t", rejectFirst), func(t *testing.T) {
			f := a232NewFixture(t, true, "")
			store := &a232RejectRepairStore{a232Store: f.store}
			if rejectFirst {
				store.writes.Store(1)
			}
			f.handler.tokenStore = store
			gates := []*a232Gate{a232NewGate(), a232NewGate()}
			defer func() {
				for _, g := range gates {
					g.open()
				}
			}()
			a232HoldStaged(t, gates...)
			first := f.start(t, 1)
			pr9Wait(t, gates[0].reached)
			second := f.start(t, 2)
			pr9Wait(t, gates[1].reached)
			if !f.cancel(t, first) {
				t.Fatal("cancel A refused")
			}
			gates[0].open()
			f.h.waitWatcher(first)
			gates[1].open()
			f.h.waitWatcher(second)
			_, result, _ := f.h.status(second)
			label, count := f.stored(t)
			t.Logf("final status=%v error=%v stored=%q count=%d", result["status"], result["error"], label, count)
			if result["status"] == "done" && (count != 1 || label != a232FakeLabel(2)) {
				t.Error("done was published without its persisted credential")
			}
			if rejectFirst && (result["status"] != "failed" || result["error"] != "save_failed" || count != 0) {
				t.Error("a rejected write did not end the login failed/save_failed with nothing stored")
			}
		})
	}
}

// R3-4: a process killed after an accepted cancel leaves no credential.
func TestA232CrashWorker(t *testing.T) {
	if os.Getenv("A232_CRASH_CHILD") != "1" {
		t.Skip("subprocess helper")
	}
	f := a232NewFixture(t, false, os.Getenv("A232_FAKE_AUTH_DIR"))
	gate := a232NewGate()
	a232HoldStaged(t, gate)
	state := f.start(t, 1)
	pr9Wait(t, gate.reached)
	if !f.cancel(t, state) {
		t.Fatal("cancel not accepted")
	}
	_, status, _ := f.h.status(state)
	pipe := os.NewFile(3, "ready")
	fmt.Fprintf(pipe, "%s %s\n", state, status["status"])
	pipe.Close()
	select {}
}

func TestA232CrashAfterAcceptedCancelBeforeRecord(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "auths")
	r, w, e := os.Pipe()
	if e != nil {
		t.Fatal(e)
	}
	defer r.Close()
	executable, e := os.Executable()
	if e != nil {
		t.Fatal(e)
	}
	child := exec.Command(executable, "-test.run=^TestA232CrashWorker$", "-test.v")
	child.Env = append(os.Environ(), "A232_CRASH_CHILD=1", "A232_FAKE_AUTH_DIR="+dir)
	child.ExtraFiles = []*os.File{w}
	var output pr9Buffer
	child.Stdout = &output
	child.Stderr = &output
	if e = child.Start(); e != nil {
		t.Fatal(e)
	}
	w.Close()
	defer func() {
		if child.ProcessState == nil {
			child.Process.Kill()
			child.Wait()
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
	var line string
	select {
	case line = <-ready:
	case <-time.After(10 * time.Second):
		t.Fatal("fake child not ready")
	}
	parts := strings.Fields(line)
	if len(parts) != 2 || parts[1] != "cancelled" {
		t.Fatal("child did not acknowledge cancellation")
	}
	if e = child.Process.Kill(); e != nil {
		t.Fatal(e)
	}
	child.Wait()
	fresh := a232NewFixture(t, false, dir)
	code, body, _ := fresh.h.status(parts[0])
	auths, e := fresh.store.inner.List(context.Background())
	// Set the store's base directory exactly as a fresh handler would before reading.
	if e != nil {
		fresh.store.SetBaseDir(dir)
		auths, e = fresh.store.inner.List(context.Background())
	}
	if e != nil {
		t.Fatal(e)
	}
	t.Logf("after killed gateway: status HTTP=%d error=%v persisted-cancelled-auths=%d", code, body["error"], len(auths))
	if code != 404 {
		t.Error("restart retained login state")
	}
	if len(auths) != 0 {
		t.Error("a cancelled credential survives restart after accepted cancel")
	}
}

// A real FileTokenStore with a fake failure on B's second write (or first, when
// writes starts at 1).
type a232RejectRepairStore struct {
	*a232Store
	writes atomic.Int32
}

func (s *a232RejectRepairStore) Save(ctx context.Context, a *coreauth.Auth) (string, error) {
	if a232Label(a) == a232FakeLabel(2) && s.writes.Add(1) > 1 {
		return "", errors.New("A232_FAKE_SAVE_REJECTED")
	}
	return s.a232Store.Save(ctx, a)
}
