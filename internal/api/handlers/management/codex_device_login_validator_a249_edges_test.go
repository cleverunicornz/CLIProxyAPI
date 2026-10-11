// Probes of validator a249 (CLIProxyAPI #9 at 95274db0, round 4), kept as
// regression tests. Verbatim except TestA249RegistrationFailureStillClaimsInUse,
// adapted to the contract chosen for R4-2: done means stored; a failed runtime
// registration is logged and the stored credential is loaded at the latest
// when the gateway next loads its auth store.
package management

// Independent round-4 probes. Every provider, credential, code and account is fake.
// This file is injected with go -overlay; the product checkout stays untouched.
import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"weak"

	"github.com/gin-gonic/gin"
	backendstore "github.com/router-for-me/CLIProxyAPI/v8/internal/store"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
)

type a249Store struct {
	*a232Store
	before, after func(context.Context, *coreauth.Auth) error
	mu            sync.Mutex
	writes        []string
}

func (s *a249Store) Save(ctx context.Context, a *coreauth.Auth) (string, error) {
	if s.before != nil {
		if err := s.before(ctx, a); err != nil {
			return "", err
		}
	}
	path, err := s.a232Store.Save(ctx, a)
	if err == nil {
		s.mu.Lock()
		s.writes = append(s.writes, a232Label(a))
		s.mu.Unlock()
	}
	if err == nil && s.after != nil {
		err = s.after(ctx, a)
	}
	return path, err
}
func (s *a249Store) snapshot() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.writes...)
}
func a249Legacy(h *Handler, state string) map[string]any {
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/get-auth-status?state="+state, nil)
	h.GetAuthStatus(c)
	var result map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &result)
	return result
}
func a249StackContains(t *testing.T, needle string) {
	t.Helper()
	until := time.Now().Add(5 * time.Second)
	for {
		buf := make([]byte, 2<<20)
		n := runtime.Stack(buf, true)
		if strings.Contains(string(buf[:n]), needle) {
			return
		}
		if time.Now().After(until) {
			t.Fatal("goroutine did not reach " + needle)
		}
		runtime.Gosched()
	}
}
func a249Fixture(t *testing.T) *a232Fixture {
	a234IsolateStore(t)
	replaceOAuthSessionStoreForTest(t, newOAuthSessionStore(30*time.Minute))
	return a232NewFixture(t, false, "")
}

// Every cancellation subset/order is already covered by the a232 96-scenario
// matrix. Add the formerly untested storage/registration boundaries and record
// every store write, not just the final file, for both two and three logins.
func TestA249MultiLoginEveryBoundary(t *testing.T) {
	phases := []string{"pending", "prepare", "staged", "queued", "store-entry", "stored", "registration", "done"}
	for _, n := range []int{2, 3} {
		for target := 0; target < n; target++ {
			for _, phase := range phases {
				t.Run(fmt.Sprintf("n=%d/target=%d/%s", n, target+1, phase), func(t *testing.T) {
					f := a249Fixture(t)
					gates := make([]*a232Gate, n)
					for i := range gates {
						gates[i] = a232NewGate()
					}
					boundary := a232NewGate()
					defer func() {
						boundary.open()
						for _, g := range gates {
							g.open()
						}
					}()
					original := codexDeviceStagedHook
					codexDeviceStagedHook = func(_ context.Context, a *coreauth.Auth) {
						for i, g := range gates {
							if a232Label(a) == a232FakeLabel(i+1) {
								g.hold()
							}
						}
					}
					defer func() { codexDeviceStagedHook = original }()
					isTarget := func(a *coreauth.Auth) bool { return a232Label(a) == a232FakeLabel(target+1) }
					if phase == "prepare" {
						f.handler.postAuthHook = func(_ context.Context, a *coreauth.Auth) error {
							if isTarget(a) {
								boundary.hold()
							}
							return nil
						}
					}
					st := &a249Store{a232Store: f.store}
					f.handler.tokenStore = st
					if phase == "store-entry" {
						st.before = func(_ context.Context, a *coreauth.Auth) error {
							if isTarget(a) {
								boundary.hold()
							}
							return nil
						}
					}
					if phase == "stored" {
						st.after = func(_ context.Context, a *coreauth.Auth) error {
							if isTarget(a) {
								boundary.hold()
							}
							return nil
						}
					}
					if phase == "registration" {
						f.handler.postAuthPersistHook = func(_ context.Context, a *coreauth.Auth) error {
							if isTarget(a) {
								boundary.hold()
							}
							return nil
						}
					}
					states := make([]string, n)
					for i := range states {
						states[i] = f.h.start()["state"].(string)
						if i == target && phase == "pending" {
							continue
						}
						f.h.fake.decide(fmt.Sprintf("CODE-%04d", i+1), "approve")
						if i == target && phase == "prepare" {
							pr9Wait(t, boundary.reached)
						} else {
							pr9Wait(t, gates[i].reached)
						}
					}
					locked := false
					defer func() {
						if locked {
							codexDeviceCommitMu.Unlock()
						}
					}()
					switch phase {
					case "queued":
						codexDeviceCommitMu.Lock()
						locked = true
						gates[target].open()
						a249StackContains(t, "(*Handler).commitCodexDeviceLogin(")
					case "store-entry", "stored", "registration":
						gates[target].open()
						pr9Wait(t, boundary.reached)
					case "done":
						gates[target].open()
						f.h.waitWatcher(states[target])
					}
					accepted := f.cancel(t, states[target])
					want := phase == "pending" || phase == "prepare" || phase == "staged" || phase == "queued"
					if accepted != want {
						t.Errorf("cancel accepted=%t want=%t", accepted, want)
					}
					boundary.open()
					gates[target].open()
					if locked {
						codexDeviceCommitMu.Unlock()
						locked = false
					}
					f.h.waitWatcher(states[target])
					last := ""
					if !want {
						last = a232FakeLabel(target + 1)
					}
					for i := range states {
						if i != target {
							gates[i].open()
							f.h.waitWatcher(states[i])
							last = a232FakeLabel(i + 1)
						}
					}
					actual, count := f.stored(t)
					writes := st.snapshot()
					if count != 1 || actual != last {
						t.Error("last committing login does not own stored credential")
					}
					for _, label := range writes {
						if accepted && label == a232FakeLabel(target+1) {
							t.Error("accepted cancellation was ever stored")
						}
					}
					t.Logf("accepted=%t writes=%d final-owner-matches=%t", accepted, len(writes), actual == last)
				})
			}
		}
	}
}

// Race the actual mutex-protected transition, with ordered controls for both
// sides. No injected change to the state machine or credential comparison.
func TestA249CancelExactlyAtCommit(t *testing.T) {
	f := a249Fixture(t)
	st := &a249Store{a232Store: f.store}
	f.handler.tokenStore = st
	wins := 0
	losses := 0
	for i := 0; i < 128; i++ {
		state := fmt.Sprintf("a249-transition-%d", i)
		RegisterOAuthSession(state, "codex")
		codexDeviceLogins.add(state, &codexDeviceLoginRecord{status: codexDeviceStatusSaving, expiresAt: time.Now().Add(time.Hour)})
		a := &coreauth.Auth{ID: fmt.Sprintf("fake-%d.json", i), FileName: fmt.Sprintf("fake-%d.json", i), Provider: "codex", Metadata: map[string]any{"type": "codex", "email": "fake@example.test", "refresh_token": "A249_FAKE"}}
		prepared := &preparedTokenRecord{record: a}
		start := make(chan struct{})
		done := make(chan struct{})
		answer := make(chan bool, 1)
		go func() { <-start; f.handler.commitCodexDeviceLogin(context.Background(), state, prepared); close(done) }()
		go func() { <-start; b, _ := codexDeviceLogins.cancel(state); answer <- b }()
		close(start)
		accepted := <-answer
		<-done
		record, _ := codexDeviceLogins.get(state)
		_, err := os.Stat(filepath.Join(f.h.authDir, a.FileName))
		stored := err == nil
		if accepted {
			wins++
			if stored || record.status != "cancelled" {
				t.Fatal("cancel and commit both succeeded")
			}
		} else {
			losses++
			if !stored || record.status != "done" {
				t.Fatal("losing cancel lost commit")
			}
		}
	}
	t.Logf("128 transition races: cancel-wins=%d commit-wins=%d", wins, losses)
}

func TestA249StoreFailureAndHang(t *testing.T) {
	for _, fail := range []bool{false, true} {
		t.Run(fmt.Sprintf("fail=%t", fail), func(t *testing.T) {
			f := a249Fixture(t)
			gate := a232NewGate()
			defer gate.open()
			var runtimeCalls atomic.Int32
			f.handler.postAuthPersistHook = func(context.Context, *coreauth.Auth) error { runtimeCalls.Add(1); return nil }
			st := &a249Store{a232Store: f.store, before: func(ctx context.Context, _ *coreauth.Auth) error {
				gate.hold()
				if fail {
					return errors.New("A249_FAKE_WRITE_REFUSED")
				}
				return nil
			}}
			f.handler.tokenStore = st
			state := f.start(t, 1)
			pr9Wait(t, gate.reached)
			// Deterministically advance only the device clock beyond expiry while Save is held.
			codexDeviceLogins.mu.Lock()
			expires := codexDeviceLogins.records[state].expiresAt
			codexDeviceLogins.now = func() time.Time { return expires.Add(time.Hour) }
			codexDeviceLogins.mu.Unlock()
			_, pending, _ := f.h.status(state)
			accepted := f.cancel(t, state)
			legacy := a249Legacy(f.handler, state)
			if pending["status"] != "pending" || accepted || legacy["status"] != "wait" {
				t.Error("in-progress store does not retain committing contract")
			}
			gate.open()
			f.h.waitWatcher(state)
			_, final, _ := f.h.status(state)
			_, count := f.stored(t)
			if fail {
				if final["status"] != "failed" || final["error"] != "save_failed" || count != 0 || runtimeCalls.Load() != 0 {
					t.Error("refused write not represented as failed")
				}
			} else {
				if final["status"] != "done" || count != 1 || runtimeCalls.Load() != 1 {
					t.Error("successful write not done")
				}
			}
			t.Logf("during-hang=%v cancel=%t legacy=%v final=%v stored=%d", pending["status"], accepted, legacy["status"], final["status"], count)
		})
	}
}

func TestA249RegistrationFailureStillClaimsInUse(t *testing.T) {
	for _, reject := range []bool{false, true} {
		t.Run(fmt.Sprintf("reject=%t", reject), func(t *testing.T) {
			f := a249Fixture(t)
			var called atomic.Int32
			manager := coreauth.NewManager(nil, nil, nil)
			var id string
			f.handler.postAuthPersistHook = func(ctx context.Context, a *coreauth.Auth) error {
				called.Add(1)
				id = a.ID
				if reject {
					return errors.New("A249_FAKE_RUNTIME_REJECTED")
				}
				_, err := manager.Register(ctx, a)
				return err
			}
			state := f.start(t, 1)
			f.h.waitWatcher(state)
			_, status, _ := f.h.status(state)
			_, count := f.stored(t)
			_, registered := manager.GetByID(id)
			t.Logf("status=%v files=%d registration-attempts=%d registered=%t legacy=%v", status["status"], count, called.Load(), registered, a249Legacy(f.handler, state)["status"])
			if status["status"] != "done" || count != 1 {
				t.Fatal("stored outcome changed")
			}
			if registered == reject {
				t.Error("registration outcome does not follow the registration hook")
			}
			// Revision 4: done means stored. A stored credential whose runtime
			// registration failed is loaded the next time the gateway loads its
			// auth store, as a fresh manager loading the same store does here.
			reloaded := coreauth.NewManager(f.handler.tokenStoreWithBaseDir(), nil, nil)
			if errLoad := reloaded.Load(context.Background()); errLoad != nil {
				t.Fatalf("load the store: %v", errLoad)
			}
			loaded := false
			for _, a := range reloaded.List() {
				loaded = loaded || a232Label(a) == a232FakeLabel(1)
			}
			if !loaded {
				t.Error("the done credential is not loaded from the store")
			}
			if legacy := a249Legacy(f.handler, state); legacy["status"] != "ok" {
				t.Errorf("legacy status = %v, want ok", legacy)
			}
		})
	}
}

// A real supported backend writes its local mirror before a remote refusal.
// Only the remote S3 protocol is fake; no external endpoint is contacted.
func TestA249ObjectStoreRefusalKeepsLocalCredential(t *testing.T) {
	f := a249Fixture(t)
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		w.Header().Set("Content-Type", "application/xml")
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`<Error><Code>AccessDenied</Code><Message>A249_FAKE_REFUSAL</Message></Error>`))
	}))
	defer server.Close()
	backend, err := backendstore.NewObjectTokenStore(backendstore.ObjectStoreConfig{Endpoint: strings.TrimPrefix(server.URL, "http://"), Bucket: "a249-fake", AccessKey: "A249_FAKE_KEY", SecretKey: "A249_FAKE_SECRET", Region: "us-east-1", LocalRoot: t.TempDir(), PathStyle: true})
	if err != nil {
		t.Fatal(err)
	}
	f.handler.tokenStore = backend
	f.handler.cfg.AuthDir = backend.AuthDir()
	state := f.start(t, 1)
	f.h.waitWatcher(state)
	_, status, _ := f.h.status(state)
	auths, err := backend.List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("status=%v error=%v local-auths=%d remote-requests=%d", status["status"], status["error"], len(auths), requests.Load())
	if status["status"] != "failed" || status["error"] != "save_failed" || requests.Load() == 0 {
		t.Fatal("fake remote refusal was not exercised")
	}
	if len(auths) != 0 {
		t.Error("a refused store left an admitted local credential")
	}
}

// Hold one actual store write. B has finished preparing and is parked at the
// product's mutex, with a weak pointer observing its otherwise unreferenced
// credential. Cancellation should release B independently of A's storage.
func TestA249CancelledQueuedCredentialIsReleased(t *testing.T) {
	f := a249Fixture(t)
	storeGate := a232NewGate()
	defer storeGate.open()
	f.handler.tokenStore = &a249Store{a232Store: f.store, before: func(_ context.Context, a *coreauth.Auth) error {
		if a232Label(a) == a232FakeLabel(1) {
			storeGate.hold()
		}
		return nil
	}}
	captured := make(chan weak.Pointer[coreauth.Auth], 1)
	orig := codexDeviceStagedHook
	codexDeviceStagedHook = func(_ context.Context, a *coreauth.Auth) {
		if a232Label(a) == a232FakeLabel(2) {
			a.Metadata["a249_fake_payload"] = make([]byte, 8<<20)
			captured <- weak.Make(a)
		}
	}
	defer func() { codexDeviceStagedHook = orig }()
	first := f.start(t, 1)
	pr9Wait(t, storeGate.reached)
	second := f.start(t, 2)
	ptr := <-captured
	// A is at Save and B has no other blocking test hook. Wait for two commit
	// frames to prove B is waiting in production rather than still in our hook.
	until := time.Now().Add(5 * time.Second)
	for {
		buf := make([]byte, 2<<20)
		n := runtime.Stack(buf, true)
		if strings.Count(string(buf[:n]), "(*Handler).commitCodexDeviceLogin(") >= 2 {
			break
		}
		if time.Now().After(until) {
			t.Fatal("B did not reach the commit lock")
		}
		runtime.Gosched()
	}
	if !f.cancel(t, second) {
		t.Fatal("queued cancel refused")
	}
	runtime.GC()
	runtime.GC()
	retained := ptr.Value() != nil
	exited := false
	select {
	case <-codexDeviceLogins.watcherDone(second):
		exited = true
	default:
	}
	_, status, _ := f.h.status(second)
	t.Logf("cancelled=%v watcher-exited=%t credential-retained=%t retained-payload-bytes=%d", status["status"], exited, retained, 8<<20)
	if retained || !exited {
		t.Error("accepted cancel retains its staged credential behind another login's hung store")
	}
	storeGate.open()
	f.h.waitWatcher(first)
	f.h.waitWatcher(second)
	runtime.GC()
	runtime.GC()
	if ptr.Value() != nil {
		t.Error("credential remains even after blocked commit finishes")
	}
}

// Pending login memory is measured by heap/goroutine deltas, not hard-coded
// platform thresholds. Check terminal records clear display data and their
// goroutines exit; retention is then expired by a controlled clock.
func TestA249PendingMemoryAndTerminalRelease(t *testing.T) {
	for _, outcome := range []string{"cancel", "expiry", "failure"} {
		t.Run(outcome, func(t *testing.T) {
			f := a249Fixture(t)
			const count = 24
			runtime.GC()
			var before, held, after runtime.MemStats
			runtime.ReadMemStats(&before)
			g0 := runtime.NumGoroutine()
			states := make([]string, count)
			for i := range states {
				states[i] = f.h.start()["state"].(string)
			}
			runtime.GC()
			runtime.ReadMemStats(&held)
			g1 := runtime.NumGoroutine()
			if outcome == "expiry" {
				codexDeviceLogins.mu.Lock()
				late := time.Now().Add(time.Hour)
				codexDeviceLogins.now = func() time.Time { return late }
				codexDeviceLogins.mu.Unlock()
			}
			for i, state := range states {
				switch outcome {
				case "cancel":
					f.cancel(t, state)
				case "expiry":
					f.h.status(state)
				case "failure":
					f.h.fake.decide(fmt.Sprintf("CODE-%04d", i+1), "deny")
				}
			}
			for _, state := range states {
				f.h.waitWatcher(state)
				r, _ := codexDeviceLogins.get(state)
				if r.userCode != "" || r.verificationURI != "" {
					t.Error("finished record retained display code")
				}
			}
			runtime.GC()
			runtime.ReadMemStats(&after)
			g2 := runtime.NumGoroutine()
			t.Logf("N=%d heap-pending-delta=%d bytes-per-pending=%.1f heap-terminal-delta=%d goroutines=%d/%d/%d", count, int64(held.HeapAlloc)-int64(before.HeapAlloc), float64(int64(held.HeapAlloc)-int64(before.HeapAlloc))/count, int64(after.HeapAlloc)-int64(before.HeapAlloc), g0, g1, g2)
			codexDeviceLogins.mu.Lock()
			late := codexDeviceLogins.now().Add(codexDeviceLoginRetention + time.Nanosecond)
			codexDeviceLogins.now = func() time.Time { return late }
			codexDeviceLogins.purgeLocked()
			left := len(codexDeviceLogins.records)
			codexDeviceLogins.mu.Unlock()
			if left != 0 {
				t.Errorf("retention left %d records", left)
			}
		})
	}
}

func TestA249PreparedCredentialReleasedOnTerminal(t *testing.T) {
	for _, outcome := range []string{"cancel", "prepare-failure", "store-failure"} {
		t.Run(outcome, func(t *testing.T) {
			f := a249Fixture(t)
			gate := a232NewGate()
			defer gate.open()
			captured := make(chan weak.Pointer[coreauth.Auth], 1)
			f.handler.postAuthHook = func(_ context.Context, a *coreauth.Auth) error {
				a.Metadata["a249_fake_payload"] = make([]byte, 8<<20)
				captured <- weak.Make(a)
				gate.hold()
				if outcome == "prepare-failure" {
					return errors.New("A249_FAKE_PREPARE_FAILURE")
				}
				return nil
			}
			if outcome == "store-failure" {
				f.handler.tokenStore = &a249Store{a232Store: f.store, before: func(context.Context, *coreauth.Auth) error { return errors.New("A249_FAKE_STORE_FAILURE") }}
			}
			state := f.start(t, 1)
			ptr := <-captured
			pr9Wait(t, gate.reached)
			if outcome == "cancel" && !f.cancel(t, state) {
				t.Fatal("prepare cancel refused")
			}
			gate.open()
			f.h.waitWatcher(state)
			runtime.GC()
			runtime.GC()
			_, status, _ := f.h.status(state)
			retained := ptr.Value() != nil
			t.Logf("terminal=%v credential-retained=%t", status["status"], retained)
			if retained {
				t.Error("terminal credential remains reachable")
			}
		})
	}
}

func TestA249CrashWorker(t *testing.T) {
	phase := os.Getenv("A249_FAKE_CRASH_PHASE")
	if phase == "" {
		t.Skip("subprocess helper")
	}
	f := a232NewFixture(t, false, os.Getenv("A249_FAKE_AUTH_DIR"))
	gate := a232NewGate()
	state := ""
	switch phase {
	case "prepare":
		f.handler.postAuthHook = func(context.Context, *coreauth.Auth) error { gate.hold(); return nil }
	case "staged":
		codexDeviceStagedHook = func(context.Context, *coreauth.Auth) { gate.hold() }
	case "queued":
		codexDeviceCommitMu.Lock()
		codexDeviceStagedHook = func(context.Context, *coreauth.Auth) { gate.hold() }
	case "store-entry":
		f.handler.tokenStore = &a249Store{a232Store: f.store, before: func(context.Context, *coreauth.Auth) error { gate.hold(); return nil }}
	case "store-accepted":
		f.handler.tokenStore = &a249Store{a232Store: f.store, after: func(context.Context, *coreauth.Auth) error { gate.hold(); return nil }}
	case "registration":
		f.handler.postAuthPersistHook = func(context.Context, *coreauth.Auth) error { gate.hold(); return nil }
	}
	state = f.h.start()["state"].(string)
	if phase != "pending" {
		f.h.fake.decide("CODE-0001", "approve")
		if phase == "done" {
			f.h.waitWatcher(state)
		} else {
			pr9Wait(t, gate.reached)
		}
	}
	if phase == "queued" {
		gate.open()
		a249StackContains(t, "(*Handler).commitCodexDeviceLogin(")
	}
	_, status, _ := f.h.status(state)
	pipe := os.NewFile(3, "ready")
	_, _ = fmt.Fprintf(pipe, "%s %v\n", state, status["status"])
	_ = pipe.Close()
	select {}
}

func TestA249KillAtEachCommitStep(t *testing.T) {
	for _, phase := range []string{"pending", "prepare", "staged", "queued", "store-entry", "store-accepted", "registration", "done"} {
		t.Run(phase, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "auths")
			r, w, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			defer r.Close()
			exe, err := os.Executable()
			if err != nil {
				t.Fatal(err)
			}
			child := exec.Command(exe, "-test.run=^TestA249CrashWorker$", "-test.v")
			child.Env = append(os.Environ(), "A249_FAKE_CRASH_PHASE="+phase, "A249_FAKE_AUTH_DIR="+dir)
			child.ExtraFiles = []*os.File{w}
			var output pr9Buffer
			child.Stdout = &output
			child.Stderr = &output
			if err = child.Start(); err != nil {
				t.Fatal(err)
			}
			_ = w.Close()
			defer func() {
				if child.ProcessState == nil {
					_ = child.Process.Kill()
					_ = child.Wait()
				}
			}()
			ready := make(chan string, 1)
			go func() {
				s := bufio.NewScanner(r)
				if s.Scan() {
					ready <- s.Text()
				} else {
					ready <- ""
				}
			}()
			var line string
			select {
			case line = <-ready:
			case <-time.After(10 * time.Second):
				t.Fatal("child failed to reach commit step")
			}
			fields := strings.Fields(line)
			if len(fields) != 2 {
				t.Fatalf("child did not report readiness: %s", output.String())
			}
			if err = child.Process.Kill(); err != nil {
				t.Fatal(err)
			}
			_ = child.Wait()
			a234IsolateStore(t)
			fresh := a232NewFixture(t, false, dir)
			code, status, _ := fresh.h.status(fields[0])
			accepted := fresh.cancel(t, fields[0])
			_, count := fresh.stored(t)
			want := 0
			if phase == "store-accepted" || phase == "registration" || phase == "done" {
				want = 1
			}
			t.Logf("killed-at=%s before-status=%s restart-http=%d cancel=%t auths=%d", phase, fields[1], code, accepted, count)
			if code != 404 || status["error"] != "unknown_state" || accepted || count != want {
				t.Error("restart did not match contract")
			}
		})
	}
}
