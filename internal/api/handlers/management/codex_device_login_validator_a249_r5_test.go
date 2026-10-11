// Probes of validator a249, round 5 (CLIProxyAPI #9 at 3cd6d079), kept as
// regression tests. Verbatim except, after the operator's round-6 decisions,
// TestA249R5RemoteStoreBlocksOtherAccount asserts the qualified contract (a
// store's own pre-existing lock serializes its writes, so another account's
// login waits inside storage, reads pending and refuses a cancel, then
// completes), and TestA249R5RemoteAcceptedButMirrorPublicationFailed requires
// done once the store of record accepted the credential.
package management

// Round-5 independent probes; all account names, credentials and providers are fake.
import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	backendstore "github.com/router-for-me/CLIProxyAPI/v8/internal/store"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
)

type a249R5Store struct {
	mu     sync.Mutex
	writes []*coreauth.Auth
	before func(context.Context, *coreauth.Auth) error
	after  func(context.Context, *coreauth.Auth) error
}

func (s *a249R5Store) Save(ctx context.Context, a *coreauth.Auth) (string, error) {
	if s.before != nil {
		if err := s.before(ctx, a); err != nil {
			return "", err
		}
	}
	s.mu.Lock()
	s.writes = append(s.writes, a.Clone())
	s.mu.Unlock()
	if s.after != nil {
		if err := s.after(ctx, a); err != nil {
			return "", err
		}
	}
	return "", nil
}
func (s *a249R5Store) List(context.Context) ([]*coreauth.Auth, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]*coreauth.Auth(nil), s.writes...), nil
}
func (s *a249R5Store) Delete(context.Context, string) error { return nil }
func a249R5Add(state, account, label string) (*preparedTokenRecord, context.Context) {
	ctx, stop := context.WithCancel(context.Background())
	codexDeviceLogins.add(state, &codexDeviceLoginRecord{status: codexDeviceStatusSaving, expiresAt: time.Now().Add(time.Hour), stop: stop})
	a := &coreauth.Auth{ID: account, FileName: account, Provider: "codex", Metadata: map[string]any{"email": "r5-fake@example.test", "type": "codex", "refresh_token": label}}
	return &preparedTokenRecord{record: a}, ctx
}
func a249R5Join(t *testing.T, ch <-chan struct{}) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(5 * time.Second):
		t.Fatal("commit did not exit")
	}
}
func a249R5Until(t *testing.T, condition func() bool) {
	t.Helper()
	end := time.Now().Add(5 * time.Second)
	for !condition() {
		if time.Now().After(end) {
			t.Fatal("synchronization condition not reached")
		}
		runtime.Gosched()
	}
}
func a249R5StoreLockWait(kind string) bool {
	buf := make([]byte, 2<<20)
	n := runtime.Stack(buf, true)
	for _, g := range strings.Split(string(buf[:n]), "\n\n") {
		if strings.Contains(g, "(*"+kind+").Save(") && (strings.Contains(g, "sync.Mutex.Lock") || strings.Contains(g, "(*Mutex).lockSlow")) {
			return true
		}
	}
	return false
}

// Exercise queue admission with real run-context cancellation. The retained
// direct-commit probe has no cancellable context and tests the state CAS only.
func TestA249R5QueueCancellationBoundaries(t *testing.T) {
	phases := []string{"before-call", "queued", "release-race", "admitted-before-transition", "store", "registration", "done", "store-refused"}
	for _, phase := range phases {
		t.Run(phase, func(t *testing.T) {
			repeats := 1
			if phase == "release-race" || phase == "admitted-before-transition" {
				repeats = 64
			}
			for i := 0; i < repeats; i++ {
				f := a249Fixture(t)
				state := fmt.Sprintf("r5-boundary-%s-%d", phase, i)
				account := state + ".json"
				prepared, ctx := a249R5Add(state, account, "R5_FAKE")
				gate := a232NewGate()
				store := &a249R5Store{}
				f.handler.tokenStore = store
				if phase == "store" || phase == "store-refused" {
					store.before = func(context.Context, *coreauth.Auth) error {
						gate.hold()
						if phase == "store-refused" {
							return errors.New("R5_FAKE_REFUSAL")
						}
						return nil
					}
				}
				if phase == "registration" {
					f.handler.postAuthPersistHook = func(context.Context, *coreauth.Auth) error { gate.hold(); return nil }
				}
				slot := codexDeviceCommitSlot(account)
				occupied := phase == "queued" || phase == "release-race"
				if occupied {
					slot <- struct{}{}
				}
				if phase == "before-call" {
					codexDeviceLogins.cancel(state)
				}
				locked := phase == "admitted-before-transition"
				if locked {
					codexDeviceLogins.mu.Lock()
				}
				done := make(chan struct{})
				go func() { f.handler.commitCodexDeviceLogin(context.Background(), ctx, state, prepared); close(done) }()
				var accepted bool
				switch phase {
				case "before-call":
					accepted = true
				case "queued":
					a249StackContains(t, "(*Handler).commitCodexDeviceLogin(")
					accepted, _ = codexDeviceLogins.cancel(state)
					a249R5Join(t, done)
					<-slot
					occupied = false
				case "release-race":
					a249StackContains(t, "(*Handler).commitCodexDeviceLogin(")
					start := make(chan struct{})
					answer := make(chan bool, 1)
					released := make(chan struct{})
					go func() { <-start; b, _ := codexDeviceLogins.cancel(state); answer <- b }()
					go func() { <-start; <-slot; close(released) }()
					close(start)
					accepted = <-answer
					<-released
					occupied = false
				case "admitted-before-transition":
					a249R5Until(t, func() bool { return len(slot) == 1 })
					answer := make(chan bool, 1)
					go func() { b, _ := codexDeviceLogins.cancel(state); answer <- b }()
					codexDeviceLogins.mu.Unlock()
					locked = false
					accepted = <-answer
				case "store", "store-refused", "registration":
					pr9Wait(t, gate.reached)
					accepted, _ = codexDeviceLogins.cancel(state)
				case "done":
					a249R5Join(t, done)
					accepted, _ = codexDeviceLogins.cancel(state)
				}
				gate.open()
				a249R5Join(t, done)
				if occupied {
					<-slot
				}
				if locked {
					codexDeviceLogins.mu.Unlock()
				}
				writes, _ := store.List(context.Background())
				record, _ := codexDeviceLogins.get(state)
				if accepted && (record.status != "cancelled" || len(writes) != 0) {
					t.Fatalf("cancel succeeded together with persistence: status=%s writes=%d", record.status, len(writes))
				}
				if !accepted && phase != "store-refused" && (record.status != "done" || len(writes) != 1) {
					t.Fatalf("commit winner missing: status=%s writes=%d", record.status, len(writes))
				}
				if phase == "store-refused" && (accepted || record.status != "failed" || record.errorCode != "save_failed" || len(writes) != 0) {
					t.Fatal("refusal outcome incorrect")
				}
				if len(slot) != 0 {
					t.Fatal("slot left occupied")
				}
				// Reuse the same account immediately after every outcome.
				store.before = nil
				f.handler.postAuthPersistHook = nil
				next, nextCtx := a249R5Add(state+"-again", account, "R5_FAKE_NEXT")
				f.handler.commitCodexDeviceLogin(context.Background(), nextCtx, state+"-again", next)
				if r, _ := codexDeviceLogins.get(state + "-again"); r.status != "done" {
					t.Fatal("same account cannot commit again")
				}
			}
			t.Logf("phase=%s iterations=%d plus same-account reuse", phase, repeats)
		})
	}
}

// Hold the first commit of every account simultaneously. A same-account
// follower must stay queued, cancelled followers must exit, and uncancelled
// followers must commit after their own predecessor. No FIFO assertion is
// added beyond one active commit per account and last successful commit wins.
func TestA249R5ManyAccountsAndSameAccountTwice(t *testing.T) {
	f := a249Fixture(t)
	const n = 32
	entered := make(chan string, n)
	release := make(chan struct{})
	var once sync.Once
	defer once.Do(func() { close(release) })
	var mu sync.Mutex
	active := map[string]int{}
	peak := map[string]int{}
	var simultaneous, maxSim int
	store := &a249R5Store{}
	store.before = func(_ context.Context, a *coreauth.Auth) error {
		mu.Lock()
		active[a.FileName]++
		if active[a.FileName] > peak[a.FileName] {
			peak[a.FileName] = active[a.FileName]
		}
		simultaneous++
		if simultaneous > maxSim {
			maxSim = simultaneous
		}
		mu.Unlock()
		if a.Metadata["refresh_token"] == "R5_FAKE_FIRST" {
			entered <- a.FileName
			<-release
		}
		return nil
	}
	store.after = func(_ context.Context, a *coreauth.Auth) error {
		mu.Lock()
		active[a.FileName]--
		simultaneous--
		mu.Unlock()
		return nil
	}
	f.handler.tokenStore = store
	firstDone := make([]chan struct{}, n)
	secondDone := make([]chan struct{}, n)
	states := make([]string, n)
	for i := 0; i < n; i++ {
		name := fmt.Sprintf("r5-many-%d.json", i)
		state := fmt.Sprintf("r5-many-first-%d", i)
		p, c := a249R5Add(state, name, "R5_FAKE_FIRST")
		firstDone[i] = make(chan struct{})
		go func(i int) { f.handler.commitCodexDeviceLogin(context.Background(), c, state, p); close(firstDone[i]) }(i)
	}
	for i := 0; i < n; i++ {
		select {
		case <-entered:
		case <-time.After(5 * time.Second):
			t.Fatal("different account commits did not enter concurrently")
		}
	}
	for i := 0; i < n; i++ {
		name := fmt.Sprintf("r5-many-%d.json", i)
		states[i] = fmt.Sprintf("r5-many-second-%d", i)
		p, c := a249R5Add(states[i], name, "R5_FAKE_SECOND")
		secondDone[i] = make(chan struct{})
		go func(i int) {
			f.handler.commitCodexDeviceLogin(context.Background(), c, states[i], p)
			close(secondDone[i])
		}(i)
	}
	for i, state := range states {
		if i%2 == 0 {
			if accepted, _ := codexDeviceLogins.cancel(state); !accepted {
				t.Fatal("queued cancellation lost")
			}
			a249R5Join(t, secondDone[i])
		}
	}
	rows, _ := store.List(context.Background())
	if len(rows) != 0 {
		t.Fatal("a same-account follower overtook its blocked predecessor")
	}
	once.Do(func() { close(release) })
	for i := range firstDone {
		a249R5Join(t, firstDone[i])
		a249R5Join(t, secondDone[i])
	}
	rows, _ = store.List(context.Background())
	last := map[string]string{}
	count := map[string]int{}
	for _, a := range rows {
		last[a.FileName] = a.Metadata["refresh_token"].(string)
		count[a.FileName]++
	}
	for i := 0; i < n; i++ {
		name := fmt.Sprintf("r5-many-%d.json", i)
		want := "R5_FAKE_SECOND"
		wantCount := 2
		if i%2 == 0 {
			want = "R5_FAKE_FIRST"
			wantCount = 1
		}
		if last[name] != want || count[name] != wantCount || peak[name] != 1 || len(codexDeviceCommitSlot(name)) != 0 {
			t.Fatalf("account=%d writes=%d peak=%d correct-last=%t", i, count[name], peak[name], last[name] == want)
		}
	}
	t.Logf("accounts=%d parallel-first-commits=%d writes=%d cancelled-followers=%d", n, maxSim, len(rows), n/2)
}

func TestA249R5LegacyRetentionUsesOnlyDeviceRecord(t *testing.T) {
	f := a249Fixture(t)
	state := f.start(t, 1)
	f.h.waitWatcher(state)
	if _, _, ok := GetOAuthSession(state); ok {
		t.Fatal("device login retains a legacy session")
	}
	codexDeviceLogins.mu.Lock()
	finished := codexDeviceLogins.records[state].finishedAt
	codexDeviceLogins.mu.Unlock()
	for _, step := range []struct {
		after time.Duration
		want  string
	}{{2 * time.Minute, "ok"}, {15*time.Minute - time.Nanosecond, "ok"}, {15*time.Minute + time.Nanosecond, "error"}} {
		codexDeviceLogins.mu.Lock()
		now := finished.Add(step.after)
		codexDeviceLogins.now = func() time.Time { return now }
		codexDeviceLogins.mu.Unlock()
		result := a249Legacy(f.handler, state)
		if result["status"] != step.want {
			t.Fatalf("at %v legacy=%v want=%s", step.after, result, step.want)
		}
	}
}

// Use the real object store rather than holding outside its Save mutex. A
// fake S3 PUT for account A blocks the store while account B tries to save.
func TestA249R5RemoteStoreBlocksOtherAccount(t *testing.T) {
	f := a249Fixture(t)
	pr9UseClient(f.h.fake.client(), 0)
	gate := a232NewGate()
	defer gate.open()
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if requests.Add(1) == 1 {
			gate.hold()
		}
		w.Header().Set("ETag", `"r5-fake-etag"`)
		w.WriteHeader(http.StatusOK)
	}))
	defer func() { gate.open(); server.Close() }()
	backend, err := backendstore.NewObjectTokenStore(backendstore.ObjectStoreConfig{Endpoint: strings.TrimPrefix(server.URL, "http://"), Bucket: "r5-fake", AccessKey: "R5_FAKE_KEY", SecretKey: "R5_FAKE_SECRET", Region: "us-east-1", LocalRoot: t.TempDir(), PathStyle: true})
	if err != nil {
		t.Fatal(err)
	}
	f.handler.tokenStore = backend
	f.handler.cfg.AuthDir = backend.AuthDir()
	first := f.h.start()["state"].(string)
	f.h.fake.decide("CODE-0001", "approve")
	pr9Wait(t, gate.reached)
	second := f.h.start()["state"].(string)
	f.h.fake.decide("CODE-0002", "approve")
	// Accept successful independent completion as the positive control, or
	// demonstrate the precise mutex wait without relying on a latency threshold.
	finished := false
	a249R5Until(t, func() bool {
		select {
		case <-codexDeviceLogins.watcherDone(second):
			finished = true
			return true
		default:
			return a249R5StoreLockWait("ObjectTokenStore")
		}
	})
	_, status, _ := f.h.status(second)
	cancel := f.cancel(t, second)
	t.Logf("distinct-account B: status=%v cancel=%t finished=%t remote-requests=%d while A's PUT is held", status["status"], cancel, finished, requests.Load())
	// Revision 5: the device-login queue lets B through, but the object store's
	// own lock serializes its writes, so B waits inside storage: pending, and a
	// cancel loses because its commit began.
	if finished || status["status"] != "pending" || cancel {
		t.Error("another account's commit did not wait inside the store as the contract states")
	}
	gate.open()
	f.h.waitWatcher(first)
	f.h.waitWatcher(second)
	if requests.Load() != 2 {
		t.Errorf("after release remote requests=%d", requests.Load())
	}
	for _, state := range []string{first, second} {
		if _, final, raw := f.h.status(state); final["status"] != "done" {
			t.Errorf("after release %s = %s, want done", state, raw)
		}
	}
}

// Observe publication failure after remote acceptance through the real
// endpoint. The fake remote removes the staging file immediately before
// acknowledging its write; the previous local credential stays unchanged.
func TestA249R5RemoteAcceptedButMirrorPublicationFailed(t *testing.T) {
	f := a249Fixture(t)
	var uploads atomic.Int32
	var remoteAccepted atomic.Bool
	var backend *backendstore.ObjectTokenStore
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		uploads.Add(1)
		var reader io.Reader = r.Body
		if strings.Contains(r.Header.Get("Content-Encoding"), "aws-chunked") || strings.HasPrefix(r.Header.Get("X-Amz-Content-Sha256"), "STREAMING-") {
			reader = httputil.NewChunkedReader(r.Body)
		}
		var body map[string]any
		if err := json.NewDecoder(reader).Decode(&body); err != nil {
			t.Errorf("fake upload JSON: %v", err)
		}
		remoteAccepted.Store(body["type"] == "codex")
		matches, _ := filepath.Glob(filepath.Join(backend.AuthDir(), "*.tmp"))
		for _, p := range matches {
			_ = os.Remove(p)
		}
		w.Header().Set("ETag", `"r5-fake-etag"`)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	var err error
	backend, err = backendstore.NewObjectTokenStore(backendstore.ObjectStoreConfig{Endpoint: strings.TrimPrefix(server.URL, "http://"), Bucket: "r5-fake", AccessKey: "R5_FAKE_KEY", SecretKey: "R5_FAKE_SECRET", Region: "us-east-1", LocalRoot: t.TempDir(), PathStyle: true})
	if err != nil {
		t.Fatal(err)
	}
	f.handler.tokenStore = backend
	f.handler.cfg.AuthDir = backend.AuthDir()
	state := f.start(t, 1)
	f.h.waitWatcher(state)
	_, status, _ := f.h.status(state)
	rows, err := backend.List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("remote-accepted=%t uploads=%d status=%v error=%v local-auths=%d", remoteAccepted.Load(), uploads.Load(), status["status"], status["error"], len(rows))
	if !remoteAccepted.Load() || uploads.Load() != 1 {
		t.Fatal("remote acceptance was not exercised")
	}
	// Revision 5: the store of record accepted the credential, so it is
	// stored and the login is done; the stale mirror is reconciled by the next
	// load.
	if status["status"] != "done" {
		t.Error("the remote accepted the credential, but the login did not end done")
	}
	if legacy := a249Legacy(f.handler, state); legacy["status"] != "ok" {
		t.Errorf("legacy status = %v, want ok", legacy)
	}
}
