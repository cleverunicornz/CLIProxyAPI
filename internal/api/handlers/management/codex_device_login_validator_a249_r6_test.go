// Verbatim probes of validator a249, round 6 (CLIProxyAPI #9 at 94e56a32).
package management

// Independent round-6 checks. All codes, auths, remotes and files are fake.
import (
	"bufio"
	"context"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/auth/codex"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	backendstore "github.com/router-for-me/CLIProxyAPI/v8/internal/store"
	sdkAuth "github.com/router-for-me/CLIProxyAPI/v8/sdk/auth"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	log "github.com/sirupsen/logrus"
)

type a249R6S3 struct {
	mu                 sync.Mutex
	objects            map[string][]byte
	puts, deletes      int
	faultDir           string
	refuse, mirrorFail bool
}

func (s *a249R6S3) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	key := strings.TrimPrefix(strings.TrimPrefix(r.URL.Path, "/r6-fake"), "/")
	if key == "" && r.Method == http.MethodHead {
		w.WriteHeader(200)
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if key == "" && r.Method == http.MethodGet {
		type item struct {
			Key          string
			LastModified string
			ETag         string
			Size         int64
			StorageClass string
		}
		result := struct {
			XMLName     xml.Name `xml:"ListBucketResult"`
			Name        string
			Prefix      string
			KeyCount    int
			IsTruncated bool
			Contents    []item
		}{Name: "r6-fake", Prefix: r.URL.Query().Get("prefix")}
		for k, data := range s.objects {
			if strings.HasPrefix(k, result.Prefix) {
				result.Contents = append(result.Contents, item{k, "2026-01-01T00:00:00Z", `"r6fake"`, int64(len(data)), "STANDARD"})
			}
		}
		sort.Slice(result.Contents, func(i, j int) bool { return result.Contents[i].Key < result.Contents[j].Key })
		result.KeyCount = len(result.Contents)
		w.Header().Set("Content-Type", "application/xml")
		_ = xml.NewEncoder(w).Encode(result)
		return
	}
	switch r.Method {
	case http.MethodPut:
		var reader io.Reader = r.Body
		if strings.HasPrefix(r.Header.Get("X-Amz-Content-Sha256"), "STREAMING-") {
			reader = httputil.NewChunkedReader(r.Body)
		}
		data, err := io.ReadAll(reader)
		if err != nil {
			http.Error(w, "R6_FAKE_BODY_ERROR", 400)
			return
		}
		if s.refuse {
			w.Header().Set("Content-Type", "application/xml")
			w.WriteHeader(403)
			_, _ = io.WriteString(w, `<Error><Code>AccessDenied</Code><Message>R6_FAKE_REFUSAL</Message></Error>`)
			return
		}
		s.objects[key] = data
		if strings.HasPrefix(key, "auths/") {
			s.puts++
			if s.mirrorFail {
				_ = os.Remove(filepath.Join(s.faultDir, strings.TrimPrefix(key, "auths/")) + ".tmp")
			}
		}
		w.Header().Set("ETag", `"r6fake"`)
		w.WriteHeader(200)
	case http.MethodDelete:
		delete(s.objects, key)
		s.deletes++
		w.WriteHeader(204)
	case http.MethodGet, http.MethodHead:
		data, ok := s.objects[key]
		if !ok {
			w.Header().Set("Content-Type", "application/xml")
			w.WriteHeader(404)
			_, _ = io.WriteString(w, `<Error><Code>NoSuchKey</Code><Message>R6_FAKE_MISSING</Message></Error>`)
			return
		}
		w.Header().Set("Content-Length", strconv.Itoa(len(data)))
		w.Header().Set("ETag", `"r6fake"`)
		w.Header().Set("Last-Modified", "Thu, 01 Jan 2026 00:00:00 GMT")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		if r.Method == http.MethodGet {
			_, _ = w.Write(data)
		}
	default:
		http.Error(w, "R6_FAKE_UNEXPECTED_METHOD", 400)
	}
}
func (s *a249R6S3) count() (int, int, int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for k := range s.objects {
		if strings.HasPrefix(k, "auths/") {
			n++
		}
	}
	return n, s.puts, s.deletes
}
func a249R6Object(t *testing.T, endpoint, root string) *backendstore.ObjectTokenStore {
	t.Helper()
	s, e := backendstore.NewObjectTokenStore(backendstore.ObjectStoreConfig{Endpoint: strings.TrimPrefix(endpoint, "http://"), Bucket: "r6-fake", AccessKey: "R6_FAKE_KEY", SecretKey: "R6_FAKE_SECRET", Region: "us-east-1", LocalRoot: root, PathStyle: true})
	if e != nil {
		t.Fatal(e)
	}
	return s
}
func a249R6Record() *coreauth.Auth {
	return &coreauth.Auth{ID: "r6-fake.json", FileName: "r6-fake.json", Provider: "codex", Storage: &codex.CodexTokenStorage{Email: "r6@example.test", AccessToken: "R6_FAKE_ACCESS", RefreshToken: "R6_FAKE_REFRESH"}, Metadata: map[string]any{"email": "r6@example.test"}}
}

type a249R6StorageFault struct {
	inner interface{ SaveTokenToFile(string) error }
	mode  string
}

func (s *a249R6StorageFault) SetMetadata(m map[string]any) {
	if v, ok := s.inner.(interface{ SetMetadata(map[string]any) }); ok {
		v.SetMetadata(m)
	}
}
func (s *a249R6StorageFault) SaveTokenToFile(path string) error {
	if e := s.inner.SaveTokenToFile(path); e != nil {
		return e
	}
	switch s.mode {
	case "missing":
		return os.Remove(path)
	case "empty":
		return os.WriteFile(path, nil, 0600)
	}
	return nil
}

// Disappearance/truncation of staging happens before upload. A deletion of a
// remote key must never be interpreted as acceptance of the new credential.
func TestA249R6DoneRequiresActualObjectWrite(t *testing.T) {
	for _, mode := range []string{"normal", "missing", "empty"} {
		t.Run(mode, func(t *testing.T) {
			f := a249Fixture(t)
			remote := &a249R6S3{objects: map[string][]byte{}}
			server := httptest.NewServer(remote)
			defer server.Close()
			backend := a249R6Object(t, server.URL, t.TempDir())
			f.handler.tokenStore = backend
			f.handler.cfg.AuthDir = backend.AuthDir()
			f.handler.postAuthHook = func(_ context.Context, a *coreauth.Auth) error {
				a.Storage = &a249R6StorageFault{inner: a.Storage, mode: mode}
				return nil
			}
			state := f.start(t, 1)
			f.h.waitWatcher(state)
			_, status, _ := f.h.status(state)
			n, puts, deletes := remote.count()
			fresh := a249R6Object(t, server.URL, t.TempDir())
			if e := fresh.Bootstrap(context.Background(), ""); e != nil {
				t.Fatal(e)
			}
			manager := coreauth.NewManager(fresh, nil, nil)
			if e := manager.Load(context.Background()); e != nil {
				t.Fatal(e)
			}
			t.Logf("staging=%s status=%v remote-auths=%d PUTs=%d DELETEs=%d restart-loaded=%d", mode, status["status"], n, puts, deletes, len(manager.List()))
			if status["status"] == "done" && (n == 0 || len(manager.List()) == 0) {
				t.Error("done without a credential in the store of record")
			}
			if mode == "normal" && (status["status"] != "done" || n != 1 || len(manager.List()) != 1) {
				t.Fatal("normal save/restart control failed")
			}
		})
	}
}

type a249R6FakeAuthenticator struct{ record *coreauth.Auth }

func (a *a249R6FakeAuthenticator) Provider() string            { return "r6-fake" }
func (a *a249R6FakeAuthenticator) RefreshLead() *time.Duration { return nil }
func (a *a249R6FakeAuthenticator) Login(context.Context, *config.Config, *sdkAuth.LoginOptions) (*coreauth.Auth, error) {
	return a.record, nil
}
func TestA249R6OtherSavePathsKeepMirrorError(t *testing.T) {
	for _, flow := range []string{"management", "sdk", "plugin"} {
		t.Run(flow, func(t *testing.T) {
			f := a249Fixture(t)
			remote := &a249R6S3{objects: map[string][]byte{}, mirrorFail: true}
			server := httptest.NewServer(remote)
			defer server.Close()
			backend := a249R6Object(t, server.URL, t.TempDir())
			remote.faultDir = backend.AuthDir()
			f.handler.tokenStore = backend
			f.handler.cfg.AuthDir = backend.AuthDir()
			record := a249R6Record()
			var err error
			switch flow {
			case "management":
				_, err = f.handler.saveTokenRecord(context.Background(), record)
			case "sdk":
				_, _, err = sdkAuth.NewManager(backend, &a249R6FakeAuthenticator{record}).Login(context.Background(), "r6-fake", f.handler.cfg, nil)
			case "plugin":
				err = f.handler.savePluginLoginRecords(context.Background(), []*coreauth.Auth{record})
			}
			t.Logf("flow=%s returned-error=%t mirror-error=%t", flow, err != nil, errors.Is(err, coreauth.ErrMirrorNotUpdated))
			if !errors.Is(err, coreauth.ErrMirrorNotUpdated) {
				t.Error("non-device flow did not preserve the save error")
			}
		})
	}
}

type a249R6Ready struct {
	State                     string
	Status                    string
	Note, Logged, PublicShape bool
	RemoteCount, Loaded       int
	HTTP                      int
	Cancelled                 bool
}

func TestA249R6ObjectRestartWorker(t *testing.T) {
	phase := os.Getenv("A249_R6_PHASE")
	if phase == "" {
		t.Skip("subprocess helper")
	}
	f := a249Fixture(t)
	backend := a249R6Object(t, os.Getenv("A249_R6_ENDPOINT"), os.Getenv("A249_R6_ROOT"))
	f.handler.tokenStore = backend
	f.handler.cfg.AuthDir = backend.AuthDir()
	var result a249R6Ready
	if phase == "save" {
		var logs pr9Buffer
		old := log.StandardLogger().Out
		log.SetOutput(&logs)
		defer log.SetOutput(old)
		result.State = f.start(t, 1)
		f.h.waitWatcher(result.State)
		_, status, _ := f.h.status(result.State)
		r, _ := codexDeviceLogins.get(result.State)
		result.Status = fmt.Sprint(status["status"])
		result.Note = strings.Contains(r.message, "local mirror")
		result.Logged = strings.Contains(logs.String(), "local mirror")
		_, hasMessage := status["message"]
		_, hasError := status["error"]
		result.PublicShape = len(status) == 4 && !hasMessage && !hasError && status["account"] != nil
		pipe := os.NewFile(3, "ready")
		_ = json.NewEncoder(pipe).Encode(result)
		_ = pipe.Close()
		select {}
	}
	if e := backend.Bootstrap(context.Background(), ""); e != nil {
		t.Fatal(e)
	}
	manager := coreauth.NewManager(backend, nil, nil)
	if e := manager.Load(context.Background()); e != nil {
		t.Fatal(e)
	}
	result.Loaded = len(manager.List())
	result.HTTP, _, _ = f.h.status(os.Getenv("A249_R6_OLD_STATE"))
	result.Cancelled = f.cancel(t, os.Getenv("A249_R6_OLD_STATE"))
	pipe := os.NewFile(3, "ready")
	_ = json.NewEncoder(pipe).Encode(result)
	_ = pipe.Close()
	if result.Loaded != 1 || result.HTTP != 404 || result.Cancelled {
		t.Fatal("restart did not load stored credential and forget old login")
	}
}

// The fake bucket stays in the parent. The saving gateway process is killed;
// a fresh process must Bootstrap and load the credential from that bucket.
func TestA249R6ObjectMirrorFailureSurvivesProcessRestart(t *testing.T) {
	root := t.TempDir()
	remote := &a249R6S3{objects: map[string][]byte{}, mirrorFail: true, faultDir: filepath.Join(root, "auths")}
	server := httptest.NewServer(remote)
	defer server.Close()
	exe, e := os.Executable()
	if e != nil {
		t.Fatal(e)
	}
	launch := func(phase, state string) (*exec.Cmd, *os.File, *pr9Buffer) {
		r, w, e := os.Pipe()
		if e != nil {
			t.Fatal(e)
		}
		cmd := exec.Command(exe, "-test.run=^TestA249R6ObjectRestartWorker$", "-test.v")
		cmd.Env = append(os.Environ(), "A249_R6_PHASE="+phase, "A249_R6_ENDPOINT="+server.URL, "A249_R6_ROOT="+root, "A249_R6_OLD_STATE="+state)
		cmd.ExtraFiles = []*os.File{w}
		out := &pr9Buffer{}
		cmd.Stdout = out
		cmd.Stderr = out
		if e := cmd.Start(); e != nil {
			t.Fatal(e)
		}
		_ = w.Close()
		t.Cleanup(func() {
			if cmd.ProcessState == nil {
				_ = cmd.Process.Kill()
				_ = cmd.Wait()
			}
			_ = r.Close()
		})
		return cmd, r, out
	}
	receive := func(r *os.File) a249R6Ready {
		ch := make(chan a249R6Ready, 1)
		go func() {
			var x a249R6Ready
			s := bufio.NewScanner(r)
			if s.Scan() {
				_ = json.Unmarshal(s.Bytes(), &x)
			}
			ch <- x
		}()
		select {
		case x := <-ch:
			return x
		case <-time.After(10 * time.Second):
			t.Fatal("child did not report readiness")
		}
		return a249R6Ready{}
	}
	old, r, _ := launch("save", "")
	ready := receive(r)
	n, _, _ := remote.count()
	if ready.Status != "done" || !ready.Note || !ready.Logged || !ready.PublicShape || n != 1 {
		t.Fatalf("partial-done boundary mismatch: status=%s note=%t logged=%t shape=%t remote=%d", ready.Status, ready.Note, ready.Logged, ready.PublicShape, n)
	}
	if e := old.Process.Kill(); e != nil {
		t.Fatal(e)
	}
	_ = old.Wait()
	fresh, r2, out := launch("restart", ready.State)
	loaded := receive(r2)
	if e := fresh.Wait(); e != nil {
		t.Fatalf("restart failed: %v %s", e, out.String())
	}
	t.Logf("before-kill=done remote=%d note=%t logged=%t response-unchanged=%t restart-loaded=%d old-state-HTTP=%d cancel=%t", n, ready.Note, ready.Logged, ready.PublicShape, loaded.Loaded, loaded.HTTP, loaded.Cancelled)
}
