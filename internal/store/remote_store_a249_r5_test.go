// Probes of validator a249, round 5 (CLIProxyAPI #9 at 3cd6d079), kept as
// regression tests. Verbatim except, after the operator's round-6 decisions,
// TestA249R5RemoteBackendLockBlocksDifferentAuth asserts the qualified
// contract (the store's own pre-existing lock serializes writes of different
// auths), and the publish-fails mode of TestA249R5RemoteMirrorWriteBoundaries
// requires the error to say the auth is stored (ErrMirrorNotUpdated) with the
// remote changed, the mirror unchanged and no staging file left.
package store

// Independent store-boundary checks. The SQL driver and S3 server are local
// fake remotes; every credential and row is synthetic.
import (
	"context"
	"database/sql"
	"database/sql/driver"
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

	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
)

type a249R5Remote struct {
	mu          sync.Mutex
	value       string
	refuse      bool
	afterAccept func()
	calls       int
}

func (r *a249R5Remote) write(data []byte) error {
	r.mu.Lock()
	r.calls++
	if r.refuse {
		r.mu.Unlock()
		return errors.New("R5_FAKE_REMOTE_REFUSAL")
	}
	r.value = string(data)
	after := r.afterAccept
	r.mu.Unlock()
	if after != nil {
		after()
	}
	return nil
}
func (r *a249R5Remote) snapshot() (string, int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.value, r.calls
}

type a249R5SQLDriver struct{ remote *a249R5Remote }
type a249R5SQLConn struct{ remote *a249R5Remote }

func (d *a249R5SQLDriver) Open(string) (driver.Conn, error) { return &a249R5SQLConn{d.remote}, nil }
func (c *a249R5SQLConn) Prepare(string) (driver.Stmt, error) {
	return nil, errors.New("unexpected fake SQL Prepare")
}
func (c *a249R5SQLConn) Close() error { return nil }
func (c *a249R5SQLConn) Begin() (driver.Tx, error) {
	return nil, errors.New("unexpected fake SQL Begin")
}
func (c *a249R5SQLConn) CheckNamedValue(*driver.NamedValue) error { return nil }
func (c *a249R5SQLConn) ExecContext(_ context.Context, q string, args []driver.NamedValue) (driver.Result, error) {
	if !strings.Contains(q, "INSERT INTO") || len(args) != 2 {
		return nil, errors.New("unexpected fake SQL statement")
	}
	var b []byte
	switch data := args[1].Value.(type) {
	case json.RawMessage:
		b = []byte(data)
	case []byte:
		b = data
	default:
		return nil, fmt.Errorf("unexpected payload type %T", data)
	}
	if err := c.remote.write(b); err != nil {
		return nil, err
	}
	return driver.RowsAffected(1), nil
}

var a249R5DriverID atomic.Int64

func a249R5StoreFixture(t *testing.T, kind string, remote *a249R5Remote) (coreauth.Store, string) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "auths")
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	if kind == "postgres" {
		name := fmt.Sprintf("a249-r5-%d", a249R5DriverID.Add(1))
		sql.Register(name, &a249R5SQLDriver{remote})
		db, err := sql.Open(name, "")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = db.Close() })
		return &PostgresStore{db: db, cfg: PostgresStoreConfig{AuthTable: defaultAuthTable}, authDir: dir}, dir
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var reader io.Reader = r.Body
		if strings.Contains(r.Header.Get("Content-Encoding"), "aws-chunked") || strings.HasPrefix(r.Header.Get("X-Amz-Content-Sha256"), "STREAMING-") {
			reader = httputil.NewChunkedReader(r.Body)
		}
		data, err := io.ReadAll(reader)
		if err != nil {
			t.Error(err)
		}
		if !json.Valid(data) {
			t.Error("fake remote received invalid credential JSON")
		}
		if err = remote.write(data); err != nil {
			w.Header().Set("Content-Type", "application/xml")
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`<Error><Code>AccessDenied</Code><Message>R5_FAKE_REFUSAL</Message></Error>`))
			return
		}
		w.Header().Set("ETag", `"r5-fake-etag"`)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(server.Close)
	store, err := NewObjectTokenStore(ObjectStoreConfig{Endpoint: strings.TrimPrefix(server.URL, "http://"), Bucket: "r5-fake", AccessKey: "R5_FAKE_KEY", SecretKey: "R5_FAKE_SECRET", Region: "us-east-1", LocalRoot: filepath.Dir(dir), PathStyle: true})
	if err != nil {
		t.Fatal(err)
	}
	return store, store.AuthDir()
}

func TestA249R5RemoteBackendLockBlocksDifferentAuth(t *testing.T) {
	for _, kind := range []string{"postgres", "object"} {
		t.Run(kind, func(t *testing.T) {
			reached := make(chan struct{})
			release := make(chan struct{})
			var once sync.Once
			defer once.Do(func() { close(release) })
			var entered atomic.Int32
			remote := &a249R5Remote{afterAccept: func() {
				if entered.Add(1) == 1 {
					close(reached)
					<-release
				}
			}}
			store, _ := a249R5StoreFixture(t, kind, remote)
			record := func(id string) *coreauth.Auth {
				return &coreauth.Auth{ID: id, FileName: id, Provider: "codex", Metadata: map[string]any{"type": "codex", "email": id + "@example.test", "access_token": "R5_FAKE"}}
			}
			first := make(chan error, 1)
			second := make(chan error, 1)
			go func() { _, e := store.Save(context.Background(), record("first.json")); first <- e }()
			select {
			case <-reached:
			case <-time.After(5 * time.Second):
				t.Fatal("first write did not reach fake remote")
			}
			go func() { _, e := store.Save(context.Background(), record("second.json")); second <- e }()
			typeName := "PostgresStore"
			if kind == "object" {
				typeName = "ObjectTokenStore"
			}
			blocked, finished := false, false
			until := time.Now().Add(5 * time.Second)
			for !blocked && !finished {
				select {
				case e := <-second:
					if e != nil {
						t.Error(e)
					}
					finished = true
				default:
				}
				buf := make([]byte, 2<<20)
				n := runtime.Stack(buf, true)
				for _, g := range strings.Split(string(buf[:n]), "\n\n") {
					if strings.Contains(g, "(*"+typeName+").Save(") && (strings.Contains(g, "sync.Mutex.Lock") || strings.Contains(g, "(*Mutex).lockSlow")) {
						blocked = true
					}
				}
				if time.Now().After(until) {
					t.Fatal("second write neither finished nor waited on store mutex")
				}
				runtime.Gosched()
			}
			_, calls := remote.snapshot()
			t.Logf("backend=%s second-finished=%t blocked-on-store-mutex=%t remote-writes=%d", kind, finished, blocked, calls)
			// Revision 5: the store's own lock serializes its writes.
			if !blocked || finished {
				t.Error("a different auth's write did not wait at the store's lock as the contract states")
			}
			once.Do(func() { close(release) })
			if e := <-first; e != nil {
				t.Error(e)
			}
			if !finished {
				if e := <-second; e != nil {
					t.Error(e)
				}
			}
		})
	}
}

// Exercise new-account and replacement writes, through both storage and
// metadata branches, including the local publication boundary after success.
func TestA249R5RemoteMirrorWriteBoundaries(t *testing.T) {
	const old = `{"type":"codex","email":"r5@example.test","access_token":"R5_FAKE_OLD"}`
	const next = `{"type":"codex","email":"r5@example.test","access_token":"R5_FAKE_NEW"}`
	for _, kind := range []string{"postgres", "object"} {
		for _, shape := range []string{"storage", "metadata"} {
			for _, existing := range []bool{false, true} {
				for _, mode := range []string{"refuse", "success", "publish-fails"} {
					t.Run(fmt.Sprintf("%s/%s/existing=%t/%s", kind, shape, existing, mode), func(t *testing.T) {
						remote := &a249R5Remote{refuse: mode == "refuse"}
						store, dir := a249R5StoreFixture(t, kind, remote)
						path := filepath.Join(dir, "r5-fake.json")
						previous := ""
						if existing {
							previous = old
							remote.value = old
							if err := os.WriteFile(path, []byte(old), 0600); err != nil {
								t.Fatal(err)
							}
						}
						if mode == "publish-fails" {
							remote.afterAccept = func() {
								if err := os.Remove(path + ".tmp"); err != nil {
									t.Error(err)
								}
							}
						}
						var meta map[string]any
						if err := json.Unmarshal([]byte(next), &meta); err != nil {
							t.Fatal(err)
						}
						record := &coreauth.Auth{ID: "r5-fake.json", FileName: "r5-fake.json", Provider: "codex", Metadata: meta}
						if shape == "storage" {
							record.Storage = &callbackTokenStorage{save: func(p string) error { return os.WriteFile(p, []byte(next), 0600) }}
						}
						_, err := store.Save(coreauth.WithAuthCreationIntent(context.Background()), record)
						remoteValue, calls := remote.snapshot()
						localBytes, readErr := os.ReadFile(path)
						local := string(localBytes)
						if readErr != nil && !os.IsNotExist(readErr) {
							t.Fatal(readErr)
						}
						entries, _ := os.ReadDir(dir)
						temps := 0
						for _, e := range entries {
							if strings.HasSuffix(e.Name(), ".tmp") {
								temps++
							}
						}
						t.Logf("mode=%s save-error=%t remote-changed=%t local-changed=%t calls=%d temps=%d", mode, err != nil, remoteValue != previous, local != previous, calls, temps)
						switch mode {
						case "refuse":
							if err == nil || local != previous || remoteValue != previous || temps != 0 {
								t.Error("remote refusal changed state or retained staging")
							}
						case "success":
							if err != nil || remoteValue == previous || local == previous || temps != 0 {
								t.Error("successful save did not publish both copies")
							}
						case "publish-fails":
							if err == nil {
								t.Fatal("local publication fault was not exercised")
							}
							if !errors.Is(err, coreauth.ErrMirrorNotUpdated) {
								t.Errorf("Save error %v after the remote accepted the credential does not say it is stored", err)
							}
							if remoteValue == previous || local != previous || temps != 0 {
								t.Error("after remote acceptance the remote must hold the new credential and the mirror the previous one, with no staging left")
							}
						}
					})
				}
			}
		}
	}
}
