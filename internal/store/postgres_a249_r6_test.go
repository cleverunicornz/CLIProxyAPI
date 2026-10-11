// Verbatim probes of validator a249, round 6 (CLIProxyAPI #9 at 94e56a32).
package store

// Real PostgresStore code with a fake database/sql driver. Its rows are kept
// in an isolated fake database file so they survive a killed child process.
import (
	"bufio"
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
)

type a249R6DB struct {
	mu              sync.Mutex
	rows            map[string]string
	file            string
	after           func(string)
	refuse          bool
	writes, deletes int
}
type a249R6Driver struct{ db *a249R6DB }
type a249R6Conn struct{ db *a249R6DB }
type a249R6Rows struct {
	cols   []string
	values [][]driver.Value
	at     int
}

func (r *a249R6Rows) Columns() []string { return r.cols }
func (r *a249R6Rows) Close() error      { return nil }
func (r *a249R6Rows) Next(dest []driver.Value) error {
	if r.at == len(r.values) {
		return io.EOF
	}
	copy(dest, r.values[r.at])
	r.at++
	return nil
}
func (d *a249R6Driver) Open(string) (driver.Conn, error) { return &a249R6Conn{d.db}, nil }
func (c *a249R6Conn) Prepare(string) (driver.Stmt, error) {
	return nil, errors.New("unexpected R6 fake Prepare")
}
func (c *a249R6Conn) Close() error                             { return nil }
func (c *a249R6Conn) Begin() (driver.Tx, error)                { return nil, errors.New("unexpected R6 fake Begin") }
func (c *a249R6Conn) CheckNamedValue(*driver.NamedValue) error { return nil }
func (c *a249R6Conn) ExecContext(_ context.Context, q string, args []driver.NamedValue) (driver.Result, error) {
	d := c.db
	d.mu.Lock()
	defer d.mu.Unlock()
	if strings.Contains(q, "CREATE ") {
		return driver.RowsAffected(0), nil
	}
	if strings.Contains(q, defaultConfigTable) {
		return driver.RowsAffected(1), nil
	}
	id, _ := args[0].Value.(string)
	if strings.Contains(q, "DELETE FROM") {
		delete(d.rows, id)
		d.deletes++
	} else if strings.Contains(q, "INSERT INTO") {
		if d.refuse {
			return nil, errors.New("R6_FAKE_REFUSAL")
		}
		var data []byte
		switch x := args[1].Value.(type) {
		case json.RawMessage:
			data = []byte(x)
		case []byte:
			data = x
		case string:
			data = []byte(x)
		default:
			return nil, fmt.Errorf("unexpected fake SQL type %T", x)
		}
		if !json.Valid(data) {
			return nil, errors.New("fake database received invalid JSON")
		}
		d.rows[id] = string(data)
		d.writes++
	} else {
		return nil, errors.New("unexpected R6 fake SQL statement")
	}
	if d.file != "" {
		data, _ := json.Marshal(d.rows)
		if e := os.WriteFile(d.file, data, 0600); e != nil {
			return nil, e
		}
	}
	if d.after != nil && strings.Contains(q, "INSERT INTO") {
		d.after(id)
	}
	return driver.RowsAffected(1), nil
}
func (c *a249R6Conn) QueryContext(_ context.Context, q string, _ []driver.NamedValue) (driver.Rows, error) {
	d := c.db
	d.mu.Lock()
	defer d.mu.Unlock()
	if strings.Contains(q, defaultConfigTable) {
		return &a249R6Rows{cols: []string{"content"}, values: [][]driver.Value{{"port: 0\n"}}}, nil
	}
	keys := make([]string, 0, len(d.rows))
	for k := range d.rows {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	result := &a249R6Rows{cols: []string{"id", "content"}}
	timestamps := strings.Contains(q, "created_at")
	if timestamps {
		result.cols = append(result.cols, "created_at", "updated_at")
	}
	for _, k := range keys {
		v := []driver.Value{k, d.rows[k]}
		if timestamps {
			v = append(v, time.Now(), time.Now())
		}
		result.values = append(result.values, v)
	}
	return result, nil
}

var a249R6DriverID atomic.Int64

func a249R6Postgres(t *testing.T, d *a249R6DB, root string) *PostgresStore {
	t.Helper()
	if d.rows == nil {
		d.rows = map[string]string{}
	}
	if d.file != "" {
		data, e := os.ReadFile(d.file)
		if e == nil {
			if e = json.Unmarshal(data, &d.rows); e != nil {
				t.Fatal(e)
			}
		} else if !os.IsNotExist(e) {
			t.Fatal(e)
		}
	}
	name := fmt.Sprintf("a249-r6-%d", a249R6DriverID.Add(1))
	sql.Register(name, &a249R6Driver{d})
	db, e := sql.Open(name, "")
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { _ = db.Close() })
	authDir := filepath.Join(root, "auths")
	if e := os.MkdirAll(authDir, 0700); e != nil {
		t.Fatal(e)
	}
	return &PostgresStore{db: db, cfg: PostgresStoreConfig{AuthTable: defaultAuthTable, ConfigTable: defaultConfigTable, CooldownTable: defaultCooldownTable}, spoolRoot: root, authDir: authDir, configPath: filepath.Join(root, "config", "config.yaml")}
}

const a249R6AuthJSON = `{"type":"codex","email":"r6@example.test","access_token":"R6_FAKE_ACCESS","refresh_token":"R6_FAKE_REFRESH"}`

func a249R6Auth(mode string) *coreauth.Auth {
	a := &coreauth.Auth{ID: "r6-fake.json", FileName: "r6-fake.json", Provider: "codex", Metadata: map[string]any{"type": "codex", "email": "r6@example.test"}}
	a.Storage = &callbackTokenStorage{save: func(path string) error {
		if e := os.WriteFile(path, []byte(a249R6AuthJSON), 0600); e != nil {
			return e
		}
		if mode == "missing" {
			return os.Remove(path)
		}
		if mode == "empty" {
			return os.WriteFile(path, nil, 0600)
		}
		return nil
	}}
	return a
}
func TestA249R6PostgresDoneRequiresActualWrite(t *testing.T) {
	for _, mode := range []string{"normal", "missing", "empty"} {
		t.Run(mode, func(t *testing.T) {
			d := &a249R6DB{}
			s := a249R6Postgres(t, d, t.TempDir())
			_, e := s.Save(context.Background(), a249R6Auth(mode))
			storedSignal := e == nil || errors.Is(e, coreauth.ErrMirrorNotUpdated)
			rows, eList := s.List(context.Background())
			if eList != nil {
				t.Fatal(eList)
			}
			fresh := a249R6Postgres(t, d, t.TempDir())
			if e := fresh.Bootstrap(context.Background(), ""); e != nil {
				t.Fatal(e)
			}
			manager := coreauth.NewManager(fresh, nil, nil)
			if e := manager.Load(context.Background()); e != nil {
				t.Fatal(e)
			}
			t.Logf("staging=%s reports-stored=%t rows=%d writes=%d deletes=%d restart-loaded=%d", mode, storedSignal, len(rows), d.writes, d.deletes, len(manager.List()))
			if storedSignal && (len(rows) == 0 || len(manager.List()) == 0) {
				t.Error("Save reports stored after deleting rather than storing the credential")
			}
			if mode == "normal" && (!storedSignal || len(rows) != 1) {
				t.Fatal("normal storage control failed")
			}
		})
	}
}

type a249R6PGReady struct {
	Stored, MirrorError, Note bool
	Rows, Loaded, Local       int
}

func TestA249R6PostgresRestartWorker(t *testing.T) {
	phase := os.Getenv("A249_R6_PG_PHASE")
	if phase == "" {
		t.Skip("subprocess helper")
	}
	d := &a249R6DB{file: os.Getenv("A249_R6_PG_DATABASE")}
	s := a249R6Postgres(t, d, os.Getenv("A249_R6_PG_ROOT"))
	var result a249R6PGReady
	if phase == "save" {
		d.after = func(id string) { _ = os.Remove(filepath.Join(s.authDir, id) + ".tmp") }
		path, e := s.Save(context.Background(), a249R6Auth("normal"))
		result.MirrorError = errors.Is(e, coreauth.ErrMirrorNotUpdated)
		result.Stored = path != ""
		result.Rows = len(d.rows)
		_, statErr := os.Stat(filepath.Join(s.authDir, "r6-fake.json"))
		if statErr == nil {
			result.Local = 1
		}
		pipe := os.NewFile(3, "ready")
		_ = json.NewEncoder(pipe).Encode(result)
		_ = pipe.Close()
		select {}
	}
	if e := s.Bootstrap(context.Background(), ""); e != nil {
		t.Fatal(e)
	}
	manager := coreauth.NewManager(s, nil, nil)
	if e := manager.Load(context.Background()); e != nil {
		t.Fatal(e)
	}
	result.Loaded = len(manager.List())
	result.Rows = len(d.rows)
	if raw, e := os.ReadFile(filepath.Join(s.authDir, "r6-fake.json")); e == nil && string(raw) == a249R6AuthJSON {
		result.Local = 1
	}
	pipe := os.NewFile(3, "ready")
	_ = json.NewEncoder(pipe).Encode(result)
	_ = pipe.Close()
	if result.Loaded != 1 || result.Local != 1 {
		t.Fatal("fresh Postgres bootstrap did not restore accepted credential")
	}
}
func TestA249R6PostgresMirrorFailureSurvivesProcessRestart(t *testing.T) {
	root := t.TempDir()
	file := filepath.Join(t.TempDir(), "fake-db.json")
	exe, e := os.Executable()
	if e != nil {
		t.Fatal(e)
	}
	launch := func(phase string) (*exec.Cmd, *os.File, *strings.Builder) {
		r, w, e := os.Pipe()
		if e != nil {
			t.Fatal(e)
		}
		cmd := exec.Command(exe, "-test.run=^TestA249R6PostgresRestartWorker$", "-test.v")
		cmd.Env = append(os.Environ(), "A249_R6_PG_PHASE="+phase, "A249_R6_PG_DATABASE="+file, "A249_R6_PG_ROOT="+root)
		cmd.ExtraFiles = []*os.File{w}
		out := &strings.Builder{}
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
	receive := func(r *os.File) a249R6PGReady {
		ch := make(chan a249R6PGReady, 1)
		go func() {
			var x a249R6PGReady
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
			t.Fatal("child not ready")
		}
		return a249R6PGReady{}
	}
	old, r, _ := launch("save")
	before := receive(r)
	if !before.Stored || !before.MirrorError || before.Rows != 1 || before.Local != 0 {
		t.Fatalf("save boundary mismatch: %+v", before)
	}
	if e := old.Process.Kill(); e != nil {
		t.Fatal(e)
	}
	_ = old.Wait()
	fresh, r2, out := launch("restart")
	after := receive(r2)
	if e := fresh.Wait(); e != nil {
		t.Fatalf("fresh bootstrap failed: %v %s", e, out.String())
	}
	t.Logf("before-kill: mirror-error=%t remote-rows=%d local=%d; restart: loaded=%d local=%d", before.MirrorError, before.Rows, before.Local, after.Loaded, after.Local)
}
