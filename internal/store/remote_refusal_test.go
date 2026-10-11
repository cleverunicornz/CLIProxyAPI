package store

import (
	"context"
	"database/sql"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
)

// A remote store's Save changes its local mirror only once the remote write
// succeeded. Otherwise a refused write would leave a credential file the
// auth-directory watcher or the store's local listing could admit, though the
// caller was told the save failed.
func TestRemoteStoreRefusalLeavesLocalMirrorUnchanged(t *testing.T) {
	for _, tc := range []struct {
		name string
		make func(t *testing.T) (cliproxyauth.Store, string)
	}{
		{"postgres", func(t *testing.T) (cliproxyauth.Store, string) {
			// Nothing listens on port 1: every statement is refused.
			db, err := sql.Open("pgx", "postgres://fake:fake@127.0.0.1:1/fake?sslmode=disable&connect_timeout=2")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = db.Close() })
			dir := filepath.Join(t.TempDir(), "auths")
			return &PostgresStore{db: db, cfg: PostgresStoreConfig{AuthTable: defaultAuthTable}, authDir: dir}, dir
		}},
		{"object", func(t *testing.T) (cliproxyauth.Store, string) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/xml")
				w.WriteHeader(http.StatusForbidden)
				_, _ = w.Write([]byte(`<Error><Code>AccessDenied</Code><Message>fake refusal</Message></Error>`))
			}))
			t.Cleanup(server.Close)
			store, err := NewObjectTokenStore(ObjectStoreConfig{Endpoint: strings.TrimPrefix(server.URL, "http://"), Bucket: "fake", AccessKey: "fake", SecretKey: "fake", Region: "us-east-1", LocalRoot: t.TempDir(), PathStyle: true})
			if err != nil {
				t.Fatal(err)
			}
			return store, store.AuthDir()
		}},
	} {
		for _, shape := range []string{"storage", "metadata"} {
			t.Run(tc.name+"/"+shape, func(t *testing.T) {
				store, dir := tc.make(t)
				path := filepath.Join(dir, "codex-fake.json")
				if err := os.MkdirAll(dir, 0o700); err != nil {
					t.Fatal(err)
				}
				const previous = `{"type":"codex","access_token":"previous"}`
				if err := os.WriteFile(path, []byte(previous), 0o600); err != nil {
					t.Fatal(err)
				}
				auth := &cliproxyauth.Auth{ID: "codex-fake.json", FileName: "codex-fake.json", Provider: "codex", Metadata: map[string]any{"type": "codex", "access_token": "refused"}}
				if shape == "storage" {
					auth.Storage = &callbackTokenStorage{save: func(p string) error {
						return os.WriteFile(p, []byte(`{"type":"codex","access_token":"refused"}`), 0o600)
					}}
				}
				if _, err := store.Save(cliproxyauth.WithAuthCreationIntent(context.Background()), auth); err == nil {
					t.Fatal("Save succeeded against a refusing remote")
				}
				data, err := os.ReadFile(path)
				if err != nil || string(data) != previous {
					t.Fatalf("local credential after a refused save = %q, %v; want the previous one", data, err)
				}
				entries, _ := os.ReadDir(dir)
				for _, entry := range entries {
					if entry.Name() != "codex-fake.json" {
						t.Fatalf("a refused save left %s in the auth directory", entry.Name())
					}
				}
			})
		}
	}
}
