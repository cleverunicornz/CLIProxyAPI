// Verbatim probes of validator a249, round 6 (CLIProxyAPI #9 at 94e56a32).
package store

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	sdkAuth "github.com/router-for-me/CLIProxyAPI/v8/sdk/auth"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
)

func TestA249R6FileAndGitStoreSerialization(t *testing.T) {
	for _, kind := range []string{"file", "git"} {
		t.Run(kind, func(t *testing.T) {
			root := t.TempDir()
			var store coreauth.Store
			typeName := "FileTokenStore"
			if kind == "file" {
				s := sdkAuth.NewFileTokenStore()
				s.SetBaseDir(filepath.Join(root, "auths"))
				store = s
			} else {
				remote := setupGitRemoteRepository(t, root, "main", testBranchSpec{name: "main", contents: "R6 fake repository\n"})
				s := NewGitTokenStore(remote, "", "", "")
				s.SetBaseDir(filepath.Join(root, "workspace", "auths"))
				store = s
				typeName = "GitTokenStore"
			}
			entered, release := make(chan struct{}), make(chan struct{})
			var once sync.Once
			defer once.Do(func() { close(release) })
			a := &coreauth.Auth{ID: "first.json", FileName: "first.json", Provider: "codex", Metadata: map[string]any{"type": "codex"}, Storage: &callbackTokenStorage{save: func(path string) error {
				close(entered)
				<-release
				return os.WriteFile(path, []byte(a249R6AuthJSON), 0600)
			}}}
			b := &coreauth.Auth{ID: "second.json", FileName: "second.json", Provider: "codex", Metadata: map[string]any{"type": "codex", "email": "r6-second@example.test", "access_token": "R6_FAKE"}}
			first, second := make(chan error, 1), make(chan error, 1)
			go func() { _, e := store.Save(context.Background(), a); first <- e }()
			select {
			case <-entered:
			case <-time.After(5 * time.Second):
				t.Fatal("first Save did not enter storage")
			}
			go func() { _, e := store.Save(context.Background(), b); second <- e }()
			blocked := false
			finished := false
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
					t.Fatal("no second-writer outcome")
				}
				runtime.Gosched()
			}
			if !blocked || finished {
				t.Error("real store did not serialize its second account write")
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
			t.Logf("backend=%s second-writer-blocked=%t both-saves-returned", kind, blocked)
		})
	}
}
