package management

import (
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	sdkAuth "github.com/router-for-me/CLIProxyAPI/v8/sdk/auth"
)

// codexDeviceLoginOptions supplies the HTTP client and timings of a
// management Codex device login; tests replace it.
var codexDeviceLoginOptions = func(*config.Config) sdkAuth.CodexDeviceOptions {
	return sdkAuth.CodexDeviceOptions{}
}

type codexDeviceLoginStore struct {
	mu  sync.Mutex
	now func() time.Time
}

var codexDeviceLogins = &codexDeviceLoginStore{now: time.Now}

func (s *codexDeviceLoginStore) watcherDone(string) <-chan struct{} { return nil }

// StartCodexDeviceLogin is not implemented yet.
func (h *Handler) StartCodexDeviceLogin(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, gin.H{"status": "error", "error": "not implemented"})
}

// GetCodexDeviceLoginStatus is not implemented yet.
func (h *Handler) GetCodexDeviceLoginStatus(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, gin.H{"status": "error", "error": "not implemented"})
}
