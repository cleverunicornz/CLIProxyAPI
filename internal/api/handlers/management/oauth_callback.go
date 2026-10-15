package management

import (
	"errors"
	"net/http"
	"net/url"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/clienterror"
	log "github.com/sirupsen/logrus"
)

type oauthCallbackRequest struct {
	Provider    string `json:"provider"`
	RedirectURL string `json:"redirect_url"`
	Code        string `json:"code"`
	State       string `json:"state"`
	Error       string `json:"error"`
}

func (h *Handler) PostOAuthCallback(c *gin.Context) {
	if h == nil || h.cfg == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"status": "error", "error": "handler not initialized"})
		return
	}

	var req oauthCallbackRequest
	errBindJSON := c.ShouldBindJSON(&req)
	// The POST callback's state is the one its parser uses (oauthCallbackState):
	// the body's state, else the state in its redirect_url. A query state is
	// not part of a POSTed callback.
	if isCodexProviderName(c.Query("provider")) && !isPluginOAuthState(oauthCallbackState(req)) {
		RespondCodexBrowserLoginRemoved(c)
		return
	}
	if errBindJSON != nil {
		c.JSON(clienterror.HTTPStatusFromErrorOr(errBindJSON, http.StatusBadRequest), gin.H{"status": "error", "error": "invalid body"})
		return
	}
	h.handleOAuthCallback(c, req)
}

func (h *Handler) GetOAuthCallback(c *gin.Context) {
	if isCodexProviderName(c.Query("provider")) && !isPluginOAuthState(c.Query("state")) {
		RespondCodexBrowserLoginRemoved(c)
		return
	}
	req := oauthCallbackRequest{
		Provider: strings.TrimSpace(c.Query("provider")),
		Code:     strings.TrimSpace(c.Query("code")),
		State:    strings.TrimSpace(c.Query("state")),
		Error:    firstNonEmpty(c.Query("error"), c.Query("error_description")),
	}
	h.handleOAuthCallback(c, req)
}

func (h *Handler) handleOAuthCallback(c *gin.Context, req oauthCallbackRequest) {
	if h == nil || h.cfg == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"status": "error", "error": "handler not initialized"})
		return
	}

	// A callback of the removed Codex browser login answers 410 before any
	// other validation (I-000026).
	if isCodexBrowserCallback(req) {
		RespondCodexBrowserLoginRemoved(c)
		return
	}

	state := strings.TrimSpace(req.State)
	code := strings.TrimSpace(req.Code)
	errMsg := strings.TrimSpace(req.Error)

	if rawRedirect := strings.TrimSpace(req.RedirectURL); rawRedirect != "" {
		u, errParse := url.Parse(rawRedirect)
		if errParse != nil {
			c.JSON(http.StatusBadRequest, gin.H{"status": "error", "error": "invalid redirect_url"})
			return
		}
		q := u.Query()
		if state == "" {
			state = strings.TrimSpace(q.Get("state"))
		}
		if code == "" {
			code = strings.TrimSpace(q.Get("code"))
		}
		if errMsg == "" {
			errMsg = strings.TrimSpace(q.Get("error"))
			if errMsg == "" {
				errMsg = strings.TrimSpace(q.Get("error_description"))
			}
		}
	}

	if state == "" {
		c.JSON(http.StatusBadRequest, gin.H{"status": "error", "error": "state is required"})
		return
	}
	if err := ValidateOAuthState(state); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"status": "error", "error": "invalid state"})
		return
	}
	if code == "" && errMsg == "" {
		c.JSON(http.StatusBadRequest, gin.H{"status": "error", "error": "code or error is required"})
		return
	}

	sessionProvider, sessionStatus, isPlugin, _, completed, ok := GetOAuthSessionDetails(state)
	if !ok {
		c.JSON(http.StatusNotFound, gin.H{"status": "error", "error": "unknown or expired state"})
		return
	}
	if completed {
		c.JSON(http.StatusConflict, gin.H{"status": "error", "error": "oauth flow is already completed"})
		return
	}
	provider := strings.TrimSpace(req.Provider)
	if provider == "" {
		provider = sessionProvider
	}
	var canonicalProvider string
	var errNormalize error
	if isPlugin {
		canonicalProvider, errNormalize = NormalizePluginOAuthCallbackProvider(provider)
	} else {
		canonicalProvider, errNormalize = NormalizeOAuthCallbackProvider(provider)
	}
	if errNormalize != nil {
		c.JSON(http.StatusBadRequest, gin.H{"status": "error", "error": "unsupported provider"})
		return
	}
	if sessionStatus != "" {
		c.JSON(http.StatusConflict, gin.H{"status": "error", "error": sessionStatus})
		return
	}
	if !strings.EqualFold(sessionProvider, canonicalProvider) {
		c.JSON(http.StatusBadRequest, gin.H{"status": "error", "error": "provider does not match state"})
		return
	}

	if _, errWrite := WriteOAuthCallbackFileForPendingSession(h.cfg.AuthDir, canonicalProvider, state, code, errMsg); errWrite != nil {
		if errors.Is(errWrite, errOAuthSessionNotPending) {
			_, status, okSession := GetOAuthSession(state)
			if okSession && status != "" {
				c.JSON(http.StatusConflict, gin.H{"status": "error", "error": status})
				return
			}
			c.JSON(http.StatusConflict, gin.H{"status": "error", "error": "oauth flow is not pending"})
			return
		}
		log.WithError(errWrite).Error("failed to persist oauth callback")
		c.JSON(http.StatusInternalServerError, gin.H{"status": "error", "error": "failed to persist oauth callback"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

// isCodexProviderName reports a provider name of the removed Codex browser
// login: codex or openai.
func isCodexProviderName(provider string) bool {
	trimmed := strings.TrimSpace(provider)
	if trimmed == "" {
		return false
	}
	normalized, errNormalize := NormalizeOAuthProvider(trimmed)
	return errNormalize == nil && normalized == "codex"
}

// oauthCallbackState is the state a callback carries, in any shape the
// callback accepts: its state field, else the state inside its redirect_url.
// It is read without validating either.
func oauthCallbackState(req oauthCallbackRequest) string {
	if state := strings.TrimSpace(req.State); state != "" {
		return state
	}
	if u, errParse := url.Parse(strings.TrimSpace(req.RedirectURL)); errParse == nil {
		return strings.TrimSpace(u.Query().Get("state"))
	}
	return ""
}

// isPluginOAuthState reports a known plugin login's state; a plugin keeps its
// own provider name, openai included.
func isPluginOAuthState(state string) bool {
	_, _, isPlugin, _, _, known := GetOAuthSessionDetails(strings.TrimSpace(state))
	return known && isPlugin
}

// isCodexBrowserCallback reports a callback of the removed Codex browser
// login (infra-v2 I-000026): a Codex provider, the state of a device login,
// or the state of a built-in Codex session, read from state or a pasted redirect_url without
// validating either. Plugin sessions keep their own provider names.
func isCodexBrowserCallback(req oauthCallbackRequest) bool {
	state := oauthCallbackState(req)
	if _, device := codexDeviceLogins.get(state); device {
		return true
	}
	sessionProvider, _, isPlugin, _, _, known := GetOAuthSessionDetails(state)
	if known && isPlugin {
		return false
	}
	return isCodexProviderName(req.Provider) || (known && strings.EqualFold(sessionProvider, "codex"))
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed != "" {
			return trimmed
		}
	}
	return ""
}
