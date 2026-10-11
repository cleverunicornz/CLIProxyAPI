package management

import (
	"context"
	"errors"
	"math"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/misc"
	sdkAuth "github.com/router-for-me/CLIProxyAPI/v8/sdk/auth"
	log "github.com/sirupsen/logrus"
)

// The Codex device login of the management API, the only Codex login it
// offers (infra-v2 I-000026). The contract is
// docs/codex-device-login-management.md.

const (
	codexDeviceStatePrefix    = "codex-device-"
	codexDeviceLoginRetention = 15 * time.Minute

	codexDeviceStatusPending   = "pending"
	codexDeviceStatusDone      = "done"
	codexDeviceStatusFailed    = "failed"
	codexDeviceStatusExpired   = "expired"
	codexDeviceStatusCancelled = "cancelled"
)

// codexDeviceLoginOptions supplies the HTTP client and timings of a
// management Codex device login; tests replace it.
var codexDeviceLoginOptions = func(*config.Config) sdkAuth.CodexDeviceOptions {
	return sdkAuth.CodexDeviceOptions{}
}

type codexDeviceAccount struct {
	Email    string `json:"email"`
	PlanType string `json:"plan_type"`
	Name     string `json:"name"`
}

type codexDeviceLoginRecord struct {
	status          string
	verificationURI string
	userCode        string
	expiresAt       time.Time
	finishedAt      time.Time
	account         *codexDeviceAccount
	errorCode       string
	message         string

	stop context.CancelFunc
	done chan struct{}
}

// codexDeviceLoginStore keeps the device logins of this gateway in memory:
// pending ones until they finish, finished ones for the retention period.
type codexDeviceLoginStore struct {
	mu      sync.Mutex
	now     func() time.Time
	records map[string]*codexDeviceLoginRecord
}

var codexDeviceLogins = &codexDeviceLoginStore{
	now:     time.Now,
	records: make(map[string]*codexDeviceLoginRecord),
}

func (s *codexDeviceLoginStore) purgeLocked() {
	now := s.now()
	for state, record := range s.records {
		if record.status != codexDeviceStatusPending && now.Sub(record.finishedAt) > codexDeviceLoginRetention {
			delete(s.records, state)
		}
	}
}

func (s *codexDeviceLoginStore) add(state string, record *codexDeviceLoginRecord) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.purgeLocked()
	s.records[state] = record
}

// finish moves a pending login to a final status; a finished login keeps
// its status.
func (s *codexDeviceLoginStore) finish(state, status string, account *codexDeviceAccount, errorCode, message string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	record, ok := s.records[state]
	if !ok || record.status != codexDeviceStatusPending {
		return
	}
	record.status = status
	record.account = account
	record.errorCode = errorCode
	record.message = message
	record.userCode = ""
	record.verificationURI = ""
	record.finishedAt = s.now()
}

func (s *codexDeviceLoginStore) get(state string) (codexDeviceLoginRecord, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.purgeLocked()
	record, ok := s.records[state]
	if !ok {
		return codexDeviceLoginRecord{}, false
	}
	return *record, true
}

// stop ends the background polling of a login, if it is still running.
func (s *codexDeviceLoginStore) stop(state string) {
	s.mu.Lock()
	record, ok := s.records[state]
	s.mu.Unlock()
	if ok && record.stop != nil {
		record.stop()
	}
}

// watcherDone is closed when the background polling of state has exited;
// nil for an unknown state.
func (s *codexDeviceLoginStore) watcherDone(state string) <-chan struct{} {
	s.mu.Lock()
	defer s.mu.Unlock()
	if record, ok := s.records[state]; ok {
		return record.done
	}
	return nil
}

// StartCodexDeviceLogin starts a Codex device login: POST
// /v0/management/codex-device-login. The answer carries the verification URL
// and the user code to show, never OpenAI's device auth id.
func (h *Handler) StartCodexDeviceLogin(c *gin.Context) {
	random, errState := misc.GenerateRandomState()
	if errState != nil {
		log.WithError(errState).Error("codex device login: failed to generate state")
		c.JSON(http.StatusInternalServerError, gin.H{"status": "error", "error": "internal_error"})
		return
	}
	state := codexDeviceStatePrefix + random

	opts := codexDeviceLoginOptions(h.cfg)
	login, errStart := sdkAuth.StartCodexDeviceLogin(c.Request.Context(), h.cfg, opts)
	if errStart != nil {
		log.WithError(errStart).Warn("codex device login: OpenAI did not issue a device code")
		c.JSON(http.StatusBadGateway, gin.H{"status": "error", "error": "device_code_request_failed", "message": errStart.Error()})
		return
	}

	RegisterOAuthSession(state, "codex")
	ctx := PopulateAuthContext(context.Background(), c)
	pollCtx, stop := context.WithCancel(ctx)
	record := &codexDeviceLoginRecord{
		status:          codexDeviceStatusPending,
		verificationURI: login.VerificationURL,
		userCode:        login.UserCode,
		expiresAt:       login.ExpiresAt,
		stop:            stop,
		done:            make(chan struct{}),
	}
	codexDeviceLogins.add(state, record)
	go h.completeCodexDeviceLogin(ctx, pollCtx, stop, record.done, state, login, opts)

	log.WithField("state", state).Info("codex device login started")
	c.JSON(http.StatusOK, gin.H{
		"status":           "ok",
		"flow":             "device",
		"state":            state,
		"verification_uri": login.VerificationURL,
		"url":              login.VerificationURL,
		"user_code":        login.UserCode,
		"expires_in":       int(math.Ceil(time.Until(login.ExpiresAt).Seconds())),
		"expires_at":       login.ExpiresAt.UTC().Format(time.RFC3339),
	})
}

// completeCodexDeviceLogin polls OpenAI for one login and stores the auth
// the way the CLI device login does. A cancel through oauth-session stops it
// without storing anything.
func (h *Handler) completeCodexDeviceLogin(ctx, pollCtx context.Context, stop context.CancelFunc, done chan struct{}, state string, login *sdkAuth.CodexDeviceLogin, opts sdkAuth.CodexDeviceOptions) {
	defer close(done)
	defer stop()
	go watchOAuthSessionCancel(pollCtx, stop, state, "codex")

	authenticator := sdkAuth.NewCodexAuthenticator()
	record, errComplete := authenticator.CompleteCodexDeviceLogin(pollCtx, h.cfg, login, opts)
	if errComplete != nil {
		if !IsOAuthSessionPending(state, "codex") {
			codexDeviceLogins.finish(state, codexDeviceStatusCancelled, nil, "", "")
			return
		}
		status, errorCode, message := classifyCodexDeviceError(errComplete)
		codexDeviceLogins.finish(state, status, nil, errorCode, message)
		SetOAuthSessionError(state, message)
		log.WithFields(log.Fields{"state": state, "error_code": errorCode}).Warn("codex device login ended without a login")
		return
	}

	if errGuard := guardOAuthSessionPendingForSave(state, "codex"); errGuard != nil {
		codexDeviceLogins.finish(state, codexDeviceStatusCancelled, nil, "", "")
		return
	}
	if _, errSave := h.saveTokenRecord(ctx, record); errSave != nil {
		message := "Failed to save authentication tokens"
		codexDeviceLogins.finish(state, codexDeviceStatusFailed, nil, "save_failed", message)
		SetOAuthSessionError(state, message)
		log.WithError(errSave).WithField("state", state).Error("codex device login: failed to save the auth")
		return
	}

	email, _ := record.Metadata["email"].(string)
	planType, _ := record.Metadata["plan_type"].(string)
	codexDeviceLogins.finish(state, codexDeviceStatusDone, &codexDeviceAccount{Email: email, PlanType: planType, Name: record.FileName}, "", "")
	CompleteOAuthSession(state)
	log.WithField("state", state).Info("codex device login stored an auth")
}

func classifyCodexDeviceError(err error) (status, errorCode, message string) {
	switch {
	case errors.Is(err, sdkAuth.ErrCodexDeviceExpired):
		return codexDeviceStatusExpired, "expired", "The device code expired before the login was completed"
	case errors.Is(err, sdkAuth.ErrCodexDeviceRejected):
		return codexDeviceStatusFailed, "provider_rejected", err.Error()
	case errors.Is(err, sdkAuth.ErrCodexDeviceInvalidResponse):
		return codexDeviceStatusFailed, "invalid_provider_response", sdkAuth.ErrCodexDeviceInvalidResponse.Error()
	case errors.Is(err, sdkAuth.ErrCodexDeviceExchangeFailed):
		return codexDeviceStatusFailed, "exchange_failed", sdkAuth.ErrCodexDeviceExchangeFailed.Error()
	case errors.Is(err, sdkAuth.ErrCodexDeviceMissingAccount):
		return codexDeviceStatusFailed, "missing_account", "The tokens carry no account e-mail"
	default:
		return codexDeviceStatusFailed, "provider_unreachable", sdkAuth.ErrCodexDeviceUnreachable.Error()
	}
}

// GetCodexDeviceLoginStatus reports a Codex device login: GET
// /v0/management/codex-device-login?state=.
func (h *Handler) GetCodexDeviceLoginStatus(c *gin.Context) {
	state := strings.TrimSpace(c.Query("state"))
	if state == "" {
		c.JSON(http.StatusBadRequest, gin.H{"status": "error", "error": "missing_state"})
		return
	}
	if errValidate := ValidateOAuthState(state); errValidate != nil {
		c.JSON(http.StatusBadRequest, gin.H{"status": "error", "error": "invalid_state"})
		return
	}
	record, ok := codexDeviceLogins.get(state)
	if !ok {
		c.JSON(http.StatusNotFound, gin.H{"status": "error", "error": "unknown_state"})
		return
	}

	status := record.status
	if status == codexDeviceStatusPending && !IsOAuthSessionPending(state, "codex") {
		// Cancelled through oauth-session; the poller is stopping.
		status = codexDeviceStatusCancelled
	}
	body := gin.H{
		"state":      state,
		"status":     status,
		"expires_at": record.expiresAt.UTC().Format(time.RFC3339),
	}
	switch status {
	case codexDeviceStatusPending:
		body["verification_uri"] = record.verificationURI
		body["user_code"] = record.userCode
	case codexDeviceStatusDone:
		body["account"] = record.account
	case codexDeviceStatusFailed, codexDeviceStatusExpired:
		body["error"] = record.errorCode
		body["message"] = record.message
	}
	c.JSON(http.StatusOK, body)
}

// RespondCodexBrowserLoginRemoved answers a request of the removed Codex
// browser login (infra-v2 I-000026) with 410 Gone and points to the device
// login. It starts and writes nothing.
func RespondCodexBrowserLoginRemoved(c *gin.Context) {
	c.JSON(http.StatusGone, gin.H{
		"status":       "error",
		"error":        "codex_browser_login_removed",
		"message":      "The Codex browser login is removed; use the device login.",
		"device_login": "POST /v0/management/codex-device-login",
	})
}
