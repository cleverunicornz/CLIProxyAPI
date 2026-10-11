package management

import (
	"context"
	"errors"
	"math"
	"net/http"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/auth/codex"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/logging"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/misc"
	sdkAuth "github.com/router-for-me/CLIProxyAPI/v8/sdk/auth"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
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
	// codexDeviceStatusSaving is internal: OpenAI confirmed before expiry and
	// the auth is being stored. It reads as pending.
	codexDeviceStatusSaving = "saving"

	codexDeviceExpiredMessage = "The device code expired before the login was completed"
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
// pending ones until they finish, finished ones for the retention period. It
// is the one state machine of a login. Every transition is a compare-and-set
// under its lock:
//
//	pending -> saving     beginSave, only before expiry
//	pending -> expired    at expiry (also when read), or OpenAI's expired_token
//	pending -> failed     OpenAI or the exchange ended the login
//	pending -> cancelled  cancel
//	saving  -> done       commit, after the auth is stored
//	saving  -> failed     the store refused the auth
//	saving  -> cancelled  cancel; the watcher then removes what the save stored
//
// A finished login never changes again, so a cancel and a commit cannot both
// win, and nothing is saved past expiry or after an accepted cancel.
type codexDeviceLoginStore struct {
	mu      sync.Mutex
	now     func() time.Time
	records map[string]*codexDeviceLoginRecord
}

var codexDeviceLogins = &codexDeviceLoginStore{
	now:     time.Now,
	records: make(map[string]*codexDeviceLoginRecord),
}

func codexDeviceFinished(status string) bool {
	return status != codexDeviceStatusPending && status != codexDeviceStatusSaving
}

func (s *codexDeviceLoginStore) purgeLocked() {
	now := s.now()
	for state, record := range s.records {
		if codexDeviceFinished(record.status) && now.Sub(record.finishedAt) > codexDeviceLoginRetention {
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

// transitionLocked moves record from one of from to status and reports
// whether it did. A finished login hides its user code and stops its poller.
func (s *codexDeviceLoginStore) transitionLocked(record *codexDeviceLoginRecord, from []string, status string, account *codexDeviceAccount, errorCode, message string) bool {
	if !slices.Contains(from, record.status) {
		return false
	}
	record.status = status
	if codexDeviceFinished(status) {
		record.account = account
		record.errorCode = errorCode
		record.message = message
		record.userCode = ""
		record.verificationURI = ""
		record.finishedAt = s.now()
		if record.stop != nil {
			record.stop()
		}
	}
	return true
}

func (s *codexDeviceLoginStore) transition(state string, from []string, status string, account *codexDeviceAccount, errorCode, message string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	record, ok := s.records[state]
	return ok && s.transitionLocked(record, from, status, account, errorCode, message)
}

// expireLocked ends a pending login whose expiry has passed.
func (s *codexDeviceLoginStore) expireLocked(record *codexDeviceLoginRecord) {
	if record.status == codexDeviceStatusPending && !s.now().Before(record.expiresAt) {
		s.transitionLocked(record, []string{codexDeviceStatusPending}, codexDeviceStatusExpired, nil, "expired", codexDeviceExpiredMessage)
	}
}

// beginSave admits the save of a login OpenAI confirmed: only a pending login
// before its expiry. A login past expiry becomes expired instead.
func (s *codexDeviceLoginStore) beginSave(state string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	record, ok := s.records[state]
	if !ok {
		return false
	}
	s.expireLocked(record)
	return s.transitionLocked(record, []string{codexDeviceStatusPending}, codexDeviceStatusSaving, nil, "", "")
}

// cancel ends a pending or saving login; known reports whether state is a
// device login at all.
func (s *codexDeviceLoginStore) cancel(state string) (accepted, known bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	record, ok := s.records[state]
	if !ok {
		return false, false
	}
	s.expireLocked(record)
	return s.transitionLocked(record, []string{codexDeviceStatusPending, codexDeviceStatusSaving}, codexDeviceStatusCancelled, nil, "", ""), true
}

func (s *codexDeviceLoginStore) get(state string) (codexDeviceLoginRecord, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.purgeLocked()
	record, ok := s.records[state]
	if !ok {
		return codexDeviceLoginRecord{}, false
	}
	s.expireLocked(record)
	return *record, true
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

// codexDeviceCredentials orders what device logins do to their stored
// credentials. Logins of the same account share one credential (its file
// name comes from the account), so a cancelled login's rollback must not
// remove, or leave its own stale write over, a credential another login has
// committed meanwhile. Its lock serializes every commit and rollback;
// committed holds, per credential name, the record last committed and when.
var codexDeviceCredentials = struct {
	mu        sync.Mutex
	committed map[string]codexDeviceCommit
}{committed: make(map[string]codexDeviceCommit)}

type codexDeviceCommit struct {
	record *coreauth.Auth
	at     time.Time
}

func codexDeviceAccessToken(auth *coreauth.Auth) string {
	if auth == nil {
		return ""
	}
	if storage, ok := auth.Storage.(*codex.CodexTokenStorage); ok && storage != nil {
		return storage.AccessToken
	}
	token, _ := auth.Metadata["access_token"].(string)
	return token
}

// storedCodexDeviceCredential reads back what the store holds under record's
// credential name: nil when it holds none; ok is false when the store could
// not be read.
func (h *Handler) storedCodexDeviceCredential(ctx context.Context, record *coreauth.Auth) (stored *coreauth.Auth, ok bool) {
	store := h.tokenStoreWithBaseDir()
	if store == nil {
		return nil, false
	}
	auths, errList := store.List(ctx)
	if errList != nil {
		return nil, false
	}
	name := filepath.Base(record.FileName)
	for _, auth := range auths {
		if auth != nil && (filepath.Base(auth.FileName) == name || filepath.Base(auth.ID) == name) {
			return auth, true
		}
	}
	return nil, true
}

// codexDeviceSave is one device login's write of its credential: what the
// store held under that name just before (previous), and when it began.
type codexDeviceSave struct {
	record   *coreauth.Auth
	path     string
	previous *coreauth.Auth
	began    time.Time
}

// rollbackCodexDeviceSaveLocked undoes a cancelled login's save. It touches the
// stored credential only while it is still this login's write, and puts back
// what that write replaced: the credential another login committed after this
// save began, else the credential stored before it, else nothing. Callers hold
// codexDeviceCredentials.mu.
func (h *Handler) rollbackCodexDeviceSaveLocked(ctx context.Context, state string, save codexDeviceSave) {
	stored, ok := h.storedCodexDeviceCredential(ctx, save.record)
	switch {
	case !ok:
		log.WithField("state", state).Warn("codex device login: could not read the stored auth back; the cancelled login's write is left in place")
		return
	case stored == nil || codexDeviceAccessToken(stored) != codexDeviceAccessToken(save.record):
		// Gone already, or another login's credential now: not ours to undo.
		return
	}
	restore := save.previous
	if commit, found := codexDeviceCredentials.committed[filepath.Base(save.record.FileName)]; found && commit.at.After(save.began) {
		restore = commit.record
	}
	if restore == nil {
		h.rollbackSavedTokenRecords(ctx, []string{save.path})
		return
	}
	if _, errSave := h.saveTokenRecord(ctx, restore); errSave != nil {
		log.WithField("state", state).Error("codex device login: failed to put back the auth a cancelled login's write replaced")
	}
}

// StartCodexDeviceLogin starts a Codex device login: POST
// /v0/management/codex-device-login. The answer carries the verification URL
// and the user code to show, never OpenAI's device auth id.
func (h *Handler) StartCodexDeviceLogin(c *gin.Context) {
	random, errState := misc.GenerateRandomState()
	if errState != nil {
		log.Error("codex device login: failed to generate state")
		c.JSON(http.StatusInternalServerError, gin.H{"status": "error", "error": "internal_error"})
		return
	}
	state := codexDeviceStatePrefix + random

	opts := codexDeviceLoginOptions(h.cfg)
	login, errStart := sdkAuth.StartCodexDeviceLogin(c.Request.Context(), h.cfg, opts)
	if errStart != nil {
		// Only the HTTP status leaves this handler, never OpenAI's body.
		message := "OpenAI did not issue a device code"
		if startErr, ok := errors.AsType[*sdkAuth.CodexDeviceStartError](errStart); ok {
			message = startErr.Error()
		}
		log.WithField("reason", message).Warn("codex device login: OpenAI did not issue a device code")
		c.JSON(http.StatusBadGateway, gin.H{"status": "error", "error": "device_code_request_failed", "message": message})
		return
	}

	RegisterOAuthSession(state, "codex")
	ctx := PopulateAuthContext(context.Background(), c)
	runCtx, stop := context.WithCancel(ctx)
	record := &codexDeviceLoginRecord{
		status:          codexDeviceStatusPending,
		verificationURI: login.VerificationURL,
		userCode:        login.UserCode,
		expiresAt:       login.ExpiresAt,
		stop:            stop,
		done:            make(chan struct{}),
	}
	codexDeviceLogins.add(state, record)
	go h.completeCodexDeviceLogin(ctx, runCtx, stop, record.done, state, login, opts)

	log.WithField("state", state).Info("codex device login started")
	c.JSON(http.StatusOK, gin.H{
		"status":           "ok",
		"flow":             "device",
		"state":            state,
		"verification_uri": login.VerificationURL,
		"url":              login.VerificationURL,
		"user_code":        login.UserCode,
		"expires_in":       int(math.Ceil(time.Until(login.ExpiresAt).Seconds())),
		"expires_at":       login.ExpiresAt.UTC().Format(time.RFC3339Nano),
	})
}

// completeCodexDeviceLogin polls OpenAI for one login and stores the auth the
// way the CLI device login does. runCtx ends on a cancel or any other final
// state; the SDK bounds polling and the exchange by the login's expiry. The
// store's transitions decide whether the auth may be saved and kept.
func (h *Handler) completeCodexDeviceLogin(ctx, runCtx context.Context, stop context.CancelFunc, done chan struct{}, state string, login *sdkAuth.CodexDeviceLogin, opts sdkAuth.CodexDeviceOptions) {
	var watchers sync.WaitGroup
	defer close(done)
	defer watchers.Wait()
	defer stop()
	watchers.Go(func() { watchOAuthSessionCancel(runCtx, stop, state, "codex") })
	pending := []string{codexDeviceStatusPending}

	authenticator := sdkAuth.NewCodexAuthenticator()
	record, errComplete := authenticator.CompleteCodexDeviceLogin(runCtx, h.cfg, login, opts)
	if errComplete != nil {
		if errors.Is(errComplete, context.Canceled) {
			// Cancelled through oauth-session, ended elsewhere, or expired when
			// its status was read.
			codexDeviceLogins.transition(state, pending, codexDeviceStatusCancelled, nil, "", "")
			if current, ok := codexDeviceLogins.get(state); ok && current.status == codexDeviceStatusExpired {
				SetOAuthSessionError(state, codexDeviceExpiredMessage)
			}
			return
		}
		status, errorCode, message := classifyCodexDeviceError(errComplete)
		if codexDeviceLogins.transition(state, pending, status, nil, errorCode, message) {
			SetOAuthSessionError(state, message)
			log.WithFields(log.Fields{"state": state, "error_code": errorCode}).Warn("codex device login ended without a login")
		}
		return
	}

	if !codexDeviceLogins.beginSave(state) {
		// Cancelled or expired while OpenAI answered: nothing is saved.
		return
	}
	save := codexDeviceSave{record: record, began: time.Now()}
	if previous, ok := h.storedCodexDeviceCredential(ctx, record); ok {
		save.previous = previous
	}
	savedPath, errSave := h.saveTokenRecord(runCtx, record)
	save.path = savedPath
	if errSave != nil {
		message := "Failed to save authentication tokens"
		if codexDeviceLogins.transition(state, []string{codexDeviceStatusSaving}, codexDeviceStatusFailed, nil, "save_failed", message) {
			SetOAuthSessionError(state, message)
			log.WithField("state", state).Error("codex device login: failed to save the auth")
		}
		if savedPath != "" {
			codexDeviceCredentials.mu.Lock()
			h.rollbackCodexDeviceSaveLocked(ctx, state, save)
			codexDeviceCredentials.mu.Unlock()
		}
		return
	}

	email, _ := record.Metadata["email"].(string)
	planType, _ := record.Metadata["plan_type"].(string)
	account := &codexDeviceAccount{Email: email, PlanType: planType, Name: record.FileName}
	codexDeviceCredentials.mu.Lock()
	defer codexDeviceCredentials.mu.Unlock()
	if !codexDeviceLogins.transition(state, []string{codexDeviceStatusSaving}, codexDeviceStatusDone, account, "", "") {
		// A cancel was accepted while the auth was being stored: undo this
		// login's write, and only this login's.
		h.rollbackCodexDeviceSaveLocked(ctx, state, save)
		log.WithField("state", state).Info("codex device login cancelled during its save; its write was undone")
		return
	}
	// Committed. A cancelled login's late write or rollback may have replaced
	// the credential since this login wrote it: make sure it is this login's.
	if stored, ok := h.storedCodexDeviceCredential(ctx, record); ok && (stored == nil || codexDeviceAccessToken(stored) != codexDeviceAccessToken(record)) {
		if _, errResave := h.saveTokenRecord(ctx, record); errResave != nil {
			log.WithField("state", state).Error("codex device login: failed to store the committed auth again")
		}
	}
	codexDeviceCredentials.committed[filepath.Base(record.FileName)] = codexDeviceCommit{record: record, at: time.Now()}
	CompleteOAuthSession(state)
	log.WithField("state", state).Info("codex device login stored an auth")
}

func classifyCodexDeviceError(err error) (status, errorCode, message string) {
	switch {
	case errors.Is(err, sdkAuth.ErrCodexDeviceExpired):
		return codexDeviceStatusExpired, "expired", codexDeviceExpiredMessage
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
	if status == codexDeviceStatusSaving {
		status = codexDeviceStatusPending
	}
	body := gin.H{
		"state":      state,
		"status":     status,
		"expires_at": record.expiresAt.UTC().Format(time.RFC3339Nano),
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
// login. It starts and writes nothing, and its access-log line carries no
// query: a pasted callback's code is never logged.
func RespondCodexBrowserLoginRemoved(c *gin.Context) {
	logging.OmitGinQueryLogging(c)
	c.JSON(http.StatusGone, gin.H{
		"status":       "error",
		"error":        "codex_browser_login_removed",
		"message":      "The Codex browser login is removed; use the device login.",
		"device_login": "POST /v0/management/codex-device-login",
	})
}
