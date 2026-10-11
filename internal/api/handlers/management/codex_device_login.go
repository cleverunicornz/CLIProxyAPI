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
	// the credential is being staged in memory; a cancel still wins. It reads
	// as pending.
	codexDeviceStatusSaving = "saving"
	// codexDeviceStatusCommitting is internal: the commit has begun and a
	// cancel no longer wins. It reads as pending.
	codexDeviceStatusCommitting = "committing"

	codexDeviceExpiredMessage = "The device code expired before the login was completed"
)

// codexDeviceStagedHook, when set, is called with a login's staged credential,
// before its commit decision; tests hold logins there.
var codexDeviceStagedHook func(ctx context.Context, record *coreauth.Auth)

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
	state           string
	status          string
	verificationURI string
	userCode        string
	expiresAt       time.Time
	finishedAt      time.Time
	account         *codexDeviceAccount
	errorCode       string
	// message is the reason of a failed or expired login, or the note of a
	// done login whose credential is stored but not yet in use.
	message string

	stop context.CancelFunc
	done chan struct{}
}

// codexDeviceLoginStore keeps the device logins of this gateway in memory:
// pending ones until they finish, finished ones for the retention period. It
// is the one state machine of a login. Every transition is a compare-and-set
// under its lock:
//
//	pending    -> saving      beginSave, only before expiry
//	pending    -> expired     at expiry (also when read), or OpenAI's expired_token
//	pending    -> failed      OpenAI or the exchange ended the login
//	pending    -> cancelled   cancel
//	saving     -> cancelled   cancel; the staged credential is dropped
//	saving     -> failed      the credential could not be prepared
//	saving     -> committing  the commit begins; a cancel no longer wins
//	committing -> done        the credential is stored
//	committing -> failed      the store refused the credential
//
// A login's credential is staged in memory until its commit and is handed to
// the token store only in the commit, so nothing of a pending, saving,
// cancelled or expired login is ever written, and nothing is undone. A login
// ends failed only when its write failed before the store of record accepted
// it, leaving what that store leaves behind a refused write: the Postgres and
// object stores nothing (they update their local mirror only after the remote
// write), the file and git stores possibly a local file. Once the store of
// record accepted it, the login is done, even if the local mirror or the
// registration with the running gateway did not follow; the next start (or,
// for a failed registration, the next load) catches them up (see the
// contract's Storage section). A
// finished login never changes again. This record is also the only source of
// the login's legacy get-auth-status answer; no OAuth session is kept beside it.
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
	switch status {
	case codexDeviceStatusPending, codexDeviceStatusSaving, codexDeviceStatusCommitting:
		return false
	}
	return true
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
	record.state = state
	s.records[state] = record
}

// transitionLocked moves the login state from one of from to status and
// reports whether it did. A finished login hides its user code and stops its
// poller.
func (s *codexDeviceLoginStore) transitionLocked(state string, record *codexDeviceLoginRecord, from []string, status string, account *codexDeviceAccount, errorCode, message string) bool {
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
	return ok && s.transitionLocked(state, record, from, status, account, errorCode, message)
}

// expireLocked ends a pending login whose expiry has passed.
func (s *codexDeviceLoginStore) expireLocked(record *codexDeviceLoginRecord) {
	if record.status == codexDeviceStatusPending && !s.now().Before(record.expiresAt) {
		s.transitionLocked(record.state, record, []string{codexDeviceStatusPending}, codexDeviceStatusExpired, nil, "expired", codexDeviceExpiredMessage)
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
	return s.transitionLocked(state, record, []string{codexDeviceStatusPending}, codexDeviceStatusSaving, nil, "", "")
}

// cancel ends a pending or saving login, whose credential is at most staged;
// a committing login's commit wins. known reports whether state is a device
// login at all.
func (s *codexDeviceLoginStore) cancel(state string) (accepted, known bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	record, ok := s.records[state]
	if !ok {
		return false, false
	}
	s.expireLocked(record)
	return s.transitionLocked(state, record, []string{codexDeviceStatusPending, codexDeviceStatusSaving}, codexDeviceStatusCancelled, nil, "", ""), true
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

// codexDeviceCommitSlots holds one commit slot per stored credential name,
// that is per account: commits of one account run one at a time, each storing
// its credential and publishing done as one step, so the login that commits
// last is the one stored. Commits of other accounts do not wait. A login
// waiting for its slot leaves the queue when it is cancelled.
var codexDeviceCommitSlots sync.Map // credential name -> chan struct{} (capacity 1)

func codexDeviceCommitSlot(name string) chan struct{} {
	slot, _ := codexDeviceCommitSlots.LoadOrStore(name, make(chan struct{}, 1))
	return slot.(chan struct{})
}

// legacyStatus is the device login's answer to get-auth-status, derived from
// its record for as long as the record is kept.
func (r codexDeviceLoginRecord) legacyStatus() gin.H {
	switch r.status {
	case codexDeviceStatusDone:
		return gin.H{"status": "ok"}
	case codexDeviceStatusFailed, codexDeviceStatusExpired:
		return gin.H{"status": "error", "error": r.message}
	case codexDeviceStatusCancelled:
		return gin.H{"status": "error", "error": "unknown or expired state"}
	default:
		return gin.H{"status": "wait"}
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
	defer close(done)
	defer stop()
	pending := []string{codexDeviceStatusPending}

	authenticator := sdkAuth.NewCodexAuthenticator()
	record, errComplete := authenticator.CompleteCodexDeviceLogin(runCtx, h.cfg, login, opts)
	if errComplete != nil {
		if errors.Is(errComplete, context.Canceled) {
			// Cancelled through oauth-session, or expired when its status was
			// read; the transition that ended it stopped the poller.
			codexDeviceLogins.transition(state, pending, codexDeviceStatusCancelled, nil, "", "")
			return
		}
		status, errorCode, message := classifyCodexDeviceError(errComplete)
		if codexDeviceLogins.transition(state, pending, status, nil, errorCode, message) {
			log.WithFields(log.Fields{"state": state, "error_code": errorCode}).Warn("codex device login ended without a login")
		}
		return
	}

	if !codexDeviceLogins.beginSave(state) {
		// Cancelled or expired while OpenAI answered: nothing is staged.
		return
	}
	saving := []string{codexDeviceStatusSaving}
	// Stage: prepare the credential in memory. Nothing reaches the token store
	// or the runtime before the commit.
	prepared, errPrepare := h.prepareTokenRecord(runCtx, record)
	if errPrepare == nil && codexDeviceStagedHook != nil {
		codexDeviceStagedHook(runCtx, record)
	}
	if errPrepare == nil && runCtx.Err() != nil {
		errPrepare = runCtx.Err()
	}
	if errPrepare != nil {
		if runCtx.Err() != nil {
			// Cancelled while staging.
			codexDeviceLogins.transition(state, saving, codexDeviceStatusCancelled, nil, "", "")
			return
		}
		if codexDeviceLogins.transition(state, saving, codexDeviceStatusFailed, nil, "save_failed", "Failed to save authentication tokens") {
			log.WithField("state", state).Error("codex device login: failed to prepare the auth")
		}
		return
	}
	h.commitCodexDeviceLogin(ctx, runCtx, state, prepared)
}

// commitCodexDeviceLogin stores a staged credential and publishes done, as one
// step holding its account's commit slot: the login must still be saving (not
// cancelled), the store must accept the credential, and done follows only
// then. A login cancelled while it waits for the slot leaves at once,
// dropping its staged credential. A refused store write ends the login
// failed.
func (h *Handler) commitCodexDeviceLogin(ctx, runCtx context.Context, state string, prepared *preparedTokenRecord) {
	slot := codexDeviceCommitSlot(filepath.Base(prepared.record.FileName))
	select {
	case slot <- struct{}{}:
	case <-runCtx.Done():
		// Cancelled while queued behind another commit of its account.
		return
	}
	defer func() { <-slot }()
	if !codexDeviceLogins.transition(state, []string{codexDeviceStatusSaving}, codexDeviceStatusCommitting, nil, "", "") {
		// Cancelled while staged: its credential is dropped, never stored.
		return
	}
	committing := []string{codexDeviceStatusCommitting}
	_, errPersist := h.persistTokenRecord(ctx, prepared)
	// Only a failure before the store of record accepted the credential is a
	// refused write.
	if errPersist != nil && !errors.Is(errPersist, errStoredButNotRegistered) {
		codexDeviceLogins.transition(state, committing, codexDeviceStatusFailed, nil, "save_failed", "Failed to save authentication tokens")
		log.WithField("state", state).Error("codex device login: the token store refused the auth")
		return
	}
	// note records, on a done login, what did not follow the store write; it is
	// kept in the login's record and logged, and is not part of any response.
	note := ""
	switch {
	case errors.Is(errPersist, coreauth.ErrMirrorNotUpdated):
		// The store of record accepted the credential: it is stored, so done.
		note = "stored in the store of record; the local mirror was not updated and the running gateway did not register it; both catch up at the gateway's next start"
	case errPersist != nil:
		// Stored, so done; the running gateway loads it the next time it loads
		// its auth store (its watcher or a restart).
		note = "stored; registration with the running gateway failed; it is used after the next load"
	}
	if note != "" {
		log.WithField("state", state).WithField("note", note).Error("codex device login: the auth is stored, but not yet in use")
	}
	record := prepared.record
	email, _ := record.Metadata["email"].(string)
	planType, _ := record.Metadata["plan_type"].(string)
	account := &codexDeviceAccount{Email: email, PlanType: planType, Name: record.FileName}
	codexDeviceLogins.transition(state, committing, codexDeviceStatusDone, account, "", note)
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
	if status == codexDeviceStatusSaving || status == codexDeviceStatusCommitting {
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
