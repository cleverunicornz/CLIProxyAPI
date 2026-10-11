package auth

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/auth/codex"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/browser"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/util"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	log "github.com/sirupsen/logrus"
)

const (
	codexLoginModeMetadataKey             = "codex_login_mode"
	codexLoginModeDevice                  = "device"
	codexDeviceUserCodeURL                = "https://auth.openai.com/api/accounts/deviceauth/usercode"
	codexDeviceTokenURL                   = "https://auth.openai.com/api/accounts/deviceauth/token"
	codexDeviceVerificationURL            = "https://auth.openai.com/codex/device"
	codexDeviceTokenExchangeRedirectURI   = "https://auth.openai.com/deviceauth/callback"
	codexDeviceTimeout                    = 15 * time.Minute
	codexDeviceDefaultPollIntervalSeconds = 5
)

type codexDeviceUserCodeRequest struct {
	ClientID string `json:"client_id"`
}

type codexDeviceUserCodeResponse struct {
	DeviceAuthID string          `json:"device_auth_id"`
	UserCode     string          `json:"user_code"`
	UserCodeAlt  string          `json:"usercode"`
	Interval     json.RawMessage `json:"interval"`
}

type codexDeviceTokenRequest struct {
	DeviceAuthID string `json:"device_auth_id"`
	UserCode     string `json:"user_code"`
}

type codexDeviceTokenResponse struct {
	AuthorizationCode string `json:"authorization_code"`
	CodeVerifier      string `json:"code_verifier"`
	CodeChallenge     string `json:"code_challenge"`
}

func shouldUseCodexDeviceFlow(opts *LoginOptions) bool {
	if opts == nil || opts.Metadata == nil {
		return false
	}
	return strings.EqualFold(strings.TrimSpace(opts.Metadata[codexLoginModeMetadataKey]), codexLoginModeDevice)
}

// Errors a Codex device login can end with. Their texts carry no code,
// token or provider response body.
var (
	ErrCodexDeviceExpired         = errors.New("the device code expired before the login was completed")
	ErrCodexDeviceRejected        = errors.New("OpenAI ended the device login")
	ErrCodexDeviceUnreachable     = errors.New("OpenAI's device login could not be reached")
	ErrCodexDeviceInvalidResponse = errors.New("OpenAI's device login answered without the authorization code")
	ErrCodexDeviceExchangeFailed  = errors.New("exchanging the device authorization code for tokens failed")
	ErrCodexDeviceMissingAccount  = errors.New("codex token storage missing account information")
)

// CodexDeviceStartError is a device-code request OpenAI refused or did not
// answer. It keeps the HTTP status alone (0 when no answer arrived), never
// the response body or transport detail.
type CodexDeviceStartError struct {
	Status int
}

func (e *CodexDeviceStartError) Error() string {
	switch {
	case e.Status == 0:
		return "OpenAI's device-code endpoint could not be reached"
	case e.Status == http.StatusNotFound:
		return "OpenAI's device-code endpoint is unavailable (HTTP 404)"
	case codexDeviceIsSuccessStatus(e.Status):
		return fmt.Sprintf("OpenAI answered the device-code request without a user code (HTTP %d)", e.Status)
	default:
		return fmt.Sprintf("OpenAI refused the device-code request (HTTP %d)", e.Status)
	}
}

// codexDeviceSlowDownStep is RFC 8628 section 3.5's interval increase on slow_down.
const codexDeviceSlowDownStep = 5 * time.Second

// CodexDeviceOptions tunes a Codex device login started outside the CLI.
// Zero values use the CLI's behavior: the proxy-aware client from the
// configuration, the 15-minute limit and OpenAI's polling interval.
type CodexDeviceOptions struct {
	HTTPClient   *http.Client
	Timeout      time.Duration
	PollInterval time.Duration
	// SlowDownStep is how much a slow_down answer raises the polling interval
	// (RFC 8628 section 3.5: 5 seconds by default).
	SlowDownStep time.Duration
}

// CodexDeviceLogin is a Codex device login OpenAI has issued a user code for.
// VerificationURL and UserCode are for the person signing in; the device
// auth id, which with the user code lets anyone poll for the authorization
// code, stays unexported.
type CodexDeviceLogin struct {
	VerificationURL string
	UserCode        string
	ExpiresAt       time.Time

	deviceAuthID string
	interval     time.Duration
	slowDownStep time.Duration
}

func (o CodexDeviceOptions) httpClient(cfg *config.Config) *http.Client {
	if o.HTTPClient != nil {
		return o.HTTPClient
	}
	return util.SetProxy(&cfg.SDKConfig, &http.Client{})
}

func (o CodexDeviceOptions) codexAuth(cfg *config.Config) *codex.CodexAuth {
	if o.HTTPClient != nil {
		return codex.NewCodexAuthWithHTTPClient(o.HTTPClient)
	}
	return codex.NewCodexAuth(cfg)
}

// StartCodexDeviceLogin asks OpenAI for a device user code. The login
// expires after opts.Timeout (15 minutes by default).
func StartCodexDeviceLogin(ctx context.Context, cfg *config.Config, opts CodexDeviceOptions) (*CodexDeviceLogin, error) {
	if cfg == nil {
		return nil, fmt.Errorf("cliproxy auth: configuration is required")
	}
	if ctx == nil {
		ctx = context.Background()
	}

	userCodeResp, err := requestCodexDeviceUserCode(ctx, opts.httpClient(cfg))
	if err != nil {
		return nil, err
	}

	userCode := strings.TrimSpace(userCodeResp.UserCode)
	if userCode == "" {
		userCode = strings.TrimSpace(userCodeResp.UserCodeAlt)
	}
	deviceAuthID := strings.TrimSpace(userCodeResp.DeviceAuthID)
	if userCode == "" || deviceAuthID == "" {
		return nil, &CodexDeviceStartError{Status: http.StatusOK}
	}

	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = codexDeviceTimeout
	}
	interval := opts.PollInterval
	if interval <= 0 {
		interval = parseCodexDevicePollInterval(userCodeResp.Interval)
	}

	slowDownStep := opts.SlowDownStep
	if slowDownStep <= 0 {
		slowDownStep = codexDeviceSlowDownStep
	}

	return &CodexDeviceLogin{
		VerificationURL: codexDeviceVerificationURL,
		UserCode:        userCode,
		ExpiresAt:       time.Now().Add(timeout),
		deviceAuthID:    deviceAuthID,
		interval:        interval,
		slowDownStep:    slowDownStep,
	}, nil
}

// CompleteCodexDeviceLogin polls OpenAI until the person signing in confirms
// the user code, then exchanges the authorization code for tokens and builds
// the auth record the CLI device login stores. Polling and the exchange run
// under the login's expiry: a request still in flight at ExpiresAt is
// abandoned and the login ends with ErrCodexDeviceExpired. It ends with ctx's
// error when ctx is cancelled, and with one of the ErrCodexDevice errors
// otherwise; no error carries a provider response body.
func (a *CodexAuthenticator) CompleteCodexDeviceLogin(ctx context.Context, cfg *config.Config, login *CodexDeviceLogin, opts CodexDeviceOptions) (*coreauth.Auth, error) {
	if cfg == nil {
		return nil, fmt.Errorf("cliproxy auth: configuration is required")
	}
	if login == nil {
		return nil, fmt.Errorf("codex device login is required")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	parent := ctx
	ctx, cancel := context.WithDeadline(parent, login.ExpiresAt)
	defer cancel()
	// expired reports err as the login's expiry when the deadline, not the
	// caller, ended it.
	expired := func(err error) error {
		if parent.Err() == nil && (errors.Is(err, context.DeadlineExceeded) || !time.Now().Before(login.ExpiresAt)) {
			return ErrCodexDeviceExpired
		}
		return err
	}

	tokenResp, err := pollCodexDeviceToken(ctx, opts.httpClient(cfg), login)
	if err != nil {
		return nil, expired(err)
	}

	authCode := strings.TrimSpace(tokenResp.AuthorizationCode)
	codeVerifier := strings.TrimSpace(tokenResp.CodeVerifier)
	codeChallenge := strings.TrimSpace(tokenResp.CodeChallenge)
	if authCode == "" || codeVerifier == "" || codeChallenge == "" {
		return nil, ErrCodexDeviceInvalidResponse
	}

	authSvc := opts.codexAuth(cfg)
	authBundle, err := authSvc.ExchangeCodeForTokensWithRedirect(
		ctx,
		authCode,
		codexDeviceTokenExchangeRedirectURI,
		&codex.PKCECodes{
			CodeVerifier:  codeVerifier,
			CodeChallenge: codeChallenge,
		},
	)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, expired(ctxErr)
		}
		// The exchange error carries the token endpoint's body; it stays here.
		return nil, ErrCodexDeviceExchangeFailed
	}
	if !time.Now().Before(login.ExpiresAt) {
		return nil, ErrCodexDeviceExpired
	}

	return a.buildAuthRecord(authSvc, authBundle)
}

func (a *CodexAuthenticator) loginWithDeviceFlow(ctx context.Context, cfg *config.Config, opts *LoginOptions) (*coreauth.Auth, error) {
	login, err := StartCodexDeviceLogin(ctx, cfg, CodexDeviceOptions{})
	if err != nil {
		return nil, err
	}

	fmt.Println("Starting Codex device authentication...")
	fmt.Printf("Codex device URL: %s\n", login.VerificationURL)
	fmt.Printf("Codex device code: %s\n", login.UserCode)

	if !opts.NoBrowser {
		if !browser.IsAvailable() {
			log.Warn("No browser available; please open the device URL manually")
		} else if errOpen := browser.OpenURL(login.VerificationURL); errOpen != nil {
			log.Warnf("Failed to open browser automatically: %v", errOpen)
		}
	}

	return a.CompleteCodexDeviceLogin(ctx, cfg, login, CodexDeviceOptions{})
}

func requestCodexDeviceUserCode(ctx context.Context, client *http.Client) (*codexDeviceUserCodeResponse, error) {
	body, err := json.Marshal(codexDeviceUserCodeRequest{ClientID: codex.ClientID})
	if err != nil {
		return nil, fmt.Errorf("failed to encode codex device request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, codexDeviceUserCodeURL, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("failed to create codex device request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, ctxErr
		}
		return nil, &CodexDeviceStartError{}
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, &CodexDeviceStartError{Status: resp.StatusCode}
	}
	if !codexDeviceIsSuccessStatus(resp.StatusCode) {
		return nil, &CodexDeviceStartError{Status: resp.StatusCode}
	}

	var parsed codexDeviceUserCodeResponse
	if err := json.Unmarshal(respBody, &parsed); err != nil {
		return nil, &CodexDeviceStartError{Status: resp.StatusCode}
	}

	return &parsed, nil
}

// pollCodexDeviceToken polls OpenAI's device-token endpoint until it issues
// the authorization code, as RFC 8628 section 3.5 asks: OpenAI's 403 or 404
// and authorization_pending mean pending; slow_down raises the interval by
// the login's slow-down step; expired_token ends the login as expired; any
// other answer ends it as rejected. The response body is read only for its
// error code.
func pollCodexDeviceToken(ctx context.Context, client *http.Client, login *CodexDeviceLogin) (*codexDeviceTokenResponse, error) {
	interval := login.interval
	for {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, ctxErr
		}
		if !time.Now().Before(login.ExpiresAt) {
			return nil, ErrCodexDeviceExpired
		}

		body, err := json.Marshal(codexDeviceTokenRequest{
			DeviceAuthID: login.deviceAuthID,
			UserCode:     login.UserCode,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to encode codex device poll request: %w", err)
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodPost, codexDeviceTokenURL, bytes.NewReader(body))
		if err != nil {
			return nil, fmt.Errorf("failed to create codex device poll request: %w", err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json")

		resp, err := client.Do(req)
		if err != nil {
			if ctxErr := ctx.Err(); ctxErr != nil {
				return nil, ctxErr
			}
			return nil, ErrCodexDeviceUnreachable
		}

		respBody, readErr := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if readErr != nil {
			if ctxErr := ctx.Err(); ctxErr != nil {
				return nil, ctxErr
			}
			return nil, ErrCodexDeviceUnreachable
		}

		if codexDeviceIsSuccessStatus(resp.StatusCode) {
			var parsed codexDeviceTokenResponse
			if err := json.Unmarshal(respBody, &parsed); err != nil {
				return nil, ErrCodexDeviceInvalidResponse
			}
			return &parsed, nil
		}
		switch codexDeviceErrorCode(respBody) {
		case "authorization_pending":
		case "slow_down":
			interval += login.slowDownStep
		case "expired_token":
			return nil, ErrCodexDeviceExpired
		case "access_denied":
			return nil, fmt.Errorf("%w with status %d", ErrCodexDeviceRejected, resp.StatusCode)
		default:
			if resp.StatusCode != http.StatusForbidden && resp.StatusCode != http.StatusNotFound {
				return nil, fmt.Errorf("%w with status %d", ErrCodexDeviceRejected, resp.StatusCode)
			}
		}

		wait := min(interval, time.Until(login.ExpiresAt))
		if wait < 0 {
			wait = 0
		}
		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil, ctx.Err()
		case <-timer.C:
		}
	}
}

// codexDeviceErrorCode reads the OAuth error code of a device-token answer:
// {"error":"slow_down"} or {"error":{"code":"slow_down"}}; "" otherwise.
func codexDeviceErrorCode(body []byte) string {
	var envelope struct {
		Error json.RawMessage `json:"error"`
	}
	if json.Unmarshal(body, &envelope) != nil || len(envelope.Error) == 0 {
		return ""
	}
	var code string
	if json.Unmarshal(envelope.Error, &code) == nil {
		return strings.TrimSpace(code)
	}
	var object struct {
		Code string `json:"code"`
	}
	if json.Unmarshal(envelope.Error, &object) == nil {
		return strings.TrimSpace(object.Code)
	}
	return ""
}

func parseCodexDevicePollInterval(raw json.RawMessage) time.Duration {
	defaultInterval := time.Duration(codexDeviceDefaultPollIntervalSeconds) * time.Second
	if len(raw) == 0 {
		return defaultInterval
	}

	var asString string
	if err := json.Unmarshal(raw, &asString); err == nil {
		if seconds, convErr := strconv.Atoi(strings.TrimSpace(asString)); convErr == nil && seconds > 0 {
			return time.Duration(seconds) * time.Second
		}
	}

	var asInt int
	if err := json.Unmarshal(raw, &asInt); err == nil && asInt > 0 {
		return time.Duration(asInt) * time.Second
	}

	return defaultInterval
}

func codexDeviceIsSuccessStatus(code int) bool {
	return code >= 200 && code < 300
}

func (a *CodexAuthenticator) buildAuthRecord(authSvc *codex.CodexAuth, authBundle *codex.CodexAuthBundle) (*coreauth.Auth, error) {
	tokenStorage := authSvc.CreateTokenStorage(authBundle)

	if tokenStorage == nil || tokenStorage.Email == "" {
		return nil, ErrCodexDeviceMissingAccount
	}

	planType := ""
	if tokenStorage.PlanType != "" {
		planType = tokenStorage.PlanType
	}
	hashAccountID := ""
	if tokenStorage.IDToken != "" {
		if claims, errParse := codex.ParseJWTToken(tokenStorage.IDToken); errParse == nil && claims != nil {
			if pt := strings.TrimSpace(claims.CodexAuthInfo.ChatgptPlanType); pt != "" {
				planType = pt
			}
			accountID := strings.TrimSpace(claims.CodexAuthInfo.ChatgptAccountID)
			if accountID != "" {
				digest := sha256.Sum256([]byte(accountID))
				hashAccountID = hex.EncodeToString(digest[:])[:8]
			}
		}
	}
	if planType == "" {
		planType = codex.DefaultPlanType
	}
	tokenStorage.PlanType = planType

	fileName := codex.CredentialFileName(tokenStorage.Email, planType, hashAccountID, true)
	metadata := map[string]any{
		"email":     tokenStorage.Email,
		"plan_type": planType,
	}

	fmt.Println("Codex authentication successful")
	if authBundle.APIKey != "" {
		fmt.Println("Codex API key obtained and stored")
	}

	return &coreauth.Auth{
		ID:       fileName,
		Provider: a.Provider(),
		FileName: fileName,
		Storage:  tokenStorage,
		Metadata: metadata,
		Attributes: map[string]string{
			"plan_type": planType,
		},
	}, nil
}
