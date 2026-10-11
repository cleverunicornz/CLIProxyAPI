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
		return nil, fmt.Errorf("codex device flow did not return required fields")
	}

	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = codexDeviceTimeout
	}
	interval := opts.PollInterval
	if interval <= 0 {
		interval = parseCodexDevicePollInterval(userCodeResp.Interval)
	}

	return &CodexDeviceLogin{
		VerificationURL: codexDeviceVerificationURL,
		UserCode:        userCode,
		ExpiresAt:       time.Now().Add(timeout),
		deviceAuthID:    deviceAuthID,
		interval:        interval,
	}, nil
}

// CompleteCodexDeviceLogin polls OpenAI until the person signing in confirms
// the user code, then exchanges the authorization code for tokens and builds
// the auth record the CLI device login stores. It ends with ctx's error when
// ctx is cancelled, and with one of the ErrCodexDevice errors otherwise.
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

	tokenResp, err := pollCodexDeviceToken(ctx, opts.httpClient(cfg), login)
	if err != nil {
		return nil, err
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
			return nil, ctxErr
		}
		return nil, fmt.Errorf("%w: %w", ErrCodexDeviceExchangeFailed, codex.NewAuthenticationError(codex.ErrCodeExchangeFailed, err))
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
		return nil, fmt.Errorf("failed to request codex device code: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read codex device code response: %w", err)
	}

	if !codexDeviceIsSuccessStatus(resp.StatusCode) {
		trimmed := strings.TrimSpace(string(respBody))
		if resp.StatusCode == http.StatusNotFound {
			return nil, fmt.Errorf("codex device endpoint is unavailable (status %d)", resp.StatusCode)
		}
		if trimmed == "" {
			trimmed = "empty response body"
		}
		return nil, fmt.Errorf("codex device code request failed with status %d: %s", resp.StatusCode, trimmed)
	}

	var parsed codexDeviceUserCodeResponse
	if err := json.Unmarshal(respBody, &parsed); err != nil {
		return nil, fmt.Errorf("failed to decode codex device code response: %w", err)
	}

	return &parsed, nil
}

// pollCodexDeviceToken polls OpenAI's device-token endpoint until it issues
// the authorization code. OpenAI answers 403 or 404 while the login is
// pending; any other non-success status ends the login.
func pollCodexDeviceToken(ctx context.Context, client *http.Client, login *CodexDeviceLogin) (*codexDeviceTokenResponse, error) {
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

		switch {
		case codexDeviceIsSuccessStatus(resp.StatusCode):
			var parsed codexDeviceTokenResponse
			if err := json.Unmarshal(respBody, &parsed); err != nil {
				return nil, ErrCodexDeviceInvalidResponse
			}
			return &parsed, nil
		case resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusNotFound:
			wait := min(login.interval, time.Until(login.ExpiresAt))
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
		default:
			return nil, fmt.Errorf("%w with status %d", ErrCodexDeviceRejected, resp.StatusCode)
		}
	}
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
