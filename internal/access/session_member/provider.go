// Package sessionmember authenticates v2 session pods by their projected ServiceAccount token and resolves each
// one to its session's member (fork-only).
//
// The pod's token is verified by a Kubernetes TokenReview for the configured audience; the review names the pod
// the token is bound to, and the live pod's member annotation (written only by the dashboard and immutable after
// create) is the member. A harness can present only its own pod's token, so it can claim no other member.
//
// Nothing is cached: every request (and every websocket frame, through the registered resolver) is reviewed and
// its pod read again, so a token the API server stops accepting, or a deleted or replaced pod, is refused at once.
package sessionmember

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"

	internalconfig "github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	sdkaccess "github.com/router-for-me/CLIProxyAPI/v8/sdk/access"
	sdkconfig "github.com/router-for-me/CLIProxyAPI/v8/sdk/config"
	log "github.com/sirupsen/logrus"
)

// ProviderType is the access provider type and identifier.
const ProviderType = "session-member"

// AuthErrorCodeForbidden marks a verified caller that has no session member: the manager returns it as is.
const AuthErrorCodeForbidden sdkaccess.AuthErrorCode = "session_member_forbidden"

const (
	defaultTokenFile = "/var/run/secrets/kubernetes.io/serviceaccount/token"
	defaultCAFile    = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
	maxResponseBytes = 1 << 20
	podNameExtra     = "authentication.kubernetes.io/pod-name"
	podUIDExtra      = "authentication.kubernetes.io/pod-uid"
)

// memberPattern is the member form admission and the dashboard accept: an optional harness, then the model.
var memberPattern = regexp.MustCompile(`^([a-z0-9-]+/)?[a-z0-9]([a-z0-9.-]*[a-z0-9])?$`)

// Register installs the provider and its resolver when the gate is enabled and removes them otherwise.
func Register(cfg *sdkconfig.SDKConfig) {
	if cfg == nil || !cfg.SessionMemberGate.Enabled {
		sdkaccess.UnregisterProvider(ProviderType)
		sdkaccess.SetSessionMemberResolver(nil)
		return
	}
	p := newProvider(cfg.SessionMemberGate)
	sdkaccess.RegisterProvider(ProviderType, p)
	sdkaccess.SetSessionMemberResolver(p.resolveRequest)
}

type provider struct {
	cfg       internalconfig.SessionMemberGateConfig
	server    string
	tokenFile string
	caFile    string

	clientOnce sync.Once
	client     *http.Client
	clientErr  error
}

func newProvider(cfg internalconfig.SessionMemberGateConfig) *provider {
	p := &provider{
		cfg:       cfg,
		server:    strings.TrimRight(strings.TrimSpace(cfg.APIServer), "/"),
		tokenFile: strings.TrimSpace(cfg.TokenFile),
		caFile:    strings.TrimSpace(cfg.CAFile),
	}
	if p.server == "" {
		if host, port := os.Getenv("KUBERNETES_SERVICE_HOST"), os.Getenv("KUBERNETES_SERVICE_PORT"); host != "" && port != "" {
			p.server = "https://" + net.JoinHostPort(host, port)
		}
	}
	if p.tokenFile == "" {
		p.tokenFile = defaultTokenFile
	}
	if p.caFile == "" {
		p.caFile = defaultCAFile
	}
	return p
}

func (p *provider) Identifier() string { return ProviderType }

func (p *provider) Authenticate(ctx context.Context, r *http.Request) (*sdkaccess.Result, *sdkaccess.AuthError) {
	token, source := presentedToken(r)
	if !looksLikeJWT(token) {
		return nil, sdkaccess.NewNotHandledError()
	}
	if errConfig := p.configError(); errConfig != nil {
		log.Errorf("session member gate: %v", errConfig)
		return nil, sdkaccess.NewInternalAuthError("session member gate is misconfigured", errConfig)
	}
	result, authErr := p.resolve(ctx, token)
	if authErr != nil {
		return nil, authErr
	}
	result.Metadata["source"] = source
	return result, nil
}

// resolveRequest resolves the request's session token to its member again (sdkaccess.SessionMemberResolver).
func (p *provider) resolveRequest(ctx context.Context, r *http.Request) (string, *sdkaccess.AuthError) {
	result, authErr := p.Authenticate(ctx, r)
	if authErr != nil {
		return "", authErr
	}
	return result.Metadata[sdkaccess.MetadataSessionMember], nil
}

func (p *provider) configError() error {
	var missing []string
	if strings.TrimSpace(p.cfg.Audience) == "" {
		missing = append(missing, "audience")
	}
	if strings.TrimSpace(p.cfg.Namespace) == "" {
		missing = append(missing, "namespace")
	}
	if strings.TrimSpace(p.cfg.ServiceAccount) == "" {
		missing = append(missing, "service-account")
	}
	if p.server == "" {
		missing = append(missing, "api-server (not in a cluster)")
	}
	if len(missing) > 0 {
		return fmt.Errorf("missing %s", strings.Join(missing, ", "))
	}
	return nil
}

// resolve verifies the token and reads its pod's member.
func (p *provider) resolve(ctx context.Context, token string) (*sdkaccess.Result, *sdkaccess.AuthError) {
	audience := strings.TrimSpace(p.cfg.Audience)
	namespace := strings.TrimSpace(p.cfg.Namespace)

	review, errReview := p.tokenReview(ctx, token, audience)
	if errReview != nil {
		log.Errorf("session member gate: token review failed: %v", errReview)
		return nil, sdkaccess.NewInternalAuthError("session member gate could not verify the token", errReview)
	}
	if !review.Status.Authenticated || review.Status.Error != "" || !contains(review.Status.Audiences, audience) {
		log.Warn("session member gate: the API server refused a session token")
		return nil, sdkaccess.NewInvalidCredentialError()
	}
	wantUser := "system:serviceaccount:" + namespace + ":" + strings.TrimSpace(p.cfg.ServiceAccount)
	if review.Status.User.Username != wantUser {
		return nil, forbidden(fmt.Sprintf("session member gate: %s is not a session ServiceAccount; inference is served only to a session's member", review.Status.User.Username))
	}
	podName := first(review.Status.User.Extra[podNameExtra])
	podUID := first(review.Status.User.Extra[podUIDExtra])
	if podName == "" || podUID == "" {
		return nil, forbidden("session member gate: the token is not bound to a session pod, so it has no session member")
	}

	pod, found, errPod := p.getPod(ctx, namespace, podName)
	if errPod != nil {
		log.Errorf("session member gate: reading pod %s/%s failed: %v", namespace, podName, errPod)
		return nil, sdkaccess.NewInternalAuthError("session member gate could not read the session pod", errPod)
	}
	if !found || pod.Metadata.UID != podUID {
		log.Warnf("session member gate: pod %s/%s is gone or replaced", namespace, podName)
		return nil, sdkaccess.NewInvalidCredentialError()
	}
	member := strings.TrimSpace(pod.Metadata.Annotations[p.cfg.Annotation()])
	if len(member) > 128 || !memberPattern.MatchString(member) {
		return nil, forbidden(fmt.Sprintf("session member gate: pod %s/%s has no valid session member (%s)", namespace, podName, p.cfg.Annotation()))
	}
	return &sdkaccess.Result{
		Provider:  ProviderType,
		Principal: namespace + "/" + podName,
		Metadata:  map[string]string{sdkaccess.MetadataSessionMember: member},
	}, nil
}

type tokenReview struct {
	Status struct {
		Authenticated bool     `json:"authenticated"`
		Error         string   `json:"error"`
		Audiences     []string `json:"audiences"`
		User          struct {
			Username string              `json:"username"`
			Extra    map[string][]string `json:"extra"`
		} `json:"user"`
	} `json:"status"`
}

type podObject struct {
	Metadata struct {
		UID         string            `json:"uid"`
		Annotations map[string]string `json:"annotations"`
	} `json:"metadata"`
}

func (p *provider) tokenReview(ctx context.Context, token, audience string) (*tokenReview, error) {
	body, errMarshal := json.Marshal(map[string]any{
		"apiVersion": "authentication.k8s.io/v1",
		"kind":       "TokenReview",
		"spec":       map[string]any{"token": token, "audiences": []string{audience}},
	})
	if errMarshal != nil {
		return nil, errMarshal
	}
	status, payload, errDo := p.do(ctx, http.MethodPost, "/apis/authentication.k8s.io/v1/tokenreviews", body)
	if errDo != nil {
		return nil, errDo
	}
	if status != http.StatusOK && status != http.StatusCreated {
		return nil, fmt.Errorf("TokenReview returned status %d", status)
	}
	var review tokenReview
	if errDecode := json.Unmarshal(payload, &review); errDecode != nil {
		return nil, fmt.Errorf("decoding TokenReview: %w", errDecode)
	}
	return &review, nil
}

func (p *provider) getPod(ctx context.Context, namespace, name string) (*podObject, bool, error) {
	path := "/api/v1/namespaces/" + url.PathEscape(namespace) + "/pods/" + url.PathEscape(name)
	status, payload, errDo := p.do(ctx, http.MethodGet, path, nil)
	if errDo != nil {
		return nil, false, errDo
	}
	if status == http.StatusNotFound {
		return nil, false, nil
	}
	if status != http.StatusOK {
		return nil, false, fmt.Errorf("pod read returned status %d", status)
	}
	var pod podObject
	if errDecode := json.Unmarshal(payload, &pod); errDecode != nil {
		return nil, false, fmt.Errorf("decoding pod: %w", errDecode)
	}
	return &pod, true, nil
}

// do calls the API server with the gateway's own ServiceAccount token, read on every call so rotation applies.
func (p *provider) do(ctx context.Context, method, path string, body []byte) (int, []byte, error) {
	client, errClient := p.httpClient()
	if errClient != nil {
		return 0, nil, errClient
	}
	ownToken, errToken := os.ReadFile(p.tokenFile)
	if errToken != nil {
		return 0, nil, fmt.Errorf("reading the gateway's ServiceAccount token: %w", errToken)
	}
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	req, errRequest := http.NewRequestWithContext(ctx, method, p.server+path, reader)
	if errRequest != nil {
		return 0, nil, errRequest
	}
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(string(ownToken)))
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, errDo := client.Do(req)
	if errDo != nil {
		return 0, nil, errDo
	}
	defer func() {
		if errClose := resp.Body.Close(); errClose != nil {
			log.Errorf("session member gate: closing API response: %v", errClose)
		}
	}()
	payload, errRead := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if errRead != nil {
		return 0, nil, errRead
	}
	return resp.StatusCode, payload, nil
}

func (p *provider) httpClient() (*http.Client, error) {
	p.clientOnce.Do(func() {
		caPEM, errRead := os.ReadFile(p.caFile)
		if errRead != nil {
			p.clientErr = fmt.Errorf("reading the cluster CA: %w", errRead)
			return
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caPEM) {
			p.clientErr = errors.New("the cluster CA file holds no certificate")
			return
		}
		transport := http.DefaultTransport.(*http.Transport).Clone()
		transport.Proxy = nil
		transport.TLSClientConfig = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
		p.client = &http.Client{Transport: transport}
	})
	return p.client, p.clientErr
}

// presentedToken returns the credential as a bearer token or an Anthropic-style API key.
func presentedToken(r *http.Request) (string, string) {
	if r == nil {
		return "", ""
	}
	if header := strings.TrimSpace(r.Header.Get("Authorization")); header != "" {
		if scheme, value, ok := strings.Cut(header, " "); ok && strings.EqualFold(scheme, "bearer") {
			return strings.TrimSpace(value), "authorization"
		}
	}
	if key := strings.TrimSpace(r.Header.Get("X-Api-Key")); key != "" {
		return key, "x-api-key"
	}
	return "", ""
}

// looksLikeJWT reports whether a credential has a JWT's form: three segments and a JSON header naming alg.
func looksLikeJWT(token string) bool {
	parts := strings.Split(token, ".")
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
		return false
	}
	header, errDecode := base64.RawURLEncoding.DecodeString(parts[0])
	if errDecode != nil {
		return false
	}
	var fields map[string]any
	if json.Unmarshal(header, &fields) != nil {
		return false
	}
	_, ok := fields["alg"]
	return ok
}

func forbidden(message string) *sdkaccess.AuthError {
	return &sdkaccess.AuthError{Code: AuthErrorCodeForbidden, Message: message, StatusCode: http.StatusForbidden}
}

func first(values []string) string {
	if len(values) == 0 {
		return ""
	}
	return strings.TrimSpace(values[0])
}

func contains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
