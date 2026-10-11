package api

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/access"
	proxyconfig "github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/registry"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	coreexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
	"github.com/tidwall/gjson"
)

// The session member gate (fork-only, cvu): a v2 session pod presents its projected ServiceAccount token, the
// gateway resolves the pod's member annotation through the Kubernetes API, and inference is served only for that
// member's model. These tests drive the whole server against a fake Kubernetes API.

const (
	memberGateNamespace      = "agent-sessions-v2"
	memberGateServiceAccount = "agent-session"
	memberGateAudience       = "cliproxy"
	memberGateGatewayToken   = "gateway-own-service-account-token"
	memberGatePlainKey       = "plain-user-key"
)

// fakeJWT shapes an opaque test token like a ServiceAccount JWT (three base64url segments); only the fake API
// server interprets it.
func fakeJWT(name string) string {
	enc := base64.RawURLEncoding
	return enc.EncodeToString([]byte(`{"alg":"RS256","kid":"test"}`)) + "." +
		enc.EncodeToString([]byte(fmt.Sprintf(`{"sub":%q}`, name))) + "." + enc.EncodeToString([]byte("signature"))
}

var (
	claudeSessionToken    = fakeJWT("claude-session")
	codexSessionToken     = fakeJWT("codex-session")
	noMemberSessionToken  = fakeJWT("no-member-session")
	otherAccountToken     = fakeJWT("other-service-account")
	stalePodToken         = fakeJWT("stale-pod")
	wrongAudienceToken    = fakeJWT("wrong-audience")
	unauthenticatedToken  = fakeJWT("unauthenticated")
	memberGateSessionPods = map[string]struct{ uid, member string }{
		"session-claude":    {uid: "uid-claude", member: "claude/claude-opus-5-5"},
		"session-codex":     {uid: "uid-codex", member: "codex/gpt-6-astra"},
		"session-no-member": {uid: "uid-no-member"},
		"session-stale":     {uid: "uid-new"},
	}
)

type memberGateReviewIdentity struct {
	username string
	pod      string
	podUID   string
	audience string
}

var memberGateReviews = map[string]memberGateReviewIdentity{
	claudeSessionToken:   {username: "system:serviceaccount:agent-sessions-v2:agent-session", pod: "session-claude", podUID: "uid-claude", audience: memberGateAudience},
	codexSessionToken:    {username: "system:serviceaccount:agent-sessions-v2:agent-session", pod: "session-codex", podUID: "uid-codex", audience: memberGateAudience},
	noMemberSessionToken: {username: "system:serviceaccount:agent-sessions-v2:agent-session", pod: "session-no-member", podUID: "uid-no-member", audience: memberGateAudience},
	otherAccountToken:    {username: "system:serviceaccount:agent-platform-v2:memory", pod: "memory-0", podUID: "uid-memory", audience: memberGateAudience},
	stalePodToken:        {username: "system:serviceaccount:agent-sessions-v2:agent-session", pod: "session-stale", podUID: "uid-old", audience: memberGateAudience},
	wrongAudienceToken:   {username: "system:serviceaccount:agent-sessions-v2:agent-session", pod: "session-claude", podUID: "uid-claude", audience: "cluster-mcp-memory"},
}

// fakeKubeAPI answers TokenReview and pod reads the way the API server does for the reviews above.
type fakeKubeAPI struct {
	server      *httptest.Server
	tokenFile   string
	caFile      string
	reviews     atomic.Int32
	podReads    atomic.Int32
	mu          sync.Mutex
	lastAudList []string
}

func newFakeKubeAPI(t *testing.T) *fakeKubeAPI {
	t.Helper()
	f := &fakeKubeAPI{}
	mux := http.NewServeMux()
	mux.HandleFunc("/apis/authentication.k8s.io/v1/tokenreviews", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.Header.Get("Authorization") != "Bearer "+memberGateGatewayToken {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		f.reviews.Add(1)
		var review struct {
			Spec struct {
				Token     string   `json:"token"`
				Audiences []string `json:"audiences"`
			} `json:"spec"`
		}
		if err := json.NewDecoder(r.Body).Decode(&review); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		f.mu.Lock()
		f.lastAudList = review.Spec.Audiences
		f.mu.Unlock()
		status := map[string]any{"authenticated": false}
		identity, ok := memberGateReviews[review.Spec.Token]
		if ok && len(review.Spec.Audiences) == 1 && review.Spec.Audiences[0] == identity.audience {
			status = map[string]any{
				"authenticated": true,
				"audiences":     []string{identity.audience},
				"user": map[string]any{
					"username": identity.username,
					"extra": map[string][]string{
						"authentication.kubernetes.io/pod-name": {identity.pod},
						"authentication.kubernetes.io/pod-uid":  {identity.podUID},
					},
				},
			}
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"apiVersion": "authentication.k8s.io/v1",
			"kind":       "TokenReview",
			"status":     status,
		})
	})
	mux.HandleFunc("/api/v1/namespaces/"+memberGateNamespace+"/pods/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.Header.Get("Authorization") != "Bearer "+memberGateGatewayToken {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		f.podReads.Add(1)
		name := strings.TrimPrefix(r.URL.Path, "/api/v1/namespaces/"+memberGateNamespace+"/pods/")
		pod, ok := memberGateSessionPods[name]
		if !ok {
			http.Error(w, `{"kind":"Status","code":404}`, http.StatusNotFound)
			return
		}
		annotations := map[string]string{"cvu.cleverunicorn.io/role": "implementer"}
		if pod.member != "" {
			annotations["cvu.cleverunicorn.io/member"] = pod.member
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"apiVersion": "v1",
			"kind":       "Pod",
			"metadata":   map[string]any{"name": name, "namespace": memberGateNamespace, "uid": pod.uid, "annotations": annotations},
		})
	})
	f.server = httptest.NewTLSServer(mux)
	t.Cleanup(f.server.Close)

	dir := t.TempDir()
	f.tokenFile = filepath.Join(dir, "token")
	if err := os.WriteFile(f.tokenFile, []byte(memberGateGatewayToken+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	f.caFile = filepath.Join(dir, "ca.crt")
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.server.Certificate().Raw})
	if err := os.WriteFile(f.caFile, caPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	return f
}

// memberGateExecutor serves a provider family and records the models it was asked to run.
type memberGateExecutor struct {
	provider string
	mu       sync.Mutex
	models   []string
}

func (e *memberGateExecutor) Identifier() string { return e.provider }

func (e *memberGateExecutor) record(model string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.models = append(e.models, model)
}

func (e *memberGateExecutor) calls() []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]string(nil), e.models...)
}

func (e *memberGateExecutor) Execute(_ context.Context, _ *auth.Auth, req coreexecutor.Request, _ coreexecutor.Options) (coreexecutor.Response, error) {
	e.record(req.Model)
	if e.provider == "claude" {
		return coreexecutor.Response{Payload: []byte(`{"id":"msg_1","type":"message","role":"assistant","model":"` + req.Model + `","content":[{"type":"text","text":"ok"}],"stop_reason":"end_turn","stop_sequence":null,"usage":{"input_tokens":1,"output_tokens":1}}`)}, nil
	}
	return coreexecutor.Response{Payload: []byte(`{"id":"resp_1","object":"response","status":"completed","model":"` + req.Model + `","output":[{"type":"message","id":"msg_1","status":"completed","role":"assistant","content":[{"type":"output_text","text":"ok","annotations":[]}]}],"usage":{"input_tokens":1,"output_tokens":1,"total_tokens":2}}`)}, nil
}

func (e *memberGateExecutor) ExecuteStream(_ context.Context, _ *auth.Auth, req coreexecutor.Request, _ coreexecutor.Options) (*coreexecutor.StreamResult, error) {
	e.record(req.Model)
	return nil, errors.New("streaming is not used by these tests")
}

func (e *memberGateExecutor) Refresh(_ context.Context, a *auth.Auth) (*auth.Auth, error) { return a, nil }

func (e *memberGateExecutor) CountTokens(_ context.Context, _ *auth.Auth, req coreexecutor.Request, _ coreexecutor.Options) (coreexecutor.Response, error) {
	e.record(req.Model)
	return coreexecutor.Response{Payload: []byte(`{"input_tokens":3}`)}, nil
}

func (e *memberGateExecutor) HttpRequest(context.Context, *auth.Auth, *http.Request) (*http.Response, error) {
	return nil, errors.New("not used")
}

type memberGateHarness struct {
	server *Server
	kube   *fakeKubeAPI
	claude *memberGateExecutor
	codex  *memberGateExecutor
}

// newMemberGateHarness starts a server from a v8 YAML config, with the gate on or off, a Claude and a Codex
// credential, and the access providers applied the way a config load applies them.
func newMemberGateHarness(t *testing.T, gateOn bool) *memberGateHarness {
	t.Helper()
	kube := newFakeKubeAPI(t)
	yamlConfig := "config-version: 8\naccess:\n  api-keys:\n    - " + memberGatePlainKey + "\n"
	if gateOn {
		yamlConfig += fmt.Sprintf("  session-member-gate:\n    enabled: true\n    audience: %s\n    namespace: %s\n    service-account: %s\n    api-server: %s\n    token-file: %s\n    ca-file: %s\n",
			memberGateAudience, memberGateNamespace, memberGateServiceAccount, kube.server.URL, kube.tokenFile, kube.caFile)
	}
	cfg, err := proxyconfig.ParseConfigBytes([]byte(yamlConfig))
	if err != nil {
		t.Fatalf("parse config: %v", err)
	}
	server := newTestServerWithConfig(t, cfg)
	if _, err = access.ApplyAccessProviders(server.accessManager, nil, cfg); err != nil {
		t.Fatalf("apply access providers: %v", err)
	}
	t.Cleanup(func() { _, _ = access.ApplyAccessProviders(server.accessManager, nil, &proxyconfig.Config{}) })

	h := &memberGateHarness{server: server, kube: kube, claude: &memberGateExecutor{provider: "claude"}, codex: &memberGateExecutor{provider: "codex"}}
	for _, family := range []struct {
		executor *memberGateExecutor
		models   []string
	}{
		{h.claude, []string{"claude-opus-5-5", "claude-sonnet-5-5"}},
		{h.codex, []string{"gpt-6-astra", "gpt-5.5-codex"}},
	} {
		server.handlers.AuthManager.RegisterExecutor(family.executor)
		credential := &auth.Auth{ID: "member-gate-" + family.executor.provider, Provider: family.executor.provider, Status: auth.StatusActive}
		if _, errRegister := server.handlers.AuthManager.Register(context.Background(), credential); errRegister != nil {
			t.Fatalf("register %s credential: %v", family.executor.provider, errRegister)
		}
		infos := make([]*registry.ModelInfo, 0, len(family.models))
		for _, model := range family.models {
			infos = append(infos, &registry.ModelInfo{ID: model, OwnedBy: family.executor.provider})
		}
		registry.GetGlobalRegistry().RegisterClient(credential.ID, family.executor.provider, infos)
		credentialID := credential.ID
		t.Cleanup(func() { registry.GetGlobalRegistry().UnregisterClient(credentialID) })
	}
	return h
}

func (h *memberGateHarness) do(t *testing.T, method, path, token, body string) *httptest.ResponseRecorder {
	t.Helper()
	var reader io.Reader
	if body != "" {
		reader = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, path, reader)
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	h.server.engine.ServeHTTP(rec, req)
	return rec
}

func claudeMessage(model string) string {
	return fmt.Sprintf(`{"model":%q,"max_tokens":16,"messages":[{"role":"user","content":"hi"}]}`, model)
}

func responsesRequest(model string) string {
	return fmt.Sprintf(`{"model":%q,"input":"hi"}`, model)
}

func chatRequest(model string) string {
	return fmt.Sprintf(`{"model":%q,"messages":[{"role":"user","content":"hi"}]}`, model)
}

func requireMemberRefusal(t *testing.T, rec *httptest.ResponseRecorder, what string) {
	t.Helper()
	if rec.Code != http.StatusForbidden {
		t.Fatalf("%s: status = %d, want 403 from the session member gate; body %s", what, rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "session member") {
		t.Fatalf("%s: body does not name the session member gate: %s", what, rec.Body.String())
	}
}

func TestSessionMemberGateServesTheClaudeMember(t *testing.T) {
	h := newMemberGateHarness(t, true)

	rec := h.do(t, http.MethodPost, "/v1/messages", claudeSessionToken, claudeMessage("claude-opus-5-5"))
	if rec.Code != http.StatusOK {
		t.Fatalf("member model: status = %d, want 200; body %s", rec.Code, rec.Body.String())
	}
	rec = h.do(t, http.MethodPost, "/v1/messages/count_tokens", claudeSessionToken, claudeMessage("claude-opus-5-5"))
	if rec.Code != http.StatusOK {
		t.Fatalf("member count_tokens: status = %d, want 200; body %s", rec.Code, rec.Body.String())
	}
	if got := h.claude.calls(); len(got) != 2 || got[0] != "claude-opus-5-5" || got[1] != "claude-opus-5-5" {
		t.Fatalf("claude executor ran %v, want the member model twice", got)
	}
	h.kube.mu.Lock()
	audiences := h.kube.lastAudList
	h.kube.mu.Unlock()
	if len(audiences) != 1 || audiences[0] != memberGateAudience {
		t.Fatalf("token review audiences = %v, want [%s]", audiences, memberGateAudience)
	}
}

func TestSessionMemberGateRefusesAnotherClaudeModel(t *testing.T) {
	h := newMemberGateHarness(t, true)

	requireMemberRefusal(t, h.do(t, http.MethodPost, "/v1/messages", claudeSessionToken, claudeMessage("claude-sonnet-5-5")), "claude session asking for claude-sonnet-5-5")
	requireMemberRefusal(t, h.do(t, http.MethodPost, "/v1/messages/count_tokens", claudeSessionToken, claudeMessage("claude-sonnet-5-5")), "claude session counting tokens for claude-sonnet-5-5")
	requireMemberRefusal(t, h.do(t, http.MethodPost, "/v1/responses", claudeSessionToken, responsesRequest("gpt-6-astra")), "claude session asking for a Codex model")
	if got := h.claude.calls(); len(got) != 0 {
		t.Fatalf("claude executor ran %v, want nothing", got)
	}
	if got := h.codex.calls(); len(got) != 0 {
		t.Fatalf("codex executor ran %v, want nothing", got)
	}
}

func TestSessionMemberGateServesTheCodexMemberOnly(t *testing.T) {
	h := newMemberGateHarness(t, true)

	rec := h.do(t, http.MethodPost, "/v1/responses", codexSessionToken, responsesRequest("gpt-6-astra"))
	if rec.Code != http.StatusOK {
		t.Fatalf("member model: status = %d, want 200; body %s", rec.Code, rec.Body.String())
	}
	if got := h.codex.calls(); len(got) != 1 || got[0] != "gpt-6-astra" {
		t.Fatalf("codex executor ran %v, want [gpt-6-astra]", got)
	}

	requireMemberRefusal(t, h.do(t, http.MethodPost, "/v1/responses", codexSessionToken, responsesRequest("gpt-5.5-codex")), "codex session asking for gpt-5.5-codex")
	requireMemberRefusal(t, h.do(t, http.MethodPost, "/v1/responses/compact", codexSessionToken, responsesRequest("gpt-5.5-codex")), "codex session compacting with gpt-5.5-codex")
	requireMemberRefusal(t, h.do(t, http.MethodPost, "/backend-api/codex/responses", codexSessionToken, responsesRequest("gpt-5.5-codex")), "codex session on the Codex direct route asking for gpt-5.5-codex")
	requireMemberRefusal(t, h.do(t, http.MethodPost, "/v1/chat/completions", codexSessionToken, chatRequest("gpt-5.5-codex")), "codex session chatting with gpt-5.5-codex")
	requireMemberRefusal(t, h.do(t, http.MethodPost, "/v1/messages", codexSessionToken, claudeMessage("claude-opus-5-5")), "codex session asking for a Claude model")
	if got := h.codex.calls(); len(got) != 1 {
		t.Fatalf("codex executor ran %v after refusals, want only the member request", got)
	}
	if got := h.claude.calls(); len(got) != 0 {
		t.Fatalf("claude executor ran %v, want nothing", got)
	}
}

func TestSessionMemberGateRefusesAnOffMemberModelOnTheResponsesWebsocket(t *testing.T) {
	h := newMemberGateHarness(t, true)
	downstream := httptest.NewServer(h.server.engine)
	defer downstream.Close()

	header := http.Header{}
	header.Set("Authorization", "Bearer "+codexSessionToken)
	conn, resp, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(downstream.URL, "http")+"/v1/responses", header)
	if err != nil {
		status := 0
		if resp != nil {
			status = resp.StatusCode
		}
		t.Fatalf("dial: %v (status %d)", err, status)
	}
	defer func() { _ = conn.Close() }()
	if err = conn.WriteMessage(websocket.TextMessage, []byte(`{"type":"response.create","model":"gpt-5.5-codex","input":[]}`)); err != nil {
		t.Fatalf("write: %v", err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	for {
		_, payload, errRead := conn.ReadMessage()
		if errRead != nil {
			t.Fatalf("read before an error event: %v", errRead)
		}
		if gjson.GetBytes(payload, "type").String() != "error" {
			continue
		}
		if gjson.GetBytes(payload, "status").Int() != http.StatusForbidden || !strings.Contains(string(payload), "session member") {
			t.Fatalf("error event = %s, want the session member gate's 403", payload)
		}
		break
	}
	if got := h.codex.calls(); len(got) != 0 {
		t.Fatalf("codex executor ran %v, want nothing", got)
	}
}

func TestSessionMemberGateRefusesRequestsWithoutAResolvableMember(t *testing.T) {
	h := newMemberGateHarness(t, true)

	requireMemberRefusal(t, h.do(t, http.MethodPost, "/v1/messages", memberGatePlainKey, claudeMessage("claude-opus-5-5")), "a plain client key")
	requireMemberRefusal(t, h.do(t, http.MethodPost, "/v1/responses", memberGatePlainKey, responsesRequest("gpt-6-astra")), "a plain client key on responses")
	requireMemberRefusal(t, h.do(t, http.MethodPost, "/v1/messages", noMemberSessionToken, claudeMessage("claude-opus-5-5")), "a session pod without a member annotation")
	requireMemberRefusal(t, h.do(t, http.MethodPost, "/v1/messages", otherAccountToken, claudeMessage("claude-opus-5-5")), "a token of another ServiceAccount")
	for name, token := range map[string]string{
		"a token bound to a replaced pod": stalePodToken,
		"a token of another audience":     wrongAudienceToken,
		"a token the API server refuses":  unauthenticatedToken,
	} {
		rec := h.do(t, http.MethodPost, "/v1/messages", token, claudeMessage("claude-opus-5-5"))
		if rec.Code != http.StatusUnauthorized && rec.Code != http.StatusForbidden {
			t.Fatalf("%s: status = %d, want 401 or 403; body %s", name, rec.Code, rec.Body.String())
		}
	}
	if got := h.claude.calls(); len(got) != 0 {
		t.Fatalf("claude executor ran %v, want nothing", got)
	}
	if got := h.codex.calls(); len(got) != 0 {
		t.Fatalf("codex executor ran %v, want nothing", got)
	}

	// Listing models is not inference: the readiness probe's plain key keeps it.
	rec := h.do(t, http.MethodGet, "/v1/models", memberGatePlainKey, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("model list with a plain key: status = %d, want 200; body %s", rec.Code, rec.Body.String())
	}
}

func TestSessionMemberGateRefusesRoutesOutsideTheModelCheck(t *testing.T) {
	h := newMemberGateHarness(t, true)

	for _, route := range []struct{ method, path, body string }{
		{http.MethodPost, "/v1/realtime/client_secrets", `{"session":{"type":"realtime","model":"gpt-6-astra"}}`},
		{http.MethodPost, "/v1/live", `{"model":"gpt-6-astra"}`},
		{http.MethodPost, "/v1/alpha/search", `{"model":"gpt-6-astra","query":"x"}`},
		{http.MethodPost, "/backend-api/codex/alpha/search", `{"model":"gpt-6-astra","query":"x"}`},
		{http.MethodPost, "/v1/images/generations", `{"model":"gpt-6-astra","prompt":"x"}`},
		{http.MethodPost, "/v1/videos", `{"model":"gpt-6-astra","prompt":"x"}`},
		{http.MethodPost, "/v1beta/models/gpt-6-astra:generateContent", `{"contents":[]}`},
	} {
		requireMemberRefusal(t, h.do(t, route.method, route.path, codexSessionToken, route.body), route.method+" "+route.path)
	}
	if got := h.codex.calls(); len(got) != 0 {
		t.Fatalf("codex executor ran %v, want nothing", got)
	}
}

func TestSessionMemberGateReusesAReviewWithinItsLifetime(t *testing.T) {
	h := newMemberGateHarness(t, true)

	for i := 0; i < 3; i++ {
		rec := h.do(t, http.MethodPost, "/v1/messages", claudeSessionToken, claudeMessage("claude-opus-5-5"))
		if rec.Code != http.StatusOK {
			t.Fatalf("request %d: status = %d; body %s", i, rec.Code, rec.Body.String())
		}
	}
	if reviews, reads := h.kube.reviews.Load(), h.kube.podReads.Load(); reviews != 1 || reads != 1 {
		t.Fatalf("token reviews = %d, pod reads = %d, want one of each for three requests", reviews, reads)
	}
}

func TestSessionMemberGateOffKeepsClientKeys(t *testing.T) {
	h := newMemberGateHarness(t, false)

	rec := h.do(t, http.MethodPost, "/v1/messages", memberGatePlainKey, claudeMessage("claude-sonnet-5-5"))
	if rec.Code != http.StatusOK {
		t.Fatalf("gate off, plain key: status = %d, want 200; body %s", rec.Code, rec.Body.String())
	}
	if got := h.claude.calls(); len(got) != 1 || got[0] != "claude-sonnet-5-5" {
		t.Fatalf("claude executor ran %v, want [claude-sonnet-5-5]", got)
	}
	if reviews := h.kube.reviews.Load(); reviews != 0 {
		t.Fatalf("token reviews = %d with the gate off, want 0", reviews)
	}
}
