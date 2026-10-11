package api

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	proxyconfig "github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	runtimeexecutor "github.com/router-for-me/CLIProxyAPI/v8/internal/runtime/executor"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	"github.com/tidwall/gjson"
)

// Regression tests for the validator's findings F1-F5 on CLIProxyAPI #10 at 7ae8687b (a216/W-5), adapted from the
// validator's reproductions: duplicate model fields, aliases, a stale identity, identity failures that were not 403,
// and tools that make the upstream use another model. Every gate refusal is a 403 with no upstream call.

// memberGateKubeMode lets a test change what the fake Kubernetes API answers after the harness starts.
func memberGateKubeMode(h *memberGateHarness) *atomic.Value {
	mode := &atomic.Value{}
	mode.Store("")
	original := h.kube.server.Config.Handler
	h.kube.server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		m := mode.Load().(string)
		if strings.HasSuffix(r.URL.Path, "/tokenreviews") && m != "" {
			h.kube.reviews.Add(1)
			switch m {
			case "api-error":
				http.Error(w, "fake unavailable", http.StatusInternalServerError)
				return
			case "expired":
				_ = json.NewEncoder(w).Encode(map[string]any{"status": map[string]any{"authenticated": false}})
				return
			case "wrong-namespace", "wrong-service-account", "wrong-audience":
				user, audience := "system:serviceaccount:agent-sessions-v2:agent-session", memberGateAudience
				switch m {
				case "wrong-namespace":
					user = "system:serviceaccount:other:agent-session"
				case "wrong-service-account":
					user = "system:serviceaccount:agent-sessions-v2:other"
				case "wrong-audience":
					audience = "other"
				}
				_ = json.NewEncoder(w).Encode(map[string]any{"status": map[string]any{"authenticated": true,
					"audiences": []string{audience}, "user": map[string]any{"username": user, "extra": map[string][]string{
						"authentication.kubernetes.io/pod-name": {"session-claude"},
						"authentication.kubernetes.io/pod-uid":  {"uid-claude"}}}}})
				return
			}
		}
		if strings.Contains(r.URL.Path, "/pods/") && m != "" {
			switch m {
			case "deleted":
				h.kube.podReads.Add(1)
				http.Error(w, `{"kind":"Status","code":404}`, http.StatusNotFound)
				return
			case "pod-api-error":
				h.kube.podReads.Add(1)
				http.Error(w, "fake unavailable", http.StatusServiceUnavailable)
				return
			case "uid-mismatch", "malformed-member", "missing-member":
				h.kube.podReads.Add(1)
				uid, member := "uid-claude", "claude/claude-opus-5-5"
				switch m {
				case "uid-mismatch":
					uid = "uid-replacement"
				case "malformed-member":
					member = "claude//bad member"
				case "missing-member":
					member = ""
				}
				_ = json.NewEncoder(w).Encode(map[string]any{"metadata": map[string]any{"uid": uid,
					"annotations": map[string]string{"cvu.cleverunicorn.io/member": member}}})
				return
			}
		}
		original.ServeHTTP(w, r)
	})
	return mode
}

// recordingUpstream is a provider endpoint that records every request body it receives.
type recordingUpstream struct {
	server *httptest.Server
	mu     sync.Mutex
	bodies [][]byte
}

func newRecordingUpstream(t *testing.T) *recordingUpstream {
	t.Helper()
	u := &recordingUpstream{}
	u.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		u.mu.Lock()
		u.bodies = append(u.bodies, raw)
		u.mu.Unlock()
		var payload map[string]any
		_ = json.Unmarshal(raw, &payload)
		model, _ := payload["model"].(string)
		switch {
		case strings.HasSuffix(r.URL.Path, "/compact"):
			w.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprint(w, `{"id":"fake","object":"response.compaction","output":[]}`)
		case strings.HasSuffix(r.URL.Path, "/v1/messages/count_tokens"):
			w.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprint(w, `{"input_tokens":3}`)
		case strings.HasSuffix(r.URL.Path, "/v1/messages"):
			w.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprint(w, `{"id":"fake","type":"message","role":"assistant","model":"`+model+`","content":[{"type":"text","text":"ok"}],"stop_reason":"end_turn","usage":{"input_tokens":1,"output_tokens":1}}`)
		default:
			w.Header().Set("Content-Type", "text/event-stream")
			_, _ = fmt.Fprint(w, `data: {"type":"response.completed","response":{"id":"fake","object":"response","status":"completed","model":"`+model+`","output":[]}}`+"\n\n")
		}
	}))
	t.Cleanup(u.server.Close)
	return u
}

func (u *recordingUpstream) received() [][]byte {
	u.mu.Lock()
	defer u.mu.Unlock()
	return append([][]byte(nil), u.bodies...)
}

// useRealExecutor replaces the harness's fake executor of a family with the real provider executor pointed at a
// recording upstream, so the test sees the payload that would leave the gateway.
func useRealExecutor(t *testing.T, h *memberGateHarness, family string) *recordingUpstream {
	t.Helper()
	upstream := newRecordingUpstream(t)
	switch family {
	case "codex":
		h.server.handlers.AuthManager.RegisterExecutor(runtimeexecutor.NewCodexExecutor(h.server.cfg))
	case "claude":
		h.server.handlers.AuthManager.RegisterExecutor(runtimeexecutor.NewClaudeExecutor(h.server.cfg))
	}
	_, err := h.server.handlers.AuthManager.Register(context.Background(), &auth.Auth{ID: "member-gate-" + family,
		Provider: family, Status: auth.StatusActive,
		Attributes: map[string]string{"api_key": "fake-upstream-key", "base_url": upstream.server.URL}})
	if err != nil {
		t.Fatalf("register %s credential: %v", family, err)
	}
	return upstream
}

func dialMemberGateWebsocket(t *testing.T, h *memberGateHarness, path, token string) *websocket.Conn {
	t.Helper()
	downstream := httptest.NewServer(h.server.engine)
	t.Cleanup(downstream.Close)
	conn, resp, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(downstream.URL, "http")+path,
		http.Header{"Authorization": {"Bearer " + token}})
	if err != nil {
		status := 0
		if resp != nil {
			status = resp.StatusCode
		}
		t.Fatalf("dial %s: %v (status %d)", path, err, status)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

// nextTerminalEvent reads frames until an error or a completed response, and returns it.
func nextTerminalEvent(t *testing.T, conn *websocket.Conn) []byte {
	t.Helper()
	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	for {
		_, payload, err := conn.ReadMessage()
		if err != nil {
			t.Fatalf("read before an error or completed event: %v", err)
		}
		if kind := gjson.GetBytes(payload, "type").String(); kind == "error" || kind == "response.completed" {
			return payload
		}
	}
}

// F1: a body naming the model more than once (or under another spelling of the key) is ambiguous: the gate checked
// one value and a provider may read another. It is refused before any upstream call.
func TestSessionMemberGateRefusesAmbiguousModelFields(t *testing.T) {
	codexBodies := map[string]string{
		"duplicate key":     `{"model":"gpt-6-astra","model":"gpt-5.5-codex","input":"hi"}`,
		"duplicate member":  `{"model":"gpt-6-astra","model":"gpt-6-astra","input":"hi"}`,
		"another case":      `{"model":"gpt-6-astra","Model":"gpt-5.5-codex","input":"hi"}`,
		"escaped key":       `{"model":"gpt-6-astra","model":"gpt-5.5-codex","input":"hi"}`,
		"not a string":      `{"model":["gpt-6-astra","gpt-5.5-codex"],"input":"hi"}`,
		"streaming":         `{"model":"gpt-6-astra","model":"gpt-5.5-codex","input":"hi","stream":true}`,
		"another body type": `{"model":"gpt-6-astra","input":"hi","model":"gpt-5.5-codex"}`,
	}
	for _, path := range []string{"/v1/responses", "/v1/responses/compact", "/backend-api/codex/responses",
		"/backend-api/codex/responses/compact"} {
		for name, body := range codexBodies {
			if strings.HasSuffix(path, "/compact") && strings.Contains(body, `"stream":true`) {
				continue
			}
			t.Run(path+" "+name, func(t *testing.T) {
				h := newMemberGateHarness(t, true)
				upstream := useRealExecutor(t, h, "codex")
				requireMemberRefusal(t, h.do(t, http.MethodPost, path, codexSessionToken, body), path+" "+name)
				if got := upstream.received(); len(got) != 0 {
					t.Fatalf("the upstream received %d requests: %s", len(got), got[0])
				}
			})
		}
	}
	for _, path := range []string{"/v1/messages", "/v1/messages/count_tokens"} {
		for _, stream := range []string{"", `,"stream":true`} {
			if stream != "" && strings.HasSuffix(path, "count_tokens") {
				continue
			}
			t.Run(path+stream, func(t *testing.T) {
				h := newMemberGateHarness(t, true)
				upstream := useRealExecutor(t, h, "claude")
				body := `{"model":"claude-opus-5-5","model":"claude-sonnet-5-5","max_tokens":16,"messages":[{"role":"user","content":"hi"}]` + stream + `}`
				requireMemberRefusal(t, h.do(t, http.MethodPost, path, claudeSessionToken, body), path+stream)
				if got := upstream.received(); len(got) != 0 {
					t.Fatalf("the upstream received %d requests: %s", len(got), got[0])
				}
			})
		}
	}
}

func TestSessionMemberGateRefusesAmbiguousModelFieldsOnTheWebsocket(t *testing.T) {
	for _, path := range []string{"/v1/responses", "/backend-api/codex/responses"} {
		t.Run(path, func(t *testing.T) {
			h := newMemberGateHarness(t, true)
			upstream := useRealExecutor(t, h, "codex")
			conn := dialMemberGateWebsocket(t, h, path, codexSessionToken)
			if err := conn.WriteMessage(websocket.TextMessage, []byte(`{"type":"response.create","model":"gpt-6-astra","model":"gpt-5.5-codex","input":[]}`)); err != nil {
				t.Fatal(err)
			}
			event := nextTerminalEvent(t, conn)
			if gjson.GetBytes(event, "status").Int() != http.StatusForbidden || !strings.Contains(string(event), "session member") {
				t.Fatalf("event = %s, want the session member gate's 403", event)
			}
			if got := upstream.received(); len(got) != 0 {
				t.Fatalf("the upstream received %d requests: %s", len(got), got[0])
			}
		})
	}
}

// F2: the member's model must be what runs upstream, after every alias and routing step.
func TestSessionMemberGateRefusesAliasesToAnotherModel(t *testing.T) {
	for _, family := range []string{"codex", "claude"} {
		t.Run(family, func(t *testing.T) {
			h := newMemberGateHarness(t, true)
			own, other, token, path, body := "gpt-6-astra", "gpt-5.5-codex", codexSessionToken, "/v1/responses", responsesRequest("gpt-6-astra")
			executor := h.codex
			if family == "claude" {
				own, other, token, path, body = "claude-opus-5-5", "claude-sonnet-5-5", claudeSessionToken, "/v1/messages", claudeMessage("claude-opus-5-5")
				executor = h.claude
			}
			h.server.handlers.AuthManager.SetOAuthModelAlias(map[string][]proxyconfig.OAuthModelAlias{family: {{Name: other, Alias: own, ForceMapping: true}}})
			requireMemberRefusal(t, h.do(t, http.MethodPost, path, token, body), family+" alias "+own+" -> "+other)
			if got := executor.calls(); len(got) != 0 {
				t.Fatalf("%s executor ran %v, want nothing", family, got)
			}
		})
	}
}

// F3: no identity outlives the API server's answer: a token it stops accepting, a deleted pod or a replaced pod is
// refused on the next request.
func TestSessionMemberGateRefusesOnceTheIdentityIsGone(t *testing.T) {
	for _, mode := range []string{"expired", "deleted", "uid-mismatch"} {
		t.Run(mode, func(t *testing.T) {
			h := newMemberGateHarness(t, true)
			kube := memberGateKubeMode(h)
			if rec := h.do(t, http.MethodPost, "/v1/messages", claudeSessionToken, claudeMessage("claude-opus-5-5")); rec.Code != http.StatusOK {
				t.Fatalf("first request: status = %d; body %s", rec.Code, rec.Body.String())
			}
			kube.Store(mode)
			requireMemberRefusal(t, h.do(t, http.MethodPost, "/v1/messages", claudeSessionToken, claudeMessage("claude-opus-5-5")), "after "+mode)
			if got := h.claude.calls(); len(got) != 1 {
				t.Fatalf("claude executor ran %v, want only the first request", got)
			}
		})
	}
}

// F3: a websocket is authenticated once, at the upgrade; each response.create frame is verified again.
func TestSessionMemberGateReverifiesEachWebsocketFrame(t *testing.T) {
	for _, mode := range []string{"expired", "deleted", "uid-mismatch"} {
		t.Run(mode, func(t *testing.T) {
			h := newMemberGateHarness(t, true)
			upstream := useRealExecutor(t, h, "codex")
			kube := memberGateKubeMode(h)
			conn := dialMemberGateWebsocket(t, h, "/v1/responses", codexSessionToken)
			if err := conn.WriteMessage(websocket.TextMessage, []byte(`{"type":"response.create","model":"gpt-6-astra","input":[]}`)); err != nil {
				t.Fatal(err)
			}
			if event := nextTerminalEvent(t, conn); gjson.GetBytes(event, "type").String() != "response.completed" {
				t.Fatalf("first frame: %s", event)
			}
			kube.Store(mode)
			if err := conn.WriteMessage(websocket.TextMessage, []byte(`{"type":"response.create","model":"gpt-6-astra","input":[]}`)); err != nil {
				t.Fatal(err)
			}
			event := nextTerminalEvent(t, conn)
			if gjson.GetBytes(event, "status").Int() != http.StatusForbidden || !strings.Contains(string(event), "session member") {
				t.Fatalf("second frame after %s: %s, want the session member gate's 403", mode, event)
			}
			if got := upstream.received(); len(got) != 1 {
				t.Fatalf("the upstream received %d requests, want only the first frame's", len(got))
			}
		})
	}
}

// F4: with the gate on, every identity that does not resolve to a session member is refused with 403, and nothing
// reaches an upstream.
func TestSessionMemberGateRefusesEveryUnresolvedIdentityWith403(t *testing.T) {
	for _, mode := range []string{"expired", "deleted", "wrong-audience", "wrong-namespace", "wrong-service-account",
		"uid-mismatch", "missing-member", "malformed-member", "api-error", "pod-api-error", "no-key", "unknown-key"} {
		t.Run(mode, func(t *testing.T) {
			h := newMemberGateHarness(t, true)
			memberGateKubeMode(h).Store(mode)
			token := claudeSessionToken
			switch mode {
			case "no-key":
				token = ""
			case "unknown-key":
				token = "fake-unknown-key"
			}
			requireMemberRefusal(t, h.do(t, http.MethodPost, "/v1/messages", token, claudeMessage("claude-opus-5-5")), mode)
			if n := len(h.claude.calls()) + len(h.codex.calls()); n != 0 {
				t.Fatalf("%d upstream calls, want none", n)
			}
		})
	}
}

// F5: a tool or option that makes the upstream use another model is refused: any tool that names a model of its own,
// such as Anthropic's advisor tool, and a stored Responses prompt template.
func TestSessionMemberGateRefusesToolsThatChooseAnotherModel(t *testing.T) {
	cases := []struct{ name, path, token, body string }{
		{"a tool naming its own model", "/v1/responses", codexSessionToken,
			`{"model":"gpt-6-astra","input":"hi","tools":[{"type":"web_search","model":"gpt-5.5-codex"}]}`},
		{"a forced tool naming its own model", "/v1/responses", codexSessionToken,
			`{"model":"gpt-6-astra","input":"hi","tool_choice":{"type":"web_search","model":"gpt-5.5-codex"}}`},
		{"a stored prompt template", "/v1/responses", codexSessionToken,
			`{"model":"gpt-6-astra","input":"hi","prompt":{"id":"pmpt_1","version":"2"}}`},
		{"claude advisor tool", "/v1/messages", claudeSessionToken,
			`{"model":"claude-opus-5-5","max_tokens":16,"messages":[{"role":"user","content":"hi"}],"tools":[{"type":"advisor_20260301","name":"advisor","model":"claude-sonnet-5-5"}]}`},
		{"claude advisor tool without a model", "/v1/messages", claudeSessionToken,
			`{"model":"claude-opus-5-5","max_tokens":16,"messages":[{"role":"user","content":"hi"}],"tools":[{"type":"advisor_20260301","name":"advisor"}]}`},
		{"claude tool naming the member", "/v1/messages", claudeSessionToken,
			`{"model":"claude-opus-5-5","max_tokens":16,"messages":[{"role":"user","content":"hi"}],"tools":[{"type":"custom","name":"x","model":"claude-opus-5-5","input_schema":{"type":"object"}}]}`},
		{"a second tools key", "/v1/responses", codexSessionToken,
			`{"model":"gpt-6-astra","input":"hi","tools":[],"tools":[{"type":"web_search","model":"gpt-5.5-codex"}]}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newMemberGateHarness(t, true)
			requireMemberRefusal(t, h.do(t, http.MethodPost, tc.path, tc.token, tc.body), tc.name)
			if n := len(h.claude.calls()) + len(h.codex.calls()); n != 0 {
				t.Fatalf("%d upstream calls, want none", n)
			}
		})
	}
}

// F5: the Responses image_generation tool runs an image model. The Codex CLI sends it by default, so it is not refused:
// with the gate on the gateway strips it from tools and tool_choice before the upstream call and never adds it. A
// function tool whose argument schema has a property called model is not a model choice.
func TestSessionMemberGateSendsNoImageToolUpstream(t *testing.T) {
	cases := []struct{ name, path, body string }{
		{"no tools", "/v1/responses", `{"model":"gpt-6-astra","input":"hi"}`},
		{"a function tool with a model argument", "/v1/responses",
			`{"model":"gpt-6-astra","input":"hi","tools":[{"type":"function","name":"spawn_agent","parameters":{"type":"object","properties":{"model":{"type":"string"}}}}]}`},
		{"the image tool naming its model, forced", "/v1/responses",
			`{"model":"gpt-6-astra","input":"make an image","tools":[{"type":"image_generation","action":"generate","model":"gpt-image-2"}],"tool_choice":{"type":"image_generation"}}`},
		{"the image tool", "/backend-api/codex/responses",
			`{"model":"gpt-6-astra","input":"make an image","tools":[{"type":"image_generation"}]}`},
		{"the image tool on a stream", "/v1/responses",
			`{"model":"gpt-6-astra","input":"make an image","tools":[{"type":"image_generation","model":"gpt-image-2"}],"stream":true}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newMemberGateHarness(t, true)
			upstream := useRealExecutor(t, h, "codex")
			rec := h.do(t, http.MethodPost, tc.path, codexSessionToken, tc.body)
			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d; body %s", rec.Code, rec.Body.String())
			}
			got := upstream.received()
			if len(got) != 1 {
				t.Fatalf("the upstream received %d requests, want 1", len(got))
			}
			if model := gjson.GetBytes(got[0], "model").String(); model != "gpt-6-astra" {
				t.Fatalf("upstream model = %q, want gpt-6-astra", model)
			}
			if strings.Contains(string(got[0]), "image_generation") || strings.Contains(string(got[0]), "gpt-image") {
				t.Fatalf("an image tool or model reached the upstream: %s", got[0])
			}
		})
	}
}
