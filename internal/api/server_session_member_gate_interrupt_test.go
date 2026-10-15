package api

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	runtimeexec "github.com/router-for-me/CLIProxyAPI/v8/internal/runtime/executor"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	"github.com/tidwall/gjson"
)

// Merge regression for upstream v8.0.29's response.interrupt (router-for-me/CLIProxyAPI#6456, PR #6457 /
// 6331b38; the late-interrupt race d318bcc) composed with the fork's session member gate. The gate and the
// interrupt handling share one frame reader
// (sdk/api/handlers/openai/openai_responses_websocket_input.go): the gate decides first, so an interrupt frame
// must pass the gate (it names no model and no tool) and reach the upstream, and the Codex turn and the
// connection must survive it. The upstream tests cover the interrupt path with the gate off; this is the
// gate-on path the fork serves.
func TestSessionMemberGateInterruptMidStreamSurvives(t *testing.T) {
	for _, steering := range []bool{false, true} {
		t.Run(fmt.Sprintf("steering_%t", steering), func(t *testing.T) {
			h := newMemberGateHarness(t, true)
			h.server.cfg.Codex.ResponseSteering = steering
			h.server.cfg.CodexResponseSteering = steering
			h.server.handlers.Cfg.CodexResponseSteering = steering

			interrupt := []byte(`{"type":"response.interrupt","response_id":"r1","mode":"discard_partial_items"}`)
			var mu sync.Mutex
			var creates, interrupts int
			interruptSeen := make(chan []byte, 1)
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				c, err := (&websocket.Upgrader{}).Upgrade(w, r, nil)
				if err != nil {
					t.Error(err)
					return
				}
				defer c.Close()
				_ = c.SetReadDeadline(time.Now().Add(10 * time.Second))
				for n := 1; ; n++ {
					_, p, errRead := c.ReadMessage()
					if errRead != nil {
						return
					}
					switch gjson.GetBytes(p, "type").String() {
					case "response.create":
						mu.Lock()
						creates++
						turn := creates
						mu.Unlock()
						c.WriteMessage(websocket.TextMessage, []byte(fmt.Sprintf(`{"type":"response.created","response":{"id":"r%d","output":[]}}`, turn)))
						if turn > 1 {
							// Keep the upstream socket open: the gateway must stay
							// usable for the frame after this turn.
							c.WriteMessage(websocket.TextMessage, []byte(fmt.Sprintf(`{"type":"response.completed","response":{"id":"r%d","status":"completed","output":[]}}`, turn)))
						}
					case "response.interrupt":
						mu.Lock()
						interrupts++
						mu.Unlock()
						select {
						case interruptSeen <- append([]byte(nil), p...):
						default:
						}
						// The upstream answers an interrupt by ending that turn.
						c.WriteMessage(websocket.TextMessage, []byte(`{"type":"response.incomplete","response":{"id":"r1","status":"incomplete","incomplete_details":{"reason":"interrupted"},"output":[]}}`))
					}
				}
			}))
			defer upstream.Close()

			h.server.handlers.AuthManager.RegisterExecutor(runtimeexec.NewCodexAutoExecutor(h.server.cfg))
			if _, err := h.server.handlers.AuthManager.Register(context.Background(), &auth.Auth{
				ID:       "member-gate-codex",
				Provider: "codex",
				Status:   auth.StatusActive,
				Attributes: map[string]string{
					"api_key":    "A295_FAKE_UPSTREAM_KEY",
					"base_url":   upstream.URL,
					"websockets": "true",
				},
			}); err != nil {
				t.Fatal(err)
			}

			c := dialMemberGateWebsocket(t, h, "/v1/responses", codexSessionToken)

			// Turn 1: the member's own model. The upstream holds the turn open.
			if errWrite := c.WriteMessage(websocket.TextMessage, []byte(`{"type":"response.create","model":"gpt-6-astra","input":[]}`)); errWrite != nil {
				t.Fatal(errWrite)
			}
			awaitEvent(t, c, "response.created")

			// The interrupt arrives mid-stream and must reach the upstream unchanged.
			if errWrite := c.WriteMessage(websocket.TextMessage, interrupt); errWrite != nil {
				t.Fatal(errWrite)
			}
			select {
			case got := <-interruptSeen:
				if !bytes.Equal(got, interrupt) {
					t.Fatalf("the interrupt reached the upstream changed: %s", got)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("the session member gate or the handler swallowed a mid-stream response.interrupt")
			}
			awaitEvent(t, c, "response.incomplete")

			// The connection and the gateway survived: a second turn completes.
			if errWrite := c.WriteMessage(websocket.TextMessage, []byte(`{"type":"response.create","model":"gpt-6-astra","input":[]}`)); errWrite != nil {
				t.Fatal(errWrite)
			}
			awaitEvent(t, c, "response.completed")

			// The gate still refuses a frame that names another model, after the interrupt.
			if errWrite := c.WriteMessage(websocket.TextMessage, []byte(`{"type":"response.create","model":"gpt-5.5-codex","input":[]}`)); errWrite != nil {
				t.Fatal(errWrite)
			}
			v := nextTerminalEvent(t, c)
			if gjson.GetBytes(v, "status").Int() != 403 {
				t.Fatalf("the gate let another model through after an interrupt: %s", v)
			}
			mu.Lock()
			defer mu.Unlock()
			if interrupts != 1 {
				t.Fatalf("upstream saw %d interrupts, want 1", interrupts)
			}
		})
	}
}

// awaitEvent reads frames until one of the given type arrives.
func awaitEvent(t *testing.T, conn *websocket.Conn, want string) []byte {
	t.Helper()
	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	for {
		_, payload, err := conn.ReadMessage()
		if err != nil {
			t.Fatalf("waiting for %s: %v", want, err)
		}
		if kind := gjson.GetBytes(payload, "type").String(); kind == want {
			return payload
		}
	}
}
