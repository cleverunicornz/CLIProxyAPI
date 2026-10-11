package api

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// sessionMemberGateRoutes are the client API routes left open while the session member gate (fork-only) is on: the
// model lists, and the inference routes whose handlers run the gate's model check on every execution
// (sdk/api/handlers session_member_gate.go). Every other client API route reaches upstream credentials outside that
// check (realtime, live, alpha search, images, videos, Gemini), so with the gate on it is refused.
var sessionMemberGateRoutes = map[string]struct{}{
	"GET /v1/models":                            {},
	"GET /v1/models/*model":                     {},
	"GET /v1beta/models":                        {},
	"POST /v1/chat/completions":                 {},
	"POST /v1/completions":                      {},
	"POST /v1/messages":                         {},
	"POST /v1/messages/count_tokens":            {},
	"GET /v1/responses":                         {},
	"POST /v1/responses":                        {},
	"POST /v1/responses/compact":                {},
	"GET /backend-api/codex/responses":          {},
	"POST /backend-api/codex/responses":         {},
	"POST /backend-api/codex/responses/compact": {},
}

// sessionMemberRouteGate refuses, while the gate is on, every client API route outside sessionMemberGateRoutes.
func (s *Server) sessionMemberRouteGate() gin.HandlerFunc {
	return func(c *gin.Context) {
		cfg := s.getConfig()
		if cfg == nil || !cfg.SessionMemberGate.Enabled {
			c.Next()
			return
		}
		if _, ok := sessionMemberGateRoutes[c.Request.Method+" "+c.FullPath()]; ok {
			c.Next()
			return
		}
		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "session member gate: this route is not served to sessions; inference is served only for the session's member model on the chat, messages and responses routes"})
	}
}
