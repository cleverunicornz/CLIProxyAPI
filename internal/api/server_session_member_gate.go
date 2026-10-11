package api

import (
	"bytes"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	sdkaccess "github.com/router-for-me/CLIProxyAPI/v8/sdk/access"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/api/handlers"
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

// sessionMemberGateEnabled reports whether the current configuration turns the session member gate on.
func (s *Server) sessionMemberGateEnabled() bool {
	cfg := s.getConfig()
	return cfg != nil && cfg.SessionMemberGate.Enabled
}

// clientAuthMiddleware authenticates the client API routes; with the gate on, a failure is the gate's 403.
func (s *Server) clientAuthMiddleware() gin.HandlerFunc {
	return accessAuthMiddleware(s.accessManager, false, s.sessionMemberGateEnabled)
}

// sessionMemberRouteGate refuses, while the gate is on, every client API route outside sessionMemberGateRoutes.
func (s *Server) sessionMemberRouteGate() gin.HandlerFunc {
	return func(c *gin.Context) {
		if !s.sessionMemberGateEnabled() {
			c.Next()
			return
		}
		if _, ok := sessionMemberGateRoutes[c.Request.Method+" "+c.FullPath()]; ok {
			if c.Request.Method == http.MethodPost && !sessionMemberCheckRawBody(c) {
				return
			}
			c.Next()
			return
		}
		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "session member gate: this route is not served to sessions; inference is served only for the session's member model on the chat, messages and responses routes"})
	}
}

// sessionMemberCheckRawBody runs the gate's strict body check on the client's own body, decoded once from its
// Content-Encoding, before any route converts it (legacy completions, a Responses-format chat body). The handler then
// reads exactly that body. It answers the refusal itself and reports false when the request must stop.
func sessionMemberCheckRawBody(c *gin.Context) bool {
	member := ""
	if raw, ok := c.Get("accessMetadata"); ok {
		if metadata, okMetadata := raw.(map[string]string); okMetadata {
			member = strings.TrimSpace(metadata[sdkaccess.MetadataSessionMember])
		}
	}
	if member == "" {
		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "session member gate: this gateway serves inference only to a session's member, and the request has no session member"})
		return false
	}
	body, err := handlers.ReadRequestBody(c)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "session member gate: the request body cannot be read"})
		return false
	}
	if reason := handlers.SessionMemberBodyError(member, body); reason != "" {
		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "session member gate: " + reason})
		return false
	}
	c.Request.Body = io.NopCloser(bytes.NewReader(body))
	c.Request.ContentLength = int64(len(body))
	c.Request.Header.Del("Content-Encoding")
	c.Request.Header.Set("Content-Length", strconv.Itoa(len(body)))
	return true
}
