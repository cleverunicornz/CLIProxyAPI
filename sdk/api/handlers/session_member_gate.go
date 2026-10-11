package handlers

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/interfaces"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/thinking"
	sdkaccess "github.com/router-for-me/CLIProxyAPI/v8/sdk/access"
)

// SessionMemberGateError enforces the session member gate (fork-only) on every model execution: with the gate on,
// a request runs only when its caller resolved to a session member and the requested model is that member's model.
func (h *BaseAPIHandler) SessionMemberGateError(ctx context.Context, modelName string) *interfaces.ErrorMessage {
	if h == nil || h.Cfg == nil || !h.Cfg.SessionMemberGate.Enabled {
		return nil
	}
	member := sessionMemberFromContext(ctx)
	if member == "" {
		return &interfaces.ErrorMessage{
			StatusCode: http.StatusForbidden,
			Error:      fmt.Errorf("session member gate: this gateway serves inference only to a session's member, and the request has no session member"),
		}
	}
	if !SessionMemberAllowsModel(member, modelName) {
		return &interfaces.ErrorMessage{
			StatusCode: http.StatusForbidden,
			Error:      fmt.Errorf("session member gate: model %q is not this session's member %q", strings.TrimSpace(modelName), member),
		}
	}
	return nil
}

// SessionMemberAllowsModel reports whether a requested model is the member's model. A member is `<harness>/<model>`
// or `<model>`; the comparison ignores case (the member is lowercased) and a thinking suffix such as `(high)`.
func SessionMemberAllowsModel(member, model string) bool {
	memberModel := strings.TrimSpace(member)
	if _, after, found := strings.Cut(memberModel, "/"); found {
		memberModel = after
	}
	requested := strings.TrimSpace(thinking.ParseSuffix(strings.TrimSpace(model)).ModelName)
	return memberModel != "" && strings.EqualFold(requested, memberModel)
}

func sessionMemberFromContext(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	ginCtx, ok := ctx.Value("gin").(*gin.Context)
	if !ok || ginCtx == nil {
		return ""
	}
	raw, ok := ginCtx.Get("accessMetadata")
	if !ok {
		return ""
	}
	metadata, ok := raw.(map[string]string)
	if !ok {
		return ""
	}
	return strings.TrimSpace(metadata[sdkaccess.MetadataSessionMember])
}
