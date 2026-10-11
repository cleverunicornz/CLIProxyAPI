package access

import (
	"context"
	"net/http"
	"strings"
	"sync"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/thinking"
)

// MetadataSessionMember is the Result metadata key carrying the caller's v2 session member (`<harness>/<model>`).
// Only the session member provider sets it (fork-only).
const MetadataSessionMember = "session-member"

// SessionMemberResolver resolves a request's credential to its session member again, against the live identity
// source. The session member provider registers one while the gate is on.
type SessionMemberResolver func(ctx context.Context, r *http.Request) (string, *AuthError)

var (
	sessionMemberResolverMu sync.RWMutex
	sessionMemberResolver   SessionMemberResolver
)

// SetSessionMemberResolver installs the resolver, or removes it with nil.
func SetSessionMemberResolver(resolver SessionMemberResolver) {
	sessionMemberResolverMu.Lock()
	sessionMemberResolver = resolver
	sessionMemberResolverMu.Unlock()
}

// ResolveSessionMember re-resolves a request's session member; without a resolver it resolves nothing.
func ResolveSessionMember(ctx context.Context, r *http.Request) (string, *AuthError) {
	sessionMemberResolverMu.RLock()
	resolver := sessionMemberResolver
	sessionMemberResolverMu.RUnlock()
	if resolver == nil {
		return "", NewNoCredentialsError()
	}
	return resolver(ctx, r)
}

// SessionMemberAllowsModel reports whether a model is the member's model. A member is `<harness>/<model>` or
// `<model>`; the comparison ignores case (the member is lowercased) and a thinking suffix such as `(high)`.
func SessionMemberAllowsModel(member, model string) bool {
	memberModel := strings.TrimSpace(member)
	if _, after, found := strings.Cut(memberModel, "/"); found {
		memberModel = after
	}
	requested := strings.TrimSpace(thinking.ParseSuffix(strings.TrimSpace(model)).ModelName)
	return memberModel != "" && strings.EqualFold(requested, memberModel)
}

// SessionMemberFromContext returns the session member the access layer resolved for the request in ctx (the gin
// context under "gin"), or "".
func SessionMemberFromContext(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	ginCtx, ok := ctx.Value("gin").(interface{ Get(string) (any, bool) })
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
	return strings.TrimSpace(metadata[MetadataSessionMember])
}
