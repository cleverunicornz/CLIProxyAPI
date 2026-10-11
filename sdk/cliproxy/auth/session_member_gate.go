package auth

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	sdkaccess "github.com/router-for-me/CLIProxyAPI/v8/sdk/access"
)

// sessionMemberForbiddenCode marks the session member gate's refusal: a 403 decided before any credential is used.
const sessionMemberForbiddenCode = "session_member_forbidden"

// IsSessionMemberRefusal reports whether err is the session member gate's refusal.
func IsSessionMemberRefusal(err error) bool {
	var authErr *Error
	return errors.As(err, &authErr) && authErr != nil && authErr.Code == sessionMemberForbiddenCode
}

// sessionMemberUpstreamError refuses, before any credential is picked, a session member's request whose model would
// run upstream as another model on any credential of its providers: an OAuth or API-key alias, a model pool or a
// routed upstream model (fork-only; D-000400 item 1). Requests without a session member are not affected.
func (m *Manager) sessionMemberUpstreamError(ctx context.Context, providers []string, routeModel string) error {
	member := sdkaccess.SessionMemberFromContext(ctx)
	if member == "" {
		return nil
	}
	wanted := make(map[string]struct{}, len(providers))
	for _, provider := range providers {
		wanted[strings.ToLower(strings.TrimSpace(provider))] = struct{}{}
	}
	for _, candidate := range m.List() {
		if candidate == nil {
			continue
		}
		if _, ok := wanted[strings.ToLower(strings.TrimSpace(candidate.Provider))]; !ok {
			continue
		}
		upstreamModels, _, _, _ := m.executionModelCandidatesWithAlias(candidate, routeModel)
		for _, upstreamModel := range upstreamModels {
			if !sdkaccess.SessionMemberAllowsModel(member, upstreamModel) {
				return &Error{
					Code: sessionMemberForbiddenCode,
					Message: fmt.Sprintf("session member gate: model %q runs upstream as %q, not this session's member %q",
						routeModel, upstreamModel, member),
					HTTPStatus: http.StatusForbidden,
				}
			}
		}
	}
	return nil
}
