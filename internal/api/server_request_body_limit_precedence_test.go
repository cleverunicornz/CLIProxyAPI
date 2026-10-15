package api

import (
	"fmt"
	"net/http"
	"strings"
	"testing"
)

// Round-2 regression test for the composed request body bound (validator round 1 on PR #12, finding 1; the
// validator's overlay probe TestL15ValidationForkRequestBodyPrecedence). The fork's requests.max-body-mb must
// win whenever both request body controls are configured, whether the middleware refuses the request on
// Content-Length or the handler bounds the body it reads. Both paths resolve the one effective limit
// (config.SDKConfig.EffectiveMaxRequestBodyBytes), so the middleware must not install upstream's
// server.max-request-body-bytes on the request context over the fork's key. All identities, credentials and
// bodies are fake.

// TestServerRequestBodyLimitPrefersTheForkMaxBodyMB sends one valid 2 MiB Responses request with both keys set:
// once with the fork's bound tighter than upstream's (413, nothing executed) and once with it wider (200, one
// execution), with the session member gate off and on.
func TestServerRequestBodyLimitPrefersTheForkMaxBodyMB(t *testing.T) {
	for _, gateOn := range []bool{false, true} {
		for _, tc := range []struct {
			name          string
			forkMiB       int
			upstreamBytes int
			wantStatus    int
			wantExecs     int
		}{
			{"fork_tighter", 1, 8 << 20, http.StatusRequestEntityTooLarge, 0},
			{"fork_wider", 8, 1 << 20, http.StatusOK, 1},
		} {
			t.Run(fmt.Sprintf("%s/gate_%t", tc.name, gateOn), func(t *testing.T) {
				cfg := fmt.Sprintf("server:\n  max-request-body-bytes: %d\nrequests:\n  max-body-mb: %d\n", tc.upstreamBytes, tc.forkMiB)
				h := newMemberGateHarnessWithConfig(t, gateOn, cfg)
				token := memberGatePlainKey
				if gateOn {
					token = codexSessionToken
				}
				body := `{"model":"gpt-6-astra","input":"` + strings.Repeat("x", 2<<20) + `"}`
				rec := h.do(t, http.MethodPost, "/v1/responses", token, body)
				execs := len(h.codex.calls())
				t.Logf("fork_limit=%d MiB upstream_limit=%d bytes body=%d bytes status=%d executions=%d; want status=%d executions=%d",
					tc.forkMiB, tc.upstreamBytes, len(body), rec.Code, execs, tc.wantStatus, tc.wantExecs)
				if rec.Code != tc.wantStatus || execs != tc.wantExecs {
					t.Fatalf("requests.max-body-mb did not win over server.max-request-body-bytes: status = %d with %d executions, want %d with %d; body %s",
						rec.Code, execs, tc.wantStatus, tc.wantExecs, rec.Body.String())
				}
			})
		}
	}
}
