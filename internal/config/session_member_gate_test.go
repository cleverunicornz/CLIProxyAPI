package config

import "testing"

func TestSessionMemberGateLoadsFromTheV8AccessSection(t *testing.T) {
	cfg, err := ParseConfigBytes([]byte(`config-version: 8
access:
  api-keys: [readiness-key]
  session-member-gate:
    enabled: true
    audience: cliproxy
    namespace: agent-sessions-v2
    service-account: agent-session
`))
	if err != nil {
		t.Fatal(err)
	}
	gate := cfg.SessionMemberGate
	if !gate.Enabled || gate.Audience != "cliproxy" || gate.Namespace != "agent-sessions-v2" || gate.ServiceAccount != "agent-session" {
		t.Fatalf("gate = %+v", gate)
	}
	if gate.Annotation() != DefaultSessionMemberAnnotation {
		t.Fatalf("annotation = %q, want the default %q", gate.Annotation(), DefaultSessionMemberAnnotation)
	}
	if len(cfg.APIKeys) != 1 || cfg.APIKeys[0] != "readiness-key" {
		t.Fatalf("api keys = %v", cfg.APIKeys)
	}
}
