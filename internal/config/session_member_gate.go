package config

import "strings"

// DefaultSessionMemberAnnotation is the pod annotation that names a v2 session's member.
const DefaultSessionMemberAnnotation = "cvu.cleverunicorn.io/member"

// SessionMemberGateConfig configures the session member gate (fork-only).
//
// When enabled, a caller may present the projected ServiceAccount token of a session pod. The gateway verifies it
// with a Kubernetes TokenReview for Audience, requires the ServiceAccount Namespace/ServiceAccount, reads the bound
// pod and takes the session's member (`<harness>/<model>`) from MemberAnnotation. Inference is then served only for
// the member's model; any inference request without a resolvable member is refused, whatever key it presents.
type SessionMemberGateConfig struct {
	// Enabled turns the gate on.
	Enabled bool `yaml:"enabled" json:"enabled"`
	// Audience is the audience the session token must carry.
	Audience string `yaml:"audience,omitempty" json:"audience,omitempty"`
	// Namespace and ServiceAccount name the session pods' ServiceAccount.
	Namespace      string `yaml:"namespace,omitempty" json:"namespace,omitempty"`
	ServiceAccount string `yaml:"service-account,omitempty" json:"service-account,omitempty"`
	// MemberAnnotation is the pod annotation holding the member; empty means DefaultSessionMemberAnnotation.
	MemberAnnotation string `yaml:"member-annotation,omitempty" json:"member-annotation,omitempty"`
	// APIServer, TokenFile and CAFile reach the Kubernetes API; empty means the in-cluster defaults.
	APIServer string `yaml:"api-server,omitempty" json:"api-server,omitempty"`
	TokenFile string `yaml:"token-file,omitempty" json:"token-file,omitempty"`
	CAFile    string `yaml:"ca-file,omitempty" json:"ca-file,omitempty"`
}

// Annotation returns the member annotation, defaulted.
func (c SessionMemberGateConfig) Annotation() string {
	if annotation := strings.TrimSpace(c.MemberAnnotation); annotation != "" {
		return annotation
	}
	return DefaultSessionMemberAnnotation
}
