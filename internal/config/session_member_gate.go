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

// EffectiveDisableImageGeneration is the image generation mode requests run under: with the session member gate on,
// image generation is off everywhere, so the gateway neither adds the image_generation tool nor forwards one a
// session sent (an image model is not the session's member, D-000400 item 1).
func (c *SDKConfig) EffectiveDisableImageGeneration() DisableImageGenerationMode {
	if c == nil {
		return DisableImageGenerationOff
	}
	if c.SessionMemberGate.Enabled {
		return DisableImageGenerationAll
	}
	return c.DisableImageGeneration
}

// DefaultMaxRequestBodyMB is the default bound on a client request body, as received and after each decoding stage.
// 64 MiB is above what the providers behind this gateway accept in one request (Anthropic's Messages API refuses
// requests over 32 MB; OpenAI accepts at most 50 MB of image input per request), with room for JSON framing and
// base64, and it keeps a decompression bomb from expanding past it.
const DefaultMaxRequestBodyMB = 64

// EffectiveMaxRequestBodyBytes is the effective request body bound in bytes; 0 means unbounded.
//
// The fork's requests.max-body-mb wins when it is set: a positive value is that many MiB, a negative value
// removes the bound, and 0 (unset) falls through. Otherwise upstream's server.max-request-body-bytes applies
// when it is set: a positive value is that many bytes, and a negative value removes the bound. With neither
// key set, the fork's default DefaultMaxRequestBodyMB applies, because the gateways behind this fork must be
// bounded by default.
func (c *SDKConfig) EffectiveMaxRequestBodyBytes() int64 {
	if c != nil && c.MaxRequestBodyMB != 0 {
		if c.MaxRequestBodyMB < 0 {
			return 0
		}
		return int64(c.MaxRequestBodyMB) << 20
	}
	if c != nil && c.MaxRequestBodyBytes < 0 {
		return 0
	}
	if c != nil && c.MaxRequestBodyBytes > 0 {
		return c.MaxRequestBodyBytes
	}
	return int64(DefaultMaxRequestBodyMB) << 20
}
