package handlers

import "testing"

func TestSessionMemberAllowsModel(t *testing.T) {
	for _, tc := range []struct {
		member, model string
		want          bool
	}{
		{"claude/claude-opus-5-5", "claude-opus-5-5", true},
		{"claude/claude-opus-5-5", "Claude-Opus-5-5", true},
		{"claude/claude-opus-5-5", "claude-opus-5-5(high)", true},
		{"claude/claude-opus-5-5", "claude-sonnet-5-5", false},
		{"claude/claude-opus-5-5", "claude/claude-opus-5-5", false},
		{"claude/claude-opus-5-5", "", false},
		{"codex/gpt-6-astra", "gpt-6-astra", true},
		{"codex/gpt-6-astra", "gpt-6-astra-mini", false},
		{"claude/glm-5.3", "glm-5.3", true},
		{"gpt-6-astra", "gpt-6-astra", true},
		{"", "", false},
	} {
		if got := SessionMemberAllowsModel(tc.member, tc.model); got != tc.want {
			t.Errorf("SessionMemberAllowsModel(%q, %q) = %v, want %v", tc.member, tc.model, got, tc.want)
		}
	}
}
