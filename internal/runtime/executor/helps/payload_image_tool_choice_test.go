package helps

import (
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"github.com/tidwall/gjson"
)

// R3-2 (the fallback validator's round 3 on #10 at 4ad6f587, validator-evidence/cliproxy-pr10-r3/probes/
// r3_gateoff_payload_test.go TestR3GateOffImagePayloadSnapshot): with the session member gate off, stripping the image
// tool leaves tool_choice exactly as the base did; the cleanup of an unsatisfiable choice runs only with the gate on.

var imageToolChoices = []string{
	`"required"`,
	`{"type":"any"}`,
	`{"type":"allowed_tools","mode":"required","tools":[{"type":"image_generation"}]}`,
}

func TestR3GateOffImagePayloadSnapshot(t *testing.T) {
	for _, mode := range []config.DisableImageGenerationMode{config.DisableImageGenerationOff, config.DisableImageGenerationAll} {
		cfg := &config.Config{}
		cfg.DisableImageGeneration = mode
		for _, choice := range imageToolChoices {
			raw := []byte(`{"model":"gpt-6-astra","tools":[{"type":"image_generation"}],"tool_choice":` + choice + `}`)
			got := ApplyPayloadConfigWithRoot(cfg, "gpt-6-astra", "codex", "", raw, raw, "gpt-6-astra", "/v1/responses")
			t.Logf("disable-image-generation=%v input_choice=%s output=%s", mode, choice, got)
			wantTools := int64(1)
			if mode == config.DisableImageGenerationAll {
				wantTools = 0
			}
			if n := gjson.GetBytes(got, "tools.#").Int(); n != wantTools {
				t.Errorf("mode %v, choice %s: %d tools left, want %d", mode, choice, n, wantTools)
			}
			if gotChoice := gjson.GetBytes(got, "tool_choice").Raw; gotChoice != choice {
				t.Errorf("mode %v: tool_choice %s became %q; the gate is off, so it must stay as the base leaves it", mode, choice, gotChoice)
			}
		}
	}
}

func TestImageToolChoiceCleanupRunsWithTheGateOn(t *testing.T) {
	cfg := &config.Config{}
	cfg.SessionMemberGate.Enabled = true
	for _, choice := range imageToolChoices {
		raw := []byte(`{"model":"gpt-6-astra","tools":[{"type":"image_generation"}],"tool_choice":` + choice + `}`)
		got := ApplyPayloadConfigWithRoot(cfg, "gpt-6-astra", "codex", "", raw, raw, "gpt-6-astra", "/v1/responses")
		if gjson.GetBytes(got, "tool_choice").Exists() || gjson.GetBytes(got, "tools.#").Int() != 0 {
			t.Errorf("gate on, choice %s: output %s, want no tools and no tool_choice", choice, got)
		}
	}
}
