package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/interfaces"
	sdkaccess "github.com/router-for-me/CLIProxyAPI/v8/sdk/access"
)

// SessionMemberGateError enforces the session member gate (fork-only) on every model execution. With the gate on, a
// request runs only when:
//   - its caller resolved to a session member; on a websocket, whose credential was checked once at the upgrade,
//     the member is resolved again for every request so a refused token or a deleted or replaced pod stops it;
//   - the requested model is that member's model;
//   - its body names the model once, as a string that is the member's model, carries no other top-level key twice,
//     and asks for no tool or option that makes the upstream use another model (sessionMemberBodyError).
//
// Every refusal is a 403 and happens before any credential or upstream is used. The auth manager also refuses a
// member's model that an alias or routing would turn into another upstream model.
func (h *BaseAPIHandler) SessionMemberGateError(ctx context.Context, modelName string, rawJSON []byte) *interfaces.ErrorMessage {
	if h == nil || h.Cfg == nil || !h.Cfg.SessionMemberGate.Enabled {
		return nil
	}
	member := sdkaccess.SessionMemberFromContext(ctx)
	if member == "" {
		return sessionMemberRefusal("this gateway serves inference only to a session's member, and the request has no session member")
	}
	if ginCtx, ok := ctx.Value("gin").(*gin.Context); ok && ginCtx != nil && ginCtx.Request != nil && ginCtx.IsWebsocket() {
		current, authErr := sdkaccess.ResolveSessionMember(ctx, ginCtx.Request)
		if authErr != nil || current != member {
			return sessionMemberRefusal("the session's identity no longer resolves to its member")
		}
	}
	if !sdkaccess.SessionMemberAllowsModel(member, modelName) {
		return sessionMemberRefusal(fmt.Sprintf("model %q is not this session's member %q", strings.TrimSpace(modelName), member))
	}
	if len(bytes.TrimSpace(rawJSON)) > 0 {
		if reason := sessionMemberBodyError(member, rawJSON); reason != "" {
			return sessionMemberRefusal(reason)
		}
	}
	return nil
}

// SessionMemberFrameError enforces the session member gate on one websocket frame of the duplex path, where the
// executor forwards follow-up frames itself: the member is resolved again, and the frame passes the strict body check
// (a model it names must be the member's model). Frames without a model continue the response the gate already
// admitted.
func (h *BaseAPIHandler) SessionMemberFrameError(ctx context.Context, frame []byte) *interfaces.ErrorMessage {
	if h == nil || h.Cfg == nil || !h.Cfg.SessionMemberGate.Enabled {
		return nil
	}
	member := sdkaccess.SessionMemberFromContext(ctx)
	if member == "" {
		return sessionMemberRefusal("this gateway serves inference only to a session's member, and the request has no session member")
	}
	ginCtx, ok := ctx.Value("gin").(*gin.Context)
	if !ok || ginCtx == nil || ginCtx.Request == nil {
		return sessionMemberRefusal("the frame has no session to resolve")
	}
	current, authErr := sdkaccess.ResolveSessionMember(ctx, ginCtx.Request)
	if authErr != nil || current != member {
		return sessionMemberRefusal("the session's identity no longer resolves to its member")
	}
	if reason := sessionMemberBodyError(member, frame); reason != "" {
		return sessionMemberRefusal(reason)
	}
	return nil
}

// SessionMemberAllowsModel reports whether a requested model is the member's model (sdkaccess.SessionMemberAllowsModel).
func SessionMemberAllowsModel(member, model string) bool {
	return sdkaccess.SessionMemberAllowsModel(member, model)
}

func sessionMemberRefusal(reason string) *interfaces.ErrorMessage {
	return &interfaces.ErrorMessage{StatusCode: http.StatusForbidden, Error: errors.New("session member gate: " + reason)}
}

// SessionMemberBodyError returns why a raw request body (or websocket frame) cannot be served to the member, or "".
// Routes run it on the client's own body before any conversion (the session member route gate), and the execution
// functions on the body they execute.
func SessionMemberBodyError(member string, rawJSON []byte) string {
	return sessionMemberBodyError(member, rawJSON)
}

// sessionMemberBodyError parses the request body strictly and returns why it cannot be served to the member, or "".
//
//   - The whole body is one JSON object and no object at any depth repeats a key (after unescaping): with no repeated
//     key, every reader of the body (this gate, the image stripper's gjson, a translator, the provider's decoder)
//     reads the same value for every field, so what is forwarded means exactly what was checked.
//   - The model: at most one key equal to "model" in any letter case (a provider may read another of several, or
//     match the key case-insensitively), and it is a string naming the member's model.
//   - Any other top-level key twice: a provider may read the copy the gateway did not.
//   - Tools that run another model, in "tools" or "tool_choice": Anthropic's advisor tool (types advisor_*, which
//     consults the model it names) and any tool object that names a model of its own. The Responses API's
//     image_generation tool, which runs an image model (gpt-image-*), is not refused: the Codex CLI sends it by
//     default, so with the gate on the gateway strips it from tools and tool_choice before every upstream call and
//     never adds it (config.SDKConfig.EffectiveDisableImageGeneration). The other built-in tools of the Responses
//     API (function, custom, file_search, web_search, code_interpreter, computer_use_preview, mcp, local_shell,
//     shell, apply_patch, tool_search) and of the Messages API (client tools, web_search, web_fetch, code_execution,
//     bash, text_editor, computer, memory, tool_search, mcp_toolset) run on the request's model.
//   - A Responses "prompt" object: a stored prompt template can carry a model of its own.
func sessionMemberBodyError(member string, rawJSON []byte) string {
	if reason := strictJSONError(rawJSON); reason != "" {
		return reason
	}
	dec := json.NewDecoder(bytes.NewReader(rawJSON))
	if tok, err := dec.Token(); err != nil || tok != json.Delim('{') {
		return "the request body is not a JSON object"
	}
	seen := make(map[string]struct{})
	models := 0
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return "the request body is not valid JSON"
		}
		key, _ := tok.(string)
		var value json.RawMessage
		if err = dec.Decode(&value); err != nil {
			return "the request body is not valid JSON"
		}
		if _, dup := seen[key]; dup {
			return fmt.Sprintf("the request body names %q more than once", key)
		}
		seen[key] = struct{}{}
		switch {
		case strings.EqualFold(key, "model"):
			models++
			if models > 1 {
				return "the request body names the model more than once"
			}
			var model string
			if json.Unmarshal(value, &model) != nil {
				return "the request body's model is not a string"
			}
			if !sdkaccess.SessionMemberAllowsModel(member, model) {
				return fmt.Sprintf("model %q is not this session's member %q", model, member)
			}
		case key == "tools":
			if reason := sessionMemberToolsError(value); reason != "" {
				return reason
			}
		case key == "tool_choice":
			if reason := sessionMemberToolError(value); reason != "" {
				return reason
			}
		case key == "prompt":
			if trimmed := bytes.TrimSpace(value); len(trimmed) > 0 && trimmed[0] == '{' {
				return "a stored prompt template can choose another model"
			}
		}
	}
	if _, err := dec.Token(); err != nil {
		return "the request body is not valid JSON"
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return "the request body has data after its JSON object"
	}
	return ""
}

func sessionMemberToolsError(value json.RawMessage) string {
	var tools []json.RawMessage
	if json.Unmarshal(value, &tools) != nil {
		return ""
	}
	for _, tool := range tools {
		if reason := sessionMemberToolError(tool); reason != "" {
			return reason
		}
	}
	return ""
}

// sessionMemberToolError refuses one tool (or tool_choice) object that makes the upstream use another model.
func sessionMemberToolError(value json.RawMessage) string {
	var fields map[string]json.RawMessage
	if json.Unmarshal(value, &fields) != nil {
		return ""
	}
	var toolType string
	namesModel := false
	for key, raw := range fields {
		if strings.EqualFold(key, "model") {
			namesModel = true
		}
		if key == "type" {
			_ = json.Unmarshal(raw, &toolType)
		}
	}
	toolType = strings.ToLower(strings.TrimSpace(toolType))
	switch {
	case toolType == "image_generation":
		// Stripped before the upstream call (see sessionMemberBodyError).
		return ""
	case strings.HasPrefix(toolType, "advisor"):
		return "the advisor tool makes the upstream consult another model"
	case namesModel:
		return "a tool that names a model of its own makes the upstream use another model"
	}
	return ""
}

// strictJSONError reports a body that is not exactly one JSON object, or in which any object, at any depth, names a
// key more than once.
func strictJSONError(rawJSON []byte) string {
	dec := json.NewDecoder(bytes.NewReader(rawJSON))
	dec.UseNumber()
	tok, err := dec.Token()
	if err != nil || tok != json.Delim('{') {
		return "the request body is not a JSON object"
	}
	if reason := strictJSONObject(dec, 1); reason != "" {
		return reason
	}
	if _, err = dec.Token(); !errors.Is(err, io.EOF) {
		return "the request body has data after its JSON object"
	}
	return ""
}

// maxStrictJSONDepth bounds the nesting the strict parse follows.
const maxStrictJSONDepth = 512

// strictJSONObject reads the rest of an object whose '{' was read, refusing a repeated key in it or below it.
func strictJSONObject(dec *json.Decoder, depth int) string {
	if depth > maxStrictJSONDepth {
		return "the request body nests too deeply"
	}
	seen := make(map[string]struct{})
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return "the request body is not valid JSON"
		}
		key, ok := tok.(string)
		if !ok {
			return "the request body is not valid JSON"
		}
		if _, dup := seen[key]; dup {
			return fmt.Sprintf("the request body names %q more than once in one object", key)
		}
		seen[key] = struct{}{}
		if reason := strictJSONValue(dec, depth); reason != "" {
			return reason
		}
	}
	if _, err := dec.Token(); err != nil {
		return "the request body is not valid JSON"
	}
	return ""
}

// strictJSONValue reads one value, following objects and arrays.
func strictJSONValue(dec *json.Decoder, depth int) string {
	tok, err := dec.Token()
	if err != nil {
		return "the request body is not valid JSON"
	}
	switch tok {
	case json.Delim('{'):
		return strictJSONObject(dec, depth+1)
	case json.Delim('['):
		if depth+1 > maxStrictJSONDepth {
			return "the request body nests too deeply"
		}
		for dec.More() {
			if reason := strictJSONValue(dec, depth+1); reason != "" {
				return reason
			}
		}
		if _, err = dec.Token(); err != nil {
			return "the request body is not valid JSON"
		}
	}
	return ""
}
