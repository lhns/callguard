package hook

import (
	"context"
	"encoding/json"
	"fmt"
	"io"

	"github.com/lhns/callguard"
)

type hermesInput struct {
	HookEventName string          `json:"hook_event_name"`
	ToolName      string          `json:"tool_name"`
	ToolInput     json.RawMessage `json:"tool_input"`
	SessionID     string          `json:"session_id"`
	Cwd           string          `json:"cwd"`
}

type hermesOutput struct {
	Action  string `json:"action,omitempty"`
	Message string `json:"message,omitempty"`
	RuleKey string `json:"rule_key,omitempty"`
}

// Hermes runs the Hermes pre_tool_call shell hook and returns the exit code:
// 0 with {} or an approve answer, 2 with a block answer (Hermes blocks on
// exit 2 even without JSON).
func Hermes(in io.Reader, out, errOut io.Writer, opt Options, d Decider) (code int) {
	defer func() {
		if r := recover(); r != nil {
			fmt.Fprintf(errOut, "callguard: internal error: %v; blocking the call\n", r)
			code = 2
		}
	}()

	req := newRequest("hermes")
	req.Unattended = opt.Unattended
	var v callguard.Verdict
	var in0 hermesInput

	body, err := readInput(in)
	if err == nil {
		if err = json.Unmarshal(body, &in0); err == nil && in0.HookEventName == "" {
			err = fmt.Errorf("missing hook_event_name")
		}
	}
	switch {
	case err != nil:
		v = fallback(req, "bad hook input: "+err.Error())
	case in0.HookEventName != "pre_tool_call":
		return hermesWrite(out, errOut, hermesOutput{}, 0)
	case in0.ToolName == "":
		v = fallback(req, "bad hook input: missing tool_name")
	default:
		req.SessionID = in0.SessionID
		req.Cwd = in0.Cwd
		req.Tool = callguard.ToolCall{Name: in0.ToolName, Input: in0.ToolInput}
		v = decide(context.Background(), d, opt, req)
	}

	if !v.Enforced || v.Decision == callguard.Allow {
		return hermesWrite(out, errOut, hermesOutput{}, 0)
	}
	if v.Decision == callguard.Ask {
		key := "callguard:" + v.Layer
		if v.Rule != "" {
			key += ":" + v.Rule
		}
		return hermesWrite(out, errOut, hermesOutput{"approve", askMessage(v), key}, 0)
	}
	return hermesWrite(out, errOut, hermesOutput{Action: "block", Message: denyMessage(v)}, 2)
}

func hermesWrite(out, errOut io.Writer, o hermesOutput, code int) int {
	b, err := json.Marshal(o)
	if err == nil {
		b = append(b, '\n')
		_, err = out.Write(b)
	}
	if err != nil {
		fmt.Fprintf(errOut, "callguard: could not write the decision: %v; blocking the call\n", err)
		return 2
	}
	return code
}
