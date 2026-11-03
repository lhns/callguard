package hook

import (
	"context"
	"encoding/json"
	"fmt"
	"io"

	"github.com/lhns/callguard"
)

type claudeInput struct {
	SessionID      string          `json:"session_id"`
	TranscriptPath string          `json:"transcript_path"`
	Cwd            string          `json:"cwd"`
	PermissionMode string          `json:"permission_mode"`
	HookEventName  string          `json:"hook_event_name"`
	ToolName       string          `json:"tool_name"`
	ToolInput      json.RawMessage `json:"tool_input"`
	ToolUseID      string          `json:"tool_use_id"`
}

type claudeOutput struct {
	HookSpecificOutput claudeDecision `json:"hookSpecificOutput"`
}

type claudeDecision struct {
	HookEventName            string `json:"hookEventName"`
	PermissionDecision       string `json:"permissionDecision"`
	PermissionDecisionReason string `json:"permissionDecisionReason"`
}

// Claude runs the Claude Code PreToolUse hook and returns the exit code.
//
// Claude treats any non-zero exit other than 2 as a non-blocking error and
// runs the tool, so this function returns only 0 (JSON decision, or no
// output for "no opinion") or 2 (blocking, reason on errOut).
func Claude(in io.Reader, out, errOut io.Writer, opt Options, d Decider) (code int) {
	defer func() {
		if r := recover(); r != nil {
			fmt.Fprintf(errOut, "callguard: internal error: %v; blocking the call\n", r)
			code = 2
		}
	}()

	req := newRequest("claude")
	var v callguard.Verdict
	var in0 claudeInput

	body, err := readInput(in)
	if err == nil {
		if err = json.Unmarshal(body, &in0); err == nil && in0.HookEventName == "" {
			err = fmt.Errorf("missing hook_event_name")
		}
	}
	// Set before any fallback, so a malformed payload in dontAsk still denies.
	req.Unattended = opt.Unattended || in0.PermissionMode == "dontAsk"
	switch {
	case err != nil:
		v = fallback(req, "bad hook input: "+err.Error())
	case in0.HookEventName != "PreToolUse":
		return 0
	case in0.ToolName == "":
		v = fallback(req, "bad hook input: missing tool_name")
	default:
		req.SessionID = in0.SessionID
		req.ToolUseID = in0.ToolUseID
		req.Cwd = in0.Cwd
		req.Tool = callguard.ToolCall{Name: in0.ToolName, Input: in0.ToolInput}
		req.PermissionMode = in0.PermissionMode
		if in0.TranscriptPath != "" {
			req.Transcript = &callguard.Transcript{Path: in0.TranscriptPath, Format: "claude-jsonl"}
		}
		v = decide(context.Background(), d, opt, req)
	}

	if !v.Enforced {
		return 0
	}
	var msg string
	switch v.Decision {
	case callguard.Allow:
		// A bare allow is wrong for tools that need a user answer, and in
		// auto mode it would pre-empt Claude Code's own classifier (design §10).
		if in0.ToolName == "AskUserQuestion" || in0.ToolName == "ExitPlanMode" ||
			(in0.PermissionMode == "auto" && !opt.AllowInAuto) {
			return 0
		}
		msg = askMessage(v)
	case callguard.Ask:
		msg = askMessage(v)
	default:
		msg = denyMessage(v)
	}
	b, err := json.Marshal(claudeOutput{claudeDecision{"PreToolUse", string(v.Decision), msg}})
	if err == nil {
		b = append(b, '\n')
		_, err = out.Write(b)
	}
	if err != nil {
		fmt.Fprintf(errOut, "%s (could not write the decision: %v)\n", denyMessage(lastResort(req, "output")), err)
		return 2
	}
	return 0
}
