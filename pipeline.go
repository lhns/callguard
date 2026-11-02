package callguard

import (
	"context"
	"fmt"
	"time"

	"github.com/lhns/callguard/backend"
	"github.com/lhns/callguard/internal/declog"
	"github.com/lhns/callguard/internal/judge"
	"github.com/lhns/callguard/internal/nahlayer"
	"github.com/lhns/callguard/internal/rules"
	"github.com/lhns/callguard/internal/transcript"
	"github.com/lhns/callguard/policy"
)

// pipeline runs builtin, nah, rules and llm in order; the first layer that
// decides wins (design §4).
func (e *Engine) pipeline(ctx context.Context, req *Request) outcome {
	if req.Schema != "" && req.Schema != RequestSchema || req.V != 0 && req.V != 1 {
		return outcome{v: FallbackVerdict(req, "unsupported request schema"), layerEnforced: true}
	}
	if req.Tool.Name == "" {
		return outcome{v: FallbackVerdict(req, "request has no tool name"), layerEnforced: true}
	}
	projectDir := ResolveProjectDir(req)
	call := rules.NewCall(rules.CallInput{
		Harness: req.Harness, Tool: req.Tool.Name, Input: req.Tool.Input, Cwd: req.Cwd,
		ProjectDir: projectDir, Context: req.Context, Unattended: req.Unattended,
	}, e.impl.env)

	// 0 builtin
	if hit, ok := e.impl.builtin.Check(call); ok {
		return decided(hit.Decision, LayerBuiltin, hit.ID, hit.Reason)
	}

	// 1 nah
	var warns []string
	if nah := e.pol.Nah; nah.Enabled {
		timeout := time.Duration(nah.TimeoutMS) * time.Millisecond
		res, err := nahlayer.Run(ctx, e.impl.nahArgv, timeout, req.Tool.Name, req.Tool.Input, req.Cwd)
		switch {
		case err != nil && nah.Require:
			v := FallbackVerdict(req, "nah is required but failed: "+err.Error())
			return outcome{v: v, layerEnforced: nah.Mode != policy.ModeShadow}
		case err != nil:
			warns = append(warns, "nah skipped: "+err.Error())
		case res.Verdict == nahlayer.Block:
			rule := "nah"
			if res.Rule != "" {
				rule = "nah:" + res.Rule
			}
			out := decided("deny", LayerNah, rule, res.Reason)
			out.layerEnforced = nah.Mode != policy.ModeShadow
			out.warnings = warns
			return out
		}
	}

	// 2 rules
	if r, ok := e.impl.rules.Match(call); ok {
		reason := r.Description
		if reason == "" {
			reason = "policy rule " + r.ID
		}
		out := decided(r.Decision, LayerRules, r.ID, reason)
		out.warnings = warns
		return out
	}

	// 3 llm
	if !e.pol.LLMEnabled() {
		return outcome{warnings: warns, v: Verdict{
			Decision: Ask, Layer: LayerNone, Reason: "no callguard layer decided this call",
		}}
	}
	out := e.runLLM(ctx, req, call, projectDir)
	out.warnings = append(warns, out.warnings...)
	return out
}

func decided(decision, layer, rule, reason string) outcome {
	return outcome{layerEnforced: true, v: Verdict{
		Decision: Decision(decision), Layer: layer, Rule: rule, Reason: reason, Confidence: 1.0,
	}}
}

func (e *Engine) runLLM(ctx context.Context, req *Request, call rules.Call, projectDir string) outcome {
	llm := e.pol.LLM
	enforced := llm.Mode != policy.ModeShadow
	fail := func(rule, backendName, cause string, warns []string) outcome {
		v := FallbackVerdict(req, cause)
		v.Rule, v.Backend = rule, backendName
		return outcome{v: v, layerEnforced: enforced, warnings: warns}
	}

	b := e.opts.Backend
	if b == nil {
		cfg, ok := e.pol.Backends[llm.Backend]
		if !ok {
			return fail("backend", "", fmt.Sprintf("llm backend %q is not configured", llm.Backend), nil)
		}
		var err error
		if b, err = backend.FromConfig(cfg); err != nil {
			return fail("backend", "", fmt.Sprintf("llm backend %q unavailable: %v", llm.Backend, err), nil)
		}
	}
	if dc := req.Context["data_class"]; dc != "" && !contains(b.DataClasses(), dc) {
		return fail("data-class", b.Name(), fmt.Sprintf("data class %q may not be sent to backend %s", dc, b.Name()), nil)
	}

	var warns []string
	msgs, err := e.transcript(req)
	if err != nil {
		warns = append(warns, "transcript unreadable: "+err.Error())
	}

	jctx, cancel := context.WithTimeout(ctx, time.Duration(llm.TimeoutMS)*time.Millisecond)
	defer cancel()
	res, err := e.impl.judge(jctx, b, judge.Config{
		Environment: llm.Environment, Block: llm.Block, AllowExceptions: llm.AllowExceptions,
		MinConfidence: *llm.MinConfidence,
	}, judge.Input{
		Harness: req.Harness, Tool: req.Tool.Name, Kind: call.Kind, ToolInput: req.Tool.Input,
		Cwd: req.Cwd, ProjectDir: projectDir, Context: req.Context, Unattended: req.Unattended,
		Transcript: msgs,
	})
	if err != nil {
		rule := b.Name()
		if rule == "" {
			rule = "judge"
		}
		return fail(rule, b.Name(), "the llm judge failed: "+err.Error(), warns)
	}
	d := Decision(res.Decision)
	if !d.Valid() {
		return fail("judge", b.Name(), fmt.Sprintf("the llm judge returned decision %q", res.Decision), warns)
	}
	out := outcome{
		layerEnforced: enforced, inTok: res.InputTokens, outTok: res.OutputTokens, warnings: warns,
		v: Verdict{Decision: d, Layer: LayerLLM, Rule: res.Rule, Reason: res.Reason,
			Confidence: res.Confidence, Backend: b.Name()},
	}
	if d == Deny && enforced && e.pol.Mode != policy.ModeShadow && !req.Unattended && e.streakReached(req) {
		out.v.Decision = Ask
		out.escalated = true
		out.warnings = append(out.warnings, "deny streak: escalated to human")
	}
	return out
}

// streakReached reads this session's recent llm denies from the decision log.
func (e *Engine) streakReached(req *Request) bool {
	ds := e.pol.DenyStreak
	if ds == nil || e.impl.logger == nil || req.SessionID == "" {
		return false
	}
	entries, err := declog.ReadTail(e.impl.logger.Path(), req.SessionID)
	if err != nil {
		return false
	}
	consecutive, total := declog.LLMDenies(entries)
	return ds.Consecutive > 0 && consecutive >= ds.Consecutive || ds.Total > 0 && total >= ds.Total
}

// transcript returns the judge's view of the conversation, newest within the
// policy limits. Assistant text never gets here: inline messages are
// reduced to user/tool_call roles and the file reader drops the rest.
func (e *Engine) transcript(req *Request) ([]transcript.Message, error) {
	t := req.Transcript
	if t == nil {
		return nil, nil
	}
	lim := e.pol.LLM.Transcript
	if len(t.Messages) > 0 {
		msgs := make([]transcript.Message, 0, len(t.Messages))
		for _, m := range t.Messages {
			if m.Role != "user" && m.Role != "tool_call" {
				continue
			}
			msgs = append(msgs, transcript.Message{Role: m.Role, Text: m.Text, Tool: m.Tool, Input: m.Input})
		}
		return transcript.Limit(msgs, lim.MaxMessages, lim.MaxBytes), nil
	}
	if t.Path != "" && (t.Format == "claude-jsonl" || t.Format == "" && req.Harness == "claude") {
		return transcript.ReadClaudeJSONL(t.Path, lim.MaxMessages, lim.MaxBytes)
	}
	return nil, nil
}

func contains(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}
