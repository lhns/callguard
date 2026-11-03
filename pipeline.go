package callguard

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
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

	// 1 nah. A layer in shadow mode records what it would have decided and the
	// pipeline goes on, so a shadowed nah never hides the layers behind it.
	var warns []string
	var shadow []declog.ShadowVerdict
	var nahRes *nahlayer.Result
	if nah := e.pol.Nah; nah.Enabled {
		timeout := time.Duration(nah.TimeoutMS) * time.Millisecond
		res, err := nahlayer.Run(ctx, e.impl.nahArgv, timeout, req.Tool.Name, req.Tool.Input, req.Cwd)
		shadowed := nah.Mode == policy.ModeShadow
		switch {
		case err != nil && nah.Require:
			cause := "nah is required but failed: " + err.Error()
			v := FallbackVerdict(req, cause)
			if !shadowed {
				return outcome{v: v, layerEnforced: true}
			}
			warns = append(warns, fmt.Sprintf("shadow nah: would %s (nah): %s", v.Decision, cause))
			shadow = append(shadow, declog.ShadowVerdict{Layer: LayerNah, Decision: string(v.Decision), Rule: "nah"})
		case err != nil:
			warns = append(warns, "nah skipped: "+err.Error())
		case res.Verdict == nahlayer.Block:
			rule := "nah"
			if res.Rule != "" {
				rule = "nah:" + res.Rule
			}
			if !shadowed {
				out := decided("deny", LayerNah, rule, res.Reason)
				out.warnings = warns
				return out
			}
			warns = append(warns, fmt.Sprintf("shadow nah: would deny (%s): %s", rule, res.Reason))
			shadow = append(shadow, declog.ShadowVerdict{Layer: LayerNah, Decision: "deny", Rule: rule})
		default:
			nahRes = &res
		}
	}

	// 2 rules
	if r, ok := e.impl.rules.Match(call); ok {
		reason := r.Description
		if reason == "" {
			reason = "policy rule " + r.ID
		}
		out := decided(r.Decision, LayerRules, r.ID, reason)
		out.warnings, out.shadow = warns, shadow
		return out
	}

	// 3 llm
	if !e.pol.LLMEnabled() {
		return outcome{warnings: warns, shadow: shadow, v: Verdict{
			Decision: Ask, Layer: LayerNone, Reason: "no callguard layer decided this call",
		}}
	}
	out := e.runLLM(ctx, req, call, projectDir, e.judgeFacts(req, nahRes))
	out.warnings = append(warns, out.warnings...)
	out.shadow = shadow
	return out
}

// judgeFacts picks what the judge learns about the parse of the call: the
// host's facts, else the coverage nah reported when it delegated.
func (e *Engine) judgeFacts(req *Request, nahRes *nahlayer.Result) *Facts {
	switch {
	case e.opts.OmitFacts:
		return nil
	case req.Facts != nil:
		return req.Facts
	case nahRes != nil:
		return &Facts{Source: "nah-decide", Coverage: nahRes.Coverage}
	}
	return nil
}

func decided(decision, layer, rule, reason string) outcome {
	return outcome{layerEnforced: true, v: Verdict{
		Decision: Decision(decision), Layer: layer, Rule: rule, Reason: reason, Confidence: 1.0,
	}}
}

func (e *Engine) runLLM(ctx context.Context, req *Request, call rules.Call, projectDir string, facts *Facts) outcome {
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
	if dc := req.Context["data_class"]; dc != "" && !slices.Contains(b.DataClasses(), dc) {
		return fail("data-class", b.Name(), fmt.Sprintf("data class %q may not be sent to backend %s", dc, b.Name()), nil)
	}

	var warns []string
	msgs, err := e.transcript(req)
	if err != nil {
		warns = append(warns, "transcript unreadable: "+err.Error())
	}
	in := judge.Input{
		Harness: req.Harness, Tool: req.Tool.Name, Kind: call.Kind, ToolInput: req.Tool.Input,
		Cwd: req.Cwd, ProjectDir: projectDir, Context: req.Context, Unattended: req.Unattended,
		Transcript: msgs,
	}
	meta := req.Meta
	if e.impl.probe != nil && req.Cwd != "" && call.Kind == rules.KindShell {
		meta = e.impl.probe(ctx, req.Cwd, shellCommand(req.Tool.Input), req.Meta)
	}
	if meta != nil {
		in.GitStatus, in.RepoVisibility = meta.GitStatus, meta.RepoVisibility
	}
	if facts != nil {
		in.Facts, _ = json.Marshal(facts) // plain structs: cannot fail
	}

	jctx, cancel := context.WithTimeout(ctx, time.Duration(llm.TimeoutMS)*time.Millisecond)
	defer cancel()
	res, err := e.impl.judge(jctx, b, judge.Config{
		Environment: llm.Environment, Block: llm.Block, AllowExceptions: llm.AllowExceptions,
		MinConfidence: *llm.MinConfidence,
	}, in)
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

// shellCommand is the "command" string of a shell tool's input, "" if none.
func shellCommand(input json.RawMessage) string {
	var in struct {
		Command string `json:"command"`
	}
	_ = json.Unmarshal(input, &in)
	return in.Command
}

// transcript returns the judge's view of the conversation, newest within the
// policy limits. Assistant text survives only as the referent of a user reply
// (transcript.Referents), and calls the guard blocked earlier are marked.
func (e *Engine) transcript(req *Request) ([]transcript.Message, error) {
	t := req.Transcript
	if t == nil {
		return nil, nil
	}
	lim := e.pol.LLM.Transcript
	var msgs []transcript.Message
	var err error
	switch {
	case len(t.Messages) > 0:
		for _, m := range t.Messages {
			switch m.Role {
			case transcript.RoleUser, transcript.RoleAssistant, transcript.RoleToolCall, transcript.RoleThirdParty:
				msgs = append(msgs, transcript.Message{Role: m.Role, Text: m.Text, Tool: m.Tool, Input: m.Input, ID: m.ID})
			case transcript.RoleOutcome:
				if transcript.ValidOutcome(m.Outcome) {
					msgs = append(msgs, transcript.Message{Role: m.Role, ID: m.ID, Outcome: m.Outcome})
				}
			}
		}
		msgs = transcript.Limit(transcript.Referents(msgs), lim.MaxMessages, lim.MaxBytes)
	case t.Path != "" && (t.Format == "claude-jsonl" || t.Format == "" && req.Harness == "claude"):
		msgs, err = transcript.ReadClaudeJSONL(t.Path, lim.MaxMessages, lim.MaxBytes)
	}
	return transcript.MarkBlocked(msgs, e.blockedCalls(req)), err
}

// blockedCalls is the set of tool_use ids of this session that callguard
// itself denied (enforced), from the decision log.
func (e *Engine) blockedCalls(req *Request) map[string]bool {
	if e.impl.logger == nil || req.SessionID == "" {
		return nil
	}
	entries, err := declog.ReadTail(e.impl.logger.Path(), req.SessionID)
	if err != nil {
		return nil
	}
	ids := map[string]bool{}
	for _, en := range entries {
		if en.ToolUseID != "" && en.Enforced && en.Decision == "deny" {
			ids[en.ToolUseID] = true
		}
	}
	return ids
}

// ResolveProjectDir returns req.ProjectDir if set, else the nearest
// directory at or above req.Cwd that contains .git, else req.Cwd.
func ResolveProjectDir(req *Request) string {
	if req == nil {
		return ""
	}
	if req.ProjectDir != "" {
		return req.ProjectDir
	}
	if req.Cwd == "" {
		return ""
	}
	for dir := req.Cwd; ; {
		if _, err := os.Stat(filepath.Join(dir, ".git")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return req.Cwd
		}
		dir = parent
	}
}
