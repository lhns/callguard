package hook

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/lhns/callguard"
)

func payload(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func verdict(d callguard.Decision, enforced bool) callguard.Verdict {
	return callguard.Verdict{
		Schema: callguard.VerdictSchema, V: 1, ID: "id1", Decision: d, Enforced: enforced,
		Reason: "because", Layer: "rules", Rule: "r1", Confidence: 1,
	}
}

// capture returns a decider that records the request and returns v.
func capture(v callguard.Verdict) (Decider, *callguard.Request) {
	got := new(callguard.Request)
	return func(_ context.Context, r *callguard.Request) callguard.Verdict {
		*got = *r
		return v
	}, got
}

func panicking(context.Context, *callguard.Request) callguard.Verdict { panic("boom") }

type runFn func(in string, opt Options, d Decider) (stdout, stderr string, code int)

func harness(f func(r *strings.Reader, o, e *bytes.Buffer, opt Options, d Decider) int) runFn {
	return func(in string, opt Options, d Decider) (string, string, int) {
		var o, e bytes.Buffer
		c := f(strings.NewReader(in), &o, &e, opt, d)
		return o.String(), e.String(), c
	}
}

var (
	runClaude = harness(func(r *strings.Reader, o, e *bytes.Buffer, opt Options, d Decider) int {
		return Claude(r, o, e, opt, d)
	})
	runHermes = harness(func(r *strings.Reader, o, e *bytes.Buffer, opt Options, d Decider) int {
		return Hermes(r, o, e, opt, d)
	})
	runGeneric = harness(func(r *strings.Reader, o, e *bytes.Buffer, opt Options, d Decider) int {
		return Generic(r, o, e, opt, d)
	})
)

const (
	askMsg  = "callguard: because [rules/r1]"
	denyMsg = "callguard: because [rules/r1]. Do not try to work around this block; if the action is needed, ask the user to run or approve it."
)

func claudeJSON(decision, reason string) string {
	b, _ := json.Marshal(map[string]any{"hookSpecificOutput": map[string]string{
		"hookEventName": "PreToolUse", "permissionDecision": decision, "permissionDecisionReason": reason,
	}})
	return string(b) + "\n"
}

func TestClaudeTable(t *testing.T) {
	cases := []struct {
		name    string
		file    string
		v       callguard.Verdict
		opt     Options
		wantOut string
	}{
		{"allow", "claude_pretooluse_bash.json", verdict(callguard.Allow, true), Options{}, claudeJSON("allow", askMsg)},
		{"ask", "claude_pretooluse_bash.json", verdict(callguard.Ask, true), Options{}, claudeJSON("ask", askMsg)},
		{"deny", "claude_pretooluse_bash.json", verdict(callguard.Deny, true), Options{}, claudeJSON("deny", denyMsg)},
		{"allow not enforced", "claude_pretooluse_bash.json", verdict(callguard.Allow, false), Options{}, ""},
		{"ask not enforced", "claude_pretooluse_bash.json", verdict(callguard.Ask, false), Options{}, ""},
		{"deny not enforced", "claude_pretooluse_bash.json", verdict(callguard.Deny, false), Options{}, ""},
		{"AskUserQuestion allow is silent", "claude_askuserquestion.json", verdict(callguard.Allow, true), Options{}, ""},
		{"AskUserQuestion ask", "claude_askuserquestion.json", verdict(callguard.Ask, true), Options{}, claudeJSON("ask", askMsg)},
		{"AskUserQuestion deny", "claude_askuserquestion.json", verdict(callguard.Deny, true), Options{}, claudeJSON("deny", denyMsg)},
		{"auto mode allow is silent", "claude_auto_mode_write.json", verdict(callguard.Allow, true), Options{}, ""},
		{"auto mode allow with flag", "claude_auto_mode_write.json", verdict(callguard.Allow, true), Options{AllowInAuto: true}, claudeJSON("allow", askMsg)},
		{"auto mode ask", "claude_auto_mode_write.json", verdict(callguard.Ask, true), Options{}, claudeJSON("ask", askMsg)},
		{"auto mode deny", "claude_auto_mode_write.json", verdict(callguard.Deny, true), Options{}, claudeJSON("deny", denyMsg)},
		{"dontAsk allow", "claude_dontask_bash.json", verdict(callguard.Allow, true), Options{}, claudeJSON("allow", askMsg)},
		{"PostToolUse is ignored", "claude_posttooluse.json", verdict(callguard.Deny, true), Options{}, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			d, _ := capture(c.v)
			out, errOut, code := runClaude(payload(t, c.file), c.opt, d)
			if out != c.wantOut || code != 0 || errOut != "" {
				t.Fatalf("got out=%q err=%q code=%d, want out=%q code=0", out, errOut, code, c.wantOut)
			}
		})
	}
}

func TestClaudePostToolUseDoesNotDecide(t *testing.T) {
	d := func(context.Context, *callguard.Request) callguard.Verdict {
		t.Fatal("decider called for PostToolUse")
		return callguard.Verdict{}
	}
	if out, _, code := runClaude(payload(t, "claude_posttooluse.json"), Options{}, d); out != "" || code != 0 {
		t.Fatalf("out=%q code=%d", out, code)
	}
}

func TestClaudeRequestMapping(t *testing.T) {
	d, got := capture(verdict(callguard.Allow, true))
	runClaude(payload(t, "claude_pretooluse_bash.json"), Options{}, d)
	want := callguard.Request{
		Schema: callguard.RequestSchema, V: 1, Harness: "claude",
		SessionID: "abc123", ToolUseID: "toolu_01ABC123", Cwd: "/home/user/my-project",
		PermissionMode: "default",
		Transcript: &callguard.Transcript{
			Path:   "/home/user/.claude/projects/my-project/00893aaf-19fa-41d2-8238-13269b9b3ca0.jsonl",
			Format: "claude-jsonl",
		},
	}
	if got.Tool.Name != "Bash" {
		t.Fatalf("tool %q", got.Tool.Name)
	}
	var in map[string]any
	if err := json.Unmarshal(got.Tool.Input, &in); err != nil || in["command"] != "npm test" || in["timeout"] != float64(120000) {
		t.Fatalf("input %s (%v)", got.Tool.Input, err)
	}
	got.Tool = callguard.ToolCall{}
	if !reflect.DeepEqual(*got, want) {
		t.Fatalf("got %+v\nwant %+v", *got, want)
	}

	// dontAsk and --unattended both set Unattended.
	d, got = capture(verdict(callguard.Allow, true))
	runClaude(payload(t, "claude_dontask_bash.json"), Options{}, d)
	if !got.Unattended || got.PermissionMode != "dontAsk" {
		t.Fatalf("dontAsk: %+v", *got)
	}
	d, got = capture(verdict(callguard.Allow, true))
	runClaude(payload(t, "claude_pretooluse_bash.json"), Options{Unattended: true}, d)
	if !got.Unattended {
		t.Fatal("--unattended not applied")
	}

	// Unknown fields are ignored; no transcript path means no transcript.
	d, got = capture(verdict(callguard.Allow, true))
	runClaude(`{"hook_event_name":"PreToolUse","tool_name":"Read","tool_input":{"file_path":"/x"},"extra":1}`, Options{}, d)
	if got.Tool.Name != "Read" || got.Transcript != nil {
		t.Fatalf("%+v", *got)
	}
}

// assertClaudeSafe checks the exit-code rule and that nothing allows.
func assertClaudeSafe(t *testing.T, out, errOut string, code int, wantDecision string) {
	t.Helper()
	if code != 0 && code != 2 {
		t.Fatalf("exit %d: Claude would run the tool (out=%q err=%q)", code, out, errOut)
	}
	if code == 2 {
		if strings.TrimSpace(errOut) == "" {
			t.Fatal("exit 2 without a reason on stderr")
		}
		return
	}
	var o claudeOutput
	if err := json.Unmarshal([]byte(out), &o); err != nil {
		t.Fatalf("exit 0 without a JSON decision: %q", out)
	}
	if got := o.HookSpecificOutput.PermissionDecision; got != wantDecision {
		t.Fatalf("decision %q, want %q (%q)", got, wantDecision, out)
	}
}

func TestClaudeNeverFailsOpen(t *testing.T) {
	okDecider, _ := capture(verdict(callguard.Allow, true))
	cases := []struct {
		name string
		in   string
		opt  Options
		d    Decider
	}{
		{"garbage", "this is not json", Options{}, okDecider},
		{"empty body", "", Options{}, okDecider},
		{"empty object", "{}", Options{}, okDecider},
		{"json array", "[1,2]", Options{}, okDecider},
		{"missing tool_name", `{"hook_event_name":"PreToolUse"}`, Options{}, okDecider},
		{"panicking decider", payload(t, "claude_pretooluse_bash.json"), Options{}, panicking},
		{"invalid verdict", payload(t, "claude_pretooluse_bash.json"), Options{}, func(context.Context, *callguard.Request) callguard.Verdict {
			return callguard.Verdict{}
		}},
		{"nil decider", payload(t, "claude_pretooluse_bash.json"), Options{}, nil},
		{"oversize", `{"x":"` + strings.Repeat("a", MaxInput) + `"}`, Options{}, okDecider},
	}
	for _, c := range cases {
		for _, unattended := range []bool{false, true} {
			t.Run(c.name, func(t *testing.T) {
				opt := c.opt
				opt.Unattended = unattended
				want := "ask"
				if unattended {
					want = "deny"
				}
				out, errOut, code := runClaude(c.in, opt, c.d)
				assertClaudeSafe(t, out, errOut, code, want)
				if code == 0 && out == "" {
					t.Fatal("silent exit 0 on a failure")
				}
			})
		}
	}
}

type failWriter struct{}

func (failWriter) Write([]byte) (int, error) { return 0, errors.New("closed") }

func TestClaudeWriteFailureExits2(t *testing.T) {
	var e bytes.Buffer
	d, _ := capture(verdict(callguard.Deny, true))
	code := Claude(strings.NewReader(payload(t, "claude_pretooluse_bash.json")), failWriter{}, &e, Options{}, d)
	if code != 2 || e.Len() == 0 {
		t.Fatalf("code=%d stderr=%q", code, e.String())
	}
}

func TestContextFlagsAndFile(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "ctx.json")
	if err := os.WriteFile(file, []byte(`{"trust":"tainted","data_class":"private","principal":"alice"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	opt := Options{Context: map[string]string{"data_class": "open", "zone": "z1"}, ContextFile: file}
	want := map[string]string{"trust": "tainted", "data_class": "open", "principal": "alice", "zone": "z1"}

	for name, run := range map[string]struct {
		run runFn
		in  string
	}{
		"claude":  {runClaude, payload(t, "claude_pretooluse_bash.json")},
		"hermes":  {runHermes, payload(t, "hermes_pre_tool_call_terminal.json")},
		"generic": {runGeneric, `{"tool":"bash","input":{"command":"ls"}}`},
	} {
		t.Run(name, func(t *testing.T) {
			d, got := capture(verdict(callguard.Ask, true))
			run.run(run.in, opt, d)
			if !reflect.DeepEqual(got.Context, want) {
				t.Fatalf("context %v, want %v", got.Context, want)
			}
		})
	}

	t.Run("flags override the generic request context", func(t *testing.T) {
		d, got := capture(verdict(callguard.Ask, true))
		runGeneric(payload(t, "generic_opencode_bash.json"), Options{Context: map[string]string{"trust": "trusted"}}, d)
		if got.Context["trust"] != "trusted" {
			t.Fatalf("%v", got.Context)
		}
	})

	for name, content := range map[string]string{"missing": "", "invalid JSON": "{", "not strings": `{"a":1}`, "array": `[]`} {
		t.Run("bad context file: "+name, func(t *testing.T) {
			path := filepath.Join(dir, "bad.json")
			if content == "" {
				path = filepath.Join(dir, "does-not-exist.json")
			} else if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
				t.Fatal(err)
			}
			decided := false
			d := func(context.Context, *callguard.Request) callguard.Verdict {
				decided = true
				return verdict(callguard.Allow, true)
			}
			out, errOut, code := runClaude(payload(t, "claude_pretooluse_bash.json"), Options{ContextFile: path}, d)
			if decided {
				t.Fatal("decider ran despite a bad context file")
			}
			assertClaudeSafe(t, out, errOut, code, "ask")
			out, _, code = runClaude(payload(t, "claude_dontask_bash.json"), Options{ContextFile: path}, d)
			assertClaudeSafe(t, out, "", code, "deny")
		})
	}
}

func hermesJSON(action, msg, key string) string {
	m := map[string]string{"action": action, "message": msg}
	if key != "" {
		m["rule_key"] = key
	}
	b, _ := json.Marshal(m)
	return string(b) + "\n"
}

func TestHermesTable(t *testing.T) {
	cases := []struct {
		name     string
		file     string
		v        callguard.Verdict
		wantOut  string
		wantCode int
	}{
		{"allow", "hermes_pre_tool_call_terminal.json", verdict(callguard.Allow, true), "{}\n", 0},
		{"ask", "hermes_pre_tool_call_terminal.json", verdict(callguard.Ask, true), hermesJSON("approve", askMsg, "callguard:rules:r1"), 0},
		{"deny", "hermes_pre_tool_call_terminal.json", verdict(callguard.Deny, true), hermesJSON("block", denyMsg, ""), 2},
		{"allow not enforced", "hermes_pre_tool_call_terminal.json", verdict(callguard.Allow, false), "{}\n", 0},
		{"ask not enforced", "hermes_pre_tool_call_terminal.json", verdict(callguard.Ask, false), "{}\n", 0},
		{"deny not enforced", "hermes_pre_tool_call_terminal.json", verdict(callguard.Deny, false), "{}\n", 0},
		{"post_tool_call", "hermes_post_tool_call.json", verdict(callguard.Deny, true), "{}\n", 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			d, _ := capture(c.v)
			out, errOut, code := runHermes(payload(t, c.file), Options{}, d)
			if out != c.wantOut || code != c.wantCode || errOut != "" {
				t.Fatalf("got out=%q err=%q code=%d, want out=%q code=%d", out, errOut, code, c.wantOut, c.wantCode)
			}
		})
	}

	t.Run("ask rule key without a rule", func(t *testing.T) {
		v := verdict(callguard.Ask, true)
		v.Rule = ""
		d, _ := capture(v)
		out, _, _ := runHermes(payload(t, "hermes_pre_tool_call_terminal.json"), Options{}, d)
		if !strings.Contains(out, `"rule_key":"callguard:rules"`) {
			t.Fatal(out)
		}
	})
}

func TestHermesRequestMapping(t *testing.T) {
	d, got := capture(verdict(callguard.Allow, true))
	runHermes(payload(t, "hermes_pre_tool_call_terminal.json"), Options{}, d)
	if got.Harness != "hermes" || got.SessionID != "sess_42" || got.Cwd != "/home/user/my-project" ||
		got.Tool.Name != "terminal" || string(got.Tool.Input) != `{"command": "ls -la"}` || got.Unattended {
		t.Fatalf("%+v", *got)
	}
	d, got = capture(verdict(callguard.Allow, true))
	runHermes(payload(t, "hermes_pre_tool_call_terminal.json"), Options{Unattended: true}, d)
	if !got.Unattended {
		t.Fatal("--unattended not applied")
	}
}

func TestHermesNeverFailsOpen(t *testing.T) {
	for name, c := range map[string]struct {
		in string
		d  Decider
	}{
		"garbage": {"nope", nil},
		"empty":   {"", nil},
		"panic":   {payload(t, "hermes_pre_tool_call_terminal.json"), panicking},
	} {
		t.Run(name, func(t *testing.T) {
			out, _, code := runHermes(c.in, Options{}, c.d)
			if code != 0 || !strings.Contains(out, `"action":"approve"`) {
				t.Fatalf("interactive: out=%q code=%d", out, code)
			}
			out, _, code = runHermes(c.in, Options{Unattended: true}, c.d)
			if code != 2 || !strings.Contains(out, `"action":"block"`) {
				t.Fatalf("unattended: out=%q code=%d", out, code)
			}
		})
	}
}

func TestGenericTable(t *testing.T) {
	for _, c := range []struct {
		name string
		v    callguard.Verdict
	}{
		{"allow", verdict(callguard.Allow, true)},
		{"ask", verdict(callguard.Ask, true)},
		{"deny", verdict(callguard.Deny, true)},
		{"allow not enforced", verdict(callguard.Allow, false)},
		{"deny not enforced", verdict(callguard.Deny, false)},
	} {
		t.Run(c.name, func(t *testing.T) {
			d, _ := capture(c.v)
			out, errOut, code := runGeneric(payload(t, "generic_opencode_bash.json"), Options{}, d)
			want, _ := json.Marshal(c.v)
			if out != string(want)+"\n" || code != 0 || errOut != "" {
				t.Fatalf("out=%q err=%q code=%d", out, errOut, code)
			}
		})
	}
}

func TestGenericRequestMapping(t *testing.T) {
	d, got := capture(verdict(callguard.Allow, true))
	runGeneric(payload(t, "generic_opencode_bash.json"), Options{}, d)
	if got.Harness != "opencode" || got.Tool.Name != "bash" || got.Cwd != "/home/user/my-project" ||
		got.SessionID != "ses_9" || got.Context["trust"] != "tainted" || got.Unattended {
		t.Fatalf("%+v", *got)
	}
	d, got = capture(verdict(callguard.Allow, true))
	runGeneric(payload(t, "generic_pi_read.json"), Options{}, d)
	if got.Harness != "pi" || got.ProjectDir != "/home/user/my-project" || !got.Unattended || got.Tool.Name != "read" {
		t.Fatalf("%+v", *got)
	}
}

func TestGenericNeverFailsOpen(t *testing.T) {
	for name, c := range map[string]struct {
		in string
		d  Decider
	}{
		"garbage":      {"nope", nil},
		"empty":        {"", nil},
		"missing tool": {`{"harness":"pi"}`, nil},
		"panic":        {payload(t, "generic_pi_read.json"), panicking},
	} {
		t.Run(name, func(t *testing.T) {
			out, _, code := runGeneric(c.in, Options{}, c.d)
			var v callguard.Verdict
			if err := json.Unmarshal([]byte(out), &v); err != nil || code != 0 {
				t.Fatalf("out=%q code=%d err=%v", out, code, err)
			}
			if v.Decision == callguard.Allow || !v.Decision.Valid() || !v.Enforced {
				t.Fatalf("%+v", v)
			}
		})
	}
	t.Run("unattended denies", func(t *testing.T) {
		out, _, _ := runGeneric("nope", Options{Unattended: true}, nil)
		var v callguard.Verdict
		if err := json.Unmarshal([]byte(out), &v); err != nil || v.Decision != callguard.Deny {
			t.Fatalf("%q", out)
		}
	})
}
