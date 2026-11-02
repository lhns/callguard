package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lhns/callguard"
)

func runCmd(t *testing.T, stdin string, args ...string) (int, string, string) {
	t.Helper()
	var out, errb bytes.Buffer
	code := run(args, strings.NewReader(stdin), &out, &errb)
	return code, out.String(), errb.String()
}

func writeFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func reqJSON(t *testing.T, dir, tool string, input map[string]any, extra map[string]any) string {
	t.Helper()
	m := map[string]any{"schema": "callguard/request/v1", "v": 1, "harness": "claude", "session_id": "s", "cwd": dir,
		"project_dir": dir, "tool": map[string]any{"name": tool, "input": input}}
	for k, v := range extra {
		m[k] = v
	}
	b, _ := json.Marshal(m)
	return string(b)
}

func TestDecideExitCodes(t *testing.T) {
	dir := t.TempDir()
	// LLM off so that nothing needs a backend.
	pol := writeFile(t, dir, "sys.json", `{"policy_version":1,"llm":{"enabled":false}}`)
	base := []string{"decide", "--policy", pol, "--no-user-policy", "--log", "-"}
	tests := []struct {
		name  string
		stdin string
		args  []string
		code  int
		dec   string
		layer string
	}{
		{"allow", reqJSON(t, dir, "Read", map[string]any{"file_path": "a.go"}, nil), nil, 0, "allow", "rules"},
		{"deny", reqJSON(t, dir, "Bash", map[string]any{"command": "rm -rf /"}, nil), nil, 1, "deny", "builtin"},
		{"ask", reqJSON(t, dir, "Bash", map[string]any{"command": "git push --force"}, nil), nil, 2, "ask", "rules"},
		{"none is ask", reqJSON(t, dir, "Bash", map[string]any{"command": "go test"}, nil), nil, 2, "ask", "none"},
		{"unattended flag", reqJSON(t, dir, "Bash", map[string]any{"command": "git push --force"}, nil), []string{"--unattended"}, 1, "deny", "rules"},
		{"unattended in request", reqJSON(t, dir, "Bash", map[string]any{"command": "git push --force"}, map[string]any{"unattended": true}), nil, 1, "deny", "rules"},
		{"bad json", "{not json", nil, 3, "ask", "fallback"},
		{"bad json unattended", "", []string{"--unattended"}, 3, "deny", "fallback"},
		{"no tool", `{"cwd":"/x"}`, nil, 2, "ask", "fallback"},
		{"oversized", `{"tool":{"name":"Bash"},"pad":"` + strings.Repeat("x", 4<<20) + `"}`, nil, 3, "ask", "fallback"},
	}
	for _, tc := range tests {
		code, out, errs := runCmd(t, tc.stdin, append(append([]string{}, base...), tc.args...)...)
		var v callguard.Verdict
		if err := json.Unmarshal([]byte(out), &v); err != nil || !strings.HasSuffix(out, "\n") {
			t.Errorf("%s: stdout is not one JSON line: %q (%v) stderr %q", tc.name, out, err, errs)
			continue
		}
		if code != tc.code || string(v.Decision) != tc.dec || v.Layer != tc.layer || v.Schema != callguard.VerdictSchema {
			t.Errorf("%s: exit %d verdict %+v, want exit %d %s/%s", tc.name, code, v, tc.code, tc.dec, tc.layer)
		}
	}
}

func TestDecideLoadErrors(t *testing.T) {
	dir := t.TempDir()
	req := reqJSON(t, dir, "Read", map[string]any{"file_path": "a.go"}, nil)
	code, out, _ := runCmd(t, req, "decide", "--policy", filepath.Join(dir, "missing.json"), "--no-user-policy", "--log", "-")
	if code != 3 || !strings.Contains(out, `"layer":"fallback"`) || !strings.Contains(out, `"decision":"ask"`) {
		t.Errorf("missing policy: %d %s", code, out)
	}
	bad := writeFile(t, dir, "bad.json", `{"policy_version":9}`)
	code, out, _ = runCmd(t, req, "decide", "--policy", bad, "--no-user-policy", "--log", "-", "--unattended")
	if code != 3 || !strings.Contains(out, `"decision":"deny"`) {
		t.Errorf("bad policy unattended: %d %s", code, out)
	}
	if code, _, _ := runCmd(t, req, "decide", "--bogus"); code != 64 {
		t.Errorf("bad flag: %d", code)
	}
}

func TestDecideUsesProjectPolicyAndLog(t *testing.T) {
	dir := t.TempDir()
	pol := writeFile(t, dir, "sys.json", `{"policy_version":1,"llm":{"enabled":false}}`)
	writeFile(t, dir, ".callguard/policy.json", `{"policy_version":1,"rules":[{"id":"no-make","decision":"deny","description":"no make","match":{"kind":["shell"],"command":"^make"}}]}`)
	logp := filepath.Join(dir, "d.jsonl")
	code, out, _ := runCmd(t, reqJSON(t, dir, "Bash", map[string]any{"command": "make all"}, nil),
		"decide", "--policy", pol, "--no-user-policy", "--log", logp)
	if code != 1 || !strings.Contains(out, `"rule":"no-make"`) {
		t.Errorf("project rule: %d %s", code, out)
	}
	if data, err := os.ReadFile(logp); err != nil || !strings.Contains(string(data), `"rule":"no-make"`) {
		t.Errorf("log: %v %s", err, data)
	}
}

func TestPolicyCheck(t *testing.T) {
	dir := t.TempDir()
	code, out, _ := runCmd(t, "", "policy", "check", "--policy", writeFile(t, dir, "ok.json", `{"policy_version":1}`), "--no-user-policy")
	if code != 0 || !strings.Contains(out, "policy_rev: sha256:") || !strings.Contains(out, "read-in-project") || !strings.HasSuffix(strings.TrimSpace(out), "ok") {
		t.Errorf("ok: %d %s", code, out)
	}

	bad := writeFile(t, dir, "bad.json", `{"policy_version":1,"bogus":1,
		"rules":[{"id":"nocond","decision":"ask"},{"id":"re","decision":"ask","match":{"command":"("}},
		{"id":"glob","decision":"ask","match":{"path":["[x"]}},{"id":"dec","decision":"maybe","match":{"kind":["shell"]}}],
		"llm":{"backend":"ghost"},
		"backends":{"m":{"type":"anthropic","model":"claude-haiku-latest"},"w":{"type":"weird"}}}`)
	proj := filepath.Join(dir, "proj")
	writeFile(t, proj, ".callguard/policy.json", `{"policy_version":1,"mode":"shadow"}`)
	code, out, _ = runCmd(t, "", "policy", "check", "--policy", bad, "--no-user-policy", "--project-dir", proj)
	if code != 1 {
		t.Errorf("bad policy exit %d", code)
	}
	for _, want := range []string{`unknown key "bogus"`, "no match conditions", "match.command", "match.path", `decision "maybe"`,
		`llm.backend "ghost"`, "moving alias", `unknown type "weird"`, "warning: ", "mode ignored", "proj"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}

	code, out, _ = runCmd(t, "", "policy", "check", "--json", "--policy", bad, "--no-user-policy")
	var rep struct {
		Files     []string       `json:"files"`
		PolicyRev string         `json:"policy_rev"`
		Policy    map[string]any `json:"policy"`
		Warnings  []string       `json:"warnings"`
		Errors    []string       `json:"errors"`
	}
	if err := json.Unmarshal([]byte(out), &rep); err != nil || code != 1 || len(rep.Errors) < 6 || len(rep.Files) != 1 || rep.Policy == nil {
		t.Errorf("json report: %d %v %s", code, err, out)
	}

	code, out, _ = runCmd(t, "", "policy", "check", "--json", "--policy", writeFile(t, dir, "ok2.json", `{"policy_version":1}`), "--no-user-policy")
	if err := json.Unmarshal([]byte(out), &rep); err != nil || code != 0 || len(rep.Errors) != 0 || rep.PolicyRev == "" {
		t.Errorf("json ok: %d %v %s", code, err, out)
	}

	if code, out, _ := runCmd(t, "", "policy", "check", "--policy", filepath.Join(dir, "missing.json"), "--no-user-policy"); code != 1 || !strings.Contains(out, "error:") {
		t.Errorf("missing file: %d %s", code, out)
	}
	if code, _, _ := runCmd(t, "", "policy", "check", "--policy", writeFile(t, dir, "v.json", `{"policy_version":3}`), "--no-user-policy"); code != 1 {
		t.Errorf("bad version: %d", code)
	}
	for _, args := range [][]string{{"policy"}, {"policy", "frob"}} {
		if code, _, errs := runCmd(t, "", args...); code != 64 || !strings.Contains(errs, "usage") {
			t.Errorf("%v: %d %q", args, code, errs)
		}
	}
	if code, _, _ := runCmd(t, "", "policy", "check", "--nope"); code != 64 {
		t.Errorf("bad flag: %d", code)
	}
}
