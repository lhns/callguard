package rules

import (
	"encoding/json"
	"runtime"
	"testing"

	"github.com/lhns/callguard/policy"
)

var (
	unix = Env{Home: "/home/u"}
	win  = Env{Home: "C:/Users/u", Windows: true}
)

func TestKindOf(t *testing.T) {
	for tool, want := range map[string]string{
		"Bash": KindShell, "PowerShell": KindShell, "bash": KindShell, "terminal": KindShell, "execute_code": KindShell, "process": KindShell,
		"Read": KindRead, "Glob": KindRead, "Grep": KindRead, "LS": KindRead, "list": KindRead, "find": KindRead, "ls": KindRead, "read_file": KindRead, "search_files": KindRead,
		"Write": KindWrite, "Edit": KindWrite, "MultiEdit": KindWrite, "NotebookEdit": KindWrite, "patch": KindWrite, "multi-edit": KindWrite, "write_file": KindWrite,
		"WebFetch": KindFetch, "websearch": KindFetch, "web_extract": KindFetch,
		"Task": KindAgent, "Agent": KindAgent, "task": KindAgent,
		"mcp__github__create_issue": KindMCP, "mcp__": KindOther, "Nope": KindOther, "": KindOther,
	} {
		if got := KindOf(tool); got != want {
			t.Errorf("KindOf(%q) = %q, want %q", tool, got, want)
		}
	}
}

func TestNormalizeAndInDir(t *testing.T) {
	tests := []struct {
		env          Env
		p, cwd, want string
		dir          string
		inDir        bool
	}{
		{unix, "src/a.go", "/work/p", "/work/p/src/a.go", "/work/p", true},
		{unix, "../x", "/work/p", "/work/x", "/work/p", false},
		{unix, "/work/p/../p/a", "/", "/work/p/a", "/work/p", true},
		{unix, "~/notes", "/work/p", "/home/u/notes", "/home/u", true},
		{unix, "/work/pp/a", "/", "/work/pp/a", "/work/p", false}, // sibling with common prefix
		{unix, "/work/p", "/", "/work/p", "/work/p", true},
		{unix, "/work/P/a", "/", "/work/P/a", "/work/p", false}, // case-sensitive
		{unix, `a\b`, "/w", `/w/a\b`, "/w", true},               // backslash is a name character
		{win, `src\a.go`, `C:\Work\p`, "C:/Work/p/src/a.go", `C:\Work\p`, true},
		{win, `c:\work\P\a`, `C:\x`, "c:/work/P/a", `C:\Work\p`, true}, // case-insensitive
		{win, `~\.ssh\id_rsa`, `C:\x`, "C:/Users/u/.ssh/id_rsa", `C:\Users\u`, true},
		{win, `C:\`, ``, "C:/", `C:\`, true},
		{win, `D:\other`, `C:\Work`, "D:/other", `C:\Work`, false},
	}
	for _, tc := range tests {
		got := tc.env.Normalize(tc.p, tc.cwd)
		if got != tc.want {
			t.Errorf("Normalize(%q,%q) = %q, want %q", tc.p, tc.cwd, got, tc.want)
		}
		if in := tc.env.InDir(got, tc.env.Normalize(tc.dir, "")); in != tc.inDir {
			t.Errorf("InDir(%q,%q) = %v, want %v", got, tc.dir, in, tc.inDir)
		}
	}
	if got := unix.Normalize("rel/x", ""); got != "rel/x" {
		t.Errorf("relative path without cwd = %q", got)
	}
}

func TestGlob(t *testing.T) {
	tests := []struct {
		env   Env
		glob  string
		path  string
		match bool
	}{
		{unix, "**/.ssh/**", "/home/u/.ssh/id_rsa", true},
		{unix, "**/.ssh/**", "/home/u/.ssh", true},
		{unix, "**/.ssh/**", "/home/u/ssh/id_rsa", false},
		{unix, "**/.env", "/p/.env", true},
		{unix, "**/.env", "/.env", true},
		{unix, "**/.env", "/p/.env.local", false},
		{unix, "**/.env.*", "/p/.env.local", true},
		{unix, "**/*.pem", "/p/a/b/key.pem", true},
		{unix, "**/*.pem", "/p/key.pem.txt", false},
		{unix, "**/id_rsa*", "/h/.ssh/id_rsa.pub", true},
		{unix, "/p/*/x", "/p/a/x", true},
		{unix, "/p/*/x", "/p/a/b/x", false},
		{unix, "/p/**/x", "/p/x", true},
		{unix, "/p/**/x", "/p/a/b/x", true},
		{unix, "/p/?", "/p/a", true},
		{unix, "/p/[ab]", "/p/b", true},
		{unix, "/p/[!ab]", "/p/b", false},
		{unix, "~/.config/**", "/home/u/.config/a", true},
		{unix, "/p/a+b(c)", "/p/a+b(c)", true},
		{win, "**/.SSH/**", "C:/Users/u/.ssh/id_rsa", true},
		{win, `**\.claude\settings.json`, "C:/p/.claude/settings.json", true},
		{unix, "**/.git/**", "/p/.github/x", false},
	}
	for _, tc := range tests {
		re, err := tc.env.CompileGlob(tc.glob)
		if err != nil {
			t.Fatalf("%q: %v", tc.glob, err)
		}
		if got := re.MatchString(tc.path); got != tc.match {
			t.Errorf("glob %q vs %q = %v, want %v (%s)", tc.glob, tc.path, got, tc.match, re)
		}
	}
	if _, err := unix.CompileGlob("/p/[ab"); err == nil {
		t.Error("unclosed [ should fail")
	}
}

func TestNewCall(t *testing.T) {
	in := func(s string) json.RawMessage { return json.RawMessage(s) }
	c := NewCall(CallInput{Tool: "Read", Input: in(`{"file_path":"src/a.go"}`), Cwd: "/w/p", ProjectDir: "/w/p"}, unix)
	if c.Kind != KindRead || c.Path != "/w/p/src/a.go" || !c.InProject {
		t.Errorf("read: %+v", c)
	}
	c = NewCall(CallInput{Tool: "Read", Input: in(`{"file_path":"/etc/passwd"}`), Cwd: "/w/p", ProjectDir: "/w/p"}, unix)
	if c.InProject {
		t.Error("/etc/passwd must not be in project")
	}
	c = NewCall(CallInput{Tool: "Grep", Input: in(`{"pattern":"x"}`), Cwd: "/w/p", ProjectDir: "/w/p"}, unix)
	if c.Path != "/w/p" || !c.InProject {
		t.Errorf("grep without path defaults to cwd: %+v", c)
	}
	c = NewCall(CallInput{Tool: "Write", Input: in(`{"filePath":"a"}`), Cwd: "/w/p"}, unix)
	if c.Path != "/w/p/a" || c.InProject {
		t.Errorf("no project dir means not in project: %+v", c)
	}
	c = NewCall(CallInput{Tool: "NotebookEdit", Input: in(`{"notebook_path":"n.ipynb"}`), Cwd: "/w"}, unix)
	if c.Path != "/w/n.ipynb" {
		t.Errorf("notebook_path: %+v", c)
	}
	c = NewCall(CallInput{Tool: "execute_code", Input: in(`{"code":"print(1)"}`)}, unix)
	if c.Command != "print(1)" {
		t.Errorf("execute_code command: %q", c.Command)
	}
	c = NewCall(CallInput{Tool: "WebFetch", Input: in(`{"url":"https://x.test","n":3}`)}, unix)
	if c.URL != "https://x.test" || c.Fields["n"] != "3" {
		t.Errorf("fetch: %+v", c)
	}
	c = NewCall(CallInput{Tool: "Bash", Input: in(`not json`)}, unix)
	if c.Command != "" {
		t.Errorf("bad input: %+v", c)
	}
	if runtime.GOOS == "windows" && !DefaultEnv().Windows {
		t.Error("DefaultEnv must be Windows on windows")
	}
}

func mustCompile(t *testing.T, env Env, rs ...policy.Rule) *Set {
	t.Helper()
	s, err := Compile(rs, env)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestPrecedence(t *testing.T) {
	sh := func(id, dec, cmd string) policy.Rule {
		return policy.Rule{ID: id, Decision: dec, Match: policy.Match{Kind: []string{"shell"}, Command: cmd}}
	}
	s := mustCompile(t, unix, sh("a", "allow", "git"), sh("b", "ask", "git"), sh("c", "deny", "push"), sh("d", "deny", "git"))
	call := func(cmd string) Call {
		return NewCall(CallInput{Tool: "Bash", Input: json.RawMessage(`{"command":"` + cmd + `"}`)}, unix)
	}
	if r, ok := s.Match(call("git push")); !ok || r.ID != "c" {
		t.Errorf("first deny wins: %+v", r)
	}
	if r, _ := s.Match(call("git log")); r.ID != "d" {
		t.Errorf("deny beats ask and allow: %+v", r)
	}
	s = mustCompile(t, unix, sh("a", "allow", "git"), sh("b", "ask", "git"), sh("c", "ask", "git"))
	if r, _ := s.Match(call("git log")); r.ID != "b" {
		t.Errorf("ask beats allow, first wins ties: %+v", r)
	}
	if _, ok := s.Match(call("ls")); ok {
		t.Error("no rule should match ls")
	}
}

func TestConditions(t *testing.T) {
	tests := []struct {
		name  string
		tool  string
		m     policy.Match
		input string
		want  bool
	}{
		{"tool", "Bash", policy.Match{Tool: []string{"Bash", "bash"}}, `{}`, true},
		{"tool exact", "Bash", policy.Match{Tool: []string{"bash"}}, `{}`, false},
		{"harness", "Bash", policy.Match{Harness: []string{"pi"}}, `{}`, false},
		{"context", "Bash", policy.Match{Context: map[string][]string{"trust": {"tainted"}}}, `{}`, true},
		{"context miss", "Bash", policy.Match{Context: map[string][]string{"trust": {"clean"}}}, `{}`, false},
		{"unattended", "Bash", policy.Match{Unattended: policy.Bool(true)}, `{}`, true},
		{"field", "Bash", policy.Match{Field: map[string]string{"command": "^git"}}, `{"command":"git x"}`, true},
		{"field missing", "Bash", policy.Match{Field: map[string]string{"nope": "."}}, `{"command":"git x"}`, false},
		{"field non-string", "Bash", policy.Match{Field: map[string]string{"n": "^3$"}}, `{"n":3}`, true},
		{"whole", "Bash", policy.Match{Field: map[string]string{"*": `"command":"git`}}, `{"command":"git x"}`, true},
		{"whole decoded newline", "Bash", policy.Match{Field: map[string]string{"*": "a\nb"}}, `{"x":"a\nb"}`, true},
		{"command needs command", "Bash", policy.Match{Command: "."}, `{"file_path":"x"}`, false},
		{"url", "WebFetch", policy.Match{URL: `evil\.test`}, `{"url":"https://evil.test/x"}`, true},
		{"path glob", "Write", policy.Match{Path: []string{"/w/**/*.go"}}, `{"file_path":"/w/a/b.go"}`, true},
		{"path glob no path", "Write", policy.Match{Path: []string{"**"}}, `{}`, false},
		{"not_path hit", "Write", policy.Match{Kind: []string{"write"}, NotPath: []string{"**/.git/**"}}, `{"file_path":"/w/.git/x"}`, false},
		{"not_path ok", "Write", policy.Match{Kind: []string{"write"}, NotPath: []string{"**/.git/**"}}, `{"file_path":"/w/x"}`, true},
		{"not_path no path", "Write", policy.Match{Kind: []string{"write"}, NotPath: []string{"**/.git/**"}}, `{}`, true},
		{"in_project false", "Write", policy.Match{InProject: policy.Bool(false)}, `{"file_path":"/etc/x"}`, true},
		{"in_project no path", "Write", policy.Match{InProject: policy.Bool(false)}, `{}`, false},
	}
	for _, tc := range tests {
		set := mustCompile(t, unix, policy.Rule{ID: "r", Decision: "ask", Match: tc.m})
		c := NewCall(CallInput{Tool: tc.tool, Harness: "claude", Input: json.RawMessage(tc.input), Cwd: "/w", ProjectDir: "/w",
			Context: map[string]string{"trust": "tainted"}, Unattended: true}, unix)
		if _, got := set.Match(c); got != tc.want {
			t.Errorf("%s: match = %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestCompileErrors(t *testing.T) {
	for name, r := range map[string]policy.Rule{
		"no conditions": {ID: "x", Decision: "ask"},
		"bad decision":  {ID: "x", Decision: "maybe", Match: policy.Match{Kind: []string{"shell"}}},
		"no id":         {Decision: "ask", Match: policy.Match{Kind: []string{"shell"}}},
		"bad regex":     {ID: "x", Decision: "ask", Match: policy.Match{Command: "("}},
		"bad field":     {ID: "x", Decision: "ask", Match: policy.Match{Field: map[string]string{"a": "("}}},
		"bad glob":      {ID: "x", Decision: "ask", Match: policy.Match{Path: []string{"[a"}}},
	} {
		if _, err := Compile([]policy.Rule{r}, unix); err == nil {
			t.Errorf("%s: want error", name)
		}
	}
}
