package policy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func write(t *testing.T, path, content string) string {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// layers builds a system file, a user config dir and a project dir.
func layers(t *testing.T, system, user, project string) LoadOptions {
	t.Helper()
	d := t.TempDir()
	o := LoadOptions{UserConfigDir: "-"}
	o.SystemPolicy = write(t, filepath.Join(d, "system.json"), system)
	if user != "" {
		o.UserConfigDir = filepath.Join(d, "cfg")
		write(t, filepath.Join(o.UserConfigDir, "callguard", "policy.json"), user)
	}
	if project != "" {
		o.ProjectDir = filepath.Join(d, "proj")
		write(t, filepath.Join(o.ProjectDir, ".callguard", "policy.json"), project)
	}
	return o
}

func ruleIDs(p Policy) string {
	var ids []string
	for _, r := range p.Rules {
		ids = append(ids, r.ID)
	}
	return strings.Join(ids, ",")
}

func TestDefaultValues(t *testing.T) {
	p := Default()
	if p.Mode != "enforce" || p.UnattendedAsk != "deny" || p.DeadlineMS != 8000 {
		t.Errorf("globals: %+v", p)
	}
	if p.Nah.Enabled || p.Nah.Path != "nah" || p.Nah.TimeoutMS != 2000 {
		t.Errorf("nah: %+v", p.Nah)
	}
	l := p.LLM
	if !p.LLMEnabled() || l.Mode != "shadow" || l.Backend != "anthropic" || l.TimeoutMS != 3000 || *l.MinConfidence != 0.7 ||
		l.Transcript.MaxMessages != 20 || l.Transcript.MaxBytes != 24000 {
		t.Errorf("llm: %+v", l)
	}
	b := p.Backends["anthropic"]
	if b.Type != "anthropic" || b.Model != "claude-haiku-5-5" || b.APIKeyEnv != "ANTHROPIC_API_KEY" ||
		b.BaseURL != "https://api.anthropic.com" || strings.Join(b.DataClasses, ",") != "open,private" {
		t.Errorf("anthropic: %+v", b)
	}
	if probs := Validate(p, true); len(probs) > 0 {
		t.Errorf("default policy invalid: %v", probs)
	}
	if WithDefaults(p).LLM.Mode != "shadow" || Rev(WithDefaults(p)) != Rev(p) {
		t.Error("WithDefaults must be idempotent")
	}
}

func TestWithDefaultsDoesNotMutate(t *testing.T) {
	l := &LLM{Mode: "enforce"}
	p := Policy{LLM: l}
	_ = WithDefaults(p)
	if l.Backend != "" || l.Transcript != nil {
		t.Errorf("input mutated: %+v", l)
	}
}

func TestMergeSystem(t *testing.T) {
	o := layers(t, `{"policy_version":1,"mode":"shadow","unattended_ask":"ask","deadline_ms":500,
		"rules":[{"id":"mine","decision":"allow","match":{"kind":["fetch"]}},{"id":"sudo","decision":"deny","match":{"command":"sudo"}}],
		"nah":{"enabled":true,"path":"/x/nah"},
		"llm":{"mode":"enforce","min_confidence":0.9,"block":["no prod"],"transcript":{"max_messages":5}},
		"backends":{"local":{"type":"openai","model":"m","base_url":"http://x"}},
		"disable_builtin":["fork-bomb"]}`, "", "")
	l, err := Load(o)
	if err != nil {
		t.Fatal(err)
	}
	p := l.Policy
	if p.Mode != "shadow" || p.UnattendedAsk != "ask" || p.DeadlineMS != 500 {
		t.Errorf("globals: %+v", p)
	}
	if !p.Nah.Enabled || p.Nah.Path != "/x/nah" || p.Nah.TimeoutMS != 2000 {
		t.Errorf("nah: %+v", p.Nah)
	}
	if p.LLM.Mode != "enforce" || *p.LLM.MinConfidence != 0.9 || p.LLM.Transcript.MaxMessages != 5 ||
		p.LLM.Transcript.MaxBytes != 24000 || len(p.LLM.Block) != 1 || p.LLM.Backend != "anthropic" {
		t.Errorf("llm: %+v", p.LLM)
	}
	if _, ok := p.Backends["local"]; !ok || p.Backends["anthropic"].Model == "" {
		t.Errorf("backends: %+v", p.Backends)
	}
	if !strings.HasSuffix(ruleIDs(p), ",mine") {
		t.Errorf("rules: %s", ruleIDs(p))
	}
	for _, r := range p.Rules {
		if r.ID == "sudo" && r.Decision != "deny" {
			t.Error("system rule with a default's id replaces it")
		}
	}
	if len(l.Warnings) != 0 || len(l.Problems()) != 0 {
		t.Errorf("warnings %v problems %v", l.Warnings, l.Problems())
	}
}

func TestDefaultsFalse(t *testing.T) {
	l, err := Load(layers(t, `{"policy_version":1,"defaults":false,"rules":[{"id":"only","decision":"ask","match":{"kind":["shell"]}}]}`, "", ""))
	if err != nil {
		t.Fatal(err)
	}
	if ruleIDs(l.Policy) != "only" {
		t.Errorf("rules: %s", ruleIDs(l.Policy))
	}
}

func TestTightenOnly(t *testing.T) {
	user := `{"policy_version":1,"mode":"shadow","defaults":false,"unattended_ask":"ask","deadline_ms":1,
		"rules":[{"id":"u-deny","decision":"deny","match":{"command":"x"}},{"id":"u-allow","decision":"allow","match":{"command":"y"}},
		         {"id":"sudo","decision":"ask","match":{"command":"z"}}],
		"nah":{"enabled":true},"backends":{"b":{"type":"fake"}},"deny_streak":{"consecutive":1},"log":{"disabled":true},
		"disable_builtin":["rm-root"],"final":true,
		"llm":{"enabled":false,"mode":"enforce","backend":"b","timeout_ms":1,"environment":["e"],"allow_exceptions":["a"],
		       "transcript":{"max_bytes":1},"block":["u-block"],"min_confidence":0.95}}`
	project := `{"policy_version":1,"rules":[{"id":"p-ask","decision":"ask","match":{"command":"p"}}],
		"llm":{"block":["p-block"],"min_confidence":0.5}}`
	l, err := Load(layers(t, `{"policy_version":1,"llm":{"min_confidence":0.8}}`, user, project))
	if err != nil {
		t.Fatal(err)
	}
	p := l.Policy
	if p.Mode != "enforce" || p.Nah.Enabled || p.UnattendedAsk != "deny" || p.DeadlineMS != 8000 || p.Final || p.DenyStreak != nil ||
		p.Log != nil || len(p.DisableBuiltin) != 0 || len(p.Backends) != 1 {
		t.Errorf("loosening leaked through: %+v", p)
	}
	if !p.LLMEnabled() || p.LLM.Mode != "shadow" || p.LLM.Backend != "anthropic" || p.LLM.TimeoutMS != 3000 ||
		len(p.LLM.Environment) != 0 || len(p.LLM.AllowExceptions) != 0 || p.LLM.Transcript.MaxBytes != 24000 {
		t.Errorf("llm loosened: %+v", p.LLM)
	}
	if strings.Join(p.LLM.Block, ",") != "u-block,p-block" {
		t.Errorf("block: %v", p.LLM.Block)
	}
	if *p.LLM.MinConfidence != 0.95 {
		t.Errorf("min_confidence raised by user then lowered by project: %v", *p.LLM.MinConfidence)
	}
	ids := ruleIDs(p)
	if !strings.Contains(ids, "u-deny") || !strings.Contains(ids, "p-ask") || strings.Contains(ids, "u-allow") || !strings.Contains(ids, "read-in-project") {
		t.Errorf("rules: %s", ids)
	}
	kept := false
	for _, r := range p.Rules {
		kept = kept || r.ID == "sudo" && r.Match.Command == SudoRE
	}
	if !kept {
		t.Error("a user rule with a default's id must not replace the default")
	}
	for _, key := range []string{"mode", "defaults", "unattended_ask", "deadline_ms", "final", "nah", "backends", "deny_streak", "log",
		"disable_builtin", "rules.u-allow", "llm.enabled", "llm.mode", "llm.backend", "llm.timeout_ms", "llm.environment",
		"llm.allow_exceptions", "llm.transcript", "llm.min_confidence"} {
		found := false
		for _, w := range l.Warnings {
			if strings.Contains(w, "policy.json: "+key+" ignored") {
				found = true
			}
		}
		if !found {
			t.Errorf("no warning naming key %q in %q", key, l.Warnings)
		}
	}
}

func TestFinalSkipsLowerLayers(t *testing.T) {
	o := layers(t, `{"policy_version":1,"final":true}`, `{"policy_version":1,"rules":[{"id":"u","decision":"deny","match":{"command":"x"}}]}`,
		`{"policy_version":1,"this is not json`)
	l, err := Load(o)
	if err != nil {
		t.Fatalf("a final system policy must not read user or project files: %v", err)
	}
	if strings.Contains(ruleIDs(l.Policy), "u") && strings.Contains(ruleIDs(l.Policy), ",u") || len(l.Files) != 1 {
		t.Errorf("files %d rules %s", len(l.Files), ruleIDs(l.Policy))
	}
}

func TestLoadErrors(t *testing.T) {
	d := t.TempDir()
	if _, err := Load(LoadOptions{SystemPolicy: filepath.Join(d, "missing.json"), UserConfigDir: "-"}); err == nil {
		t.Error("explicit missing system policy must fail")
	}
	bad := write(t, filepath.Join(d, "v2.json"), `{"policy_version":2}`)
	if _, err := Load(LoadOptions{SystemPolicy: bad, UserConfigDir: "-"}); err == nil || !strings.Contains(err.Error(), "policy_version") {
		t.Errorf("bad version: %v", err)
	}
	none := write(t, filepath.Join(d, "none.json"), `{}`)
	if _, err := Load(LoadOptions{SystemPolicy: none, UserConfigDir: "-"}); err == nil {
		t.Error("missing policy_version must fail")
	}
	junk := write(t, filepath.Join(d, "junk.json"), `{`)
	if _, err := Load(LoadOptions{SystemPolicy: junk, UserConfigDir: "-"}); err == nil {
		t.Error("bad JSON must fail")
	}
	// A bad user file fails too: never ignore a layer silently.
	o := layers(t, `{"policy_version":1}`, `{"policy_version":7}`, "")
	if _, err := Load(o); err == nil {
		t.Error("bad user version must fail")
	}
	// The default system path may be absent; a BOM is tolerated.
	bom := write(t, filepath.Join(d, "bom.json"), "\xef\xbb\xbf{\"policy_version\":1}")
	if _, err := Load(LoadOptions{SystemPolicy: bom, UserConfigDir: "-"}); err != nil {
		t.Errorf("BOM: %v", err)
	}
	if l, err := Load(LoadOptions{UserConfigDir: "-"}); err != nil || len(l.Files) > 1 {
		t.Errorf("default load: %v %v", err, l.Files)
	}
}

func TestUnknownKeysAndWarnings(t *testing.T) {
	src := `{"policy_version":1,"bogus":1,"rules":[{"id":"a","decision":"ask","match":{"command":"x","nope":1},"extra":2}],
		"llm":{"mode":"shadow","wat":true},"backends":{"b":{"type":"fake","zzz":1}}}`
	got := strings.Join(UnknownKeys([]byte(src)), ",")
	want := "backends.b.zzz,bogus,llm.wat,rules[0].extra,rules[0].match.nope"
	if got != want {
		t.Errorf("unknown keys %q, want %q", got, want)
	}
	l, err := Load(layers(t, src, "", ""))
	if err != nil {
		t.Fatal(err)
	}
	if len(l.Warnings) != 5 || !strings.Contains(l.Warnings[0], "unknown key") {
		t.Errorf("warnings: %q", l.Warnings)
	}
}

func TestValidate(t *testing.T) {
	bad := Policy{
		PolicyVersion: 1, Mode: "loud", UnattendedAsk: "allow", DisableBuiltin: []string{"nope"},
		Rules: []Rule{{ID: "a", Decision: "ask"}, {Decision: "ask", Match: Match{Kind: []string{"shell"}}},
			{ID: "c", Decision: "permit", Match: Match{Kind: []string{"shell"}}}},
		Nah: &Nah{Mode: "x"},
		LLM: &LLM{Mode: "y", Backend: "missing", MinConfidence: Float(1.5)},
		Backends: map[string]Backend{"l": {Type: "anthropic", Model: "claude-haiku-latest"}, "e": {Type: "exec"},
			"u": {Type: "weird"}},
		DenyStreak: &DenyStreak{Consecutive: -1},
	}
	probs := strings.Join(Validate(bad, true), "\n")
	for _, want := range []string{"mode \"loud\"", "unattended_ask", "unknown built-in rule", "no match conditions", "missing id",
		"decision \"permit\"", "nah.mode", "llm.mode", "min_confidence", "not defined in backends", "moving alias",
		"exec backend needs command", "unknown type", "deny_streak"} {
		if !strings.Contains(probs, want) {
			t.Errorf("missing problem %q in:\n%s", want, probs)
		}
	}
	if len(Validate(bad, false)) >= len(Validate(bad, true)) {
		t.Error("llm.backend cross-reference only checked for merged policies")
	}
}

func TestRevStable(t *testing.T) {
	a, b := Rev(Default()), Rev(Default())
	if a != b || !strings.HasPrefix(a, "sha256:") || len(a) != 7+64 {
		t.Errorf("rev %q %q", a, b)
	}
	p := Default()
	p.Mode = "shadow"
	if Rev(p) == a {
		t.Error("rev must change with the policy")
	}
}
