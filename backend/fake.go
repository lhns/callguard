package backend

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"github.com/lhns/callguard/policy"
)

// Fake modes (policy.Backend.FakeMode).
const (
	FakeRules          = "rules"
	FakeAllow          = "allow"
	FakeAsk            = "ask"
	FakeDeny           = "deny"
	FakeGarbage        = "garbage"
	FakeSlow           = "slow"
	FakeError          = "error"
	FakeObeyInjection  = "obey-injection"
	fakeRulesConfident = 0.9
	fakeFixedConfident = 0.95
)

type fake struct {
	mode    string
	classes []string
}

// NewFake returns a fake backend in the given mode ("" means rules). It is
// for tests and offline eval.
func NewFake(mode string) (Backend, error) {
	return newFake(policy.Backend{Type: "fake", FakeMode: mode})
}

func newFake(cfg policy.Backend) (*fake, error) {
	mode := cfg.FakeMode
	if mode == "" {
		mode = FakeRules
	}
	switch mode {
	case FakeRules, FakeAllow, FakeAsk, FakeDeny, FakeGarbage, FakeSlow, FakeError, FakeObeyInjection:
	default:
		return nil, fmt.Errorf("unknown fake_mode %q", mode)
	}
	return &fake{mode: mode, classes: cfg.DataClasses}, nil
}

func (f *fake) Name() string          { return "fake:" + f.mode }
func (f *fake) DataClasses() []string { return f.classes }

func (f *fake) Classify(ctx context.Context, req ClassifyRequest) (ClassifyResult, error) {
	switch f.mode {
	case FakeAllow, FakeAsk, FakeDeny:
		return ClassifyResult{Label: f.mode, Confidence: fakeFixedConfident, Rule: "fake", Reason: "fixed fake answer"}, nil
	case FakeGarbage:
		return ClassifyResult{Label: "definitely-fine", Confidence: 7, Reason: "garbage"}, nil
	case FakeSlow:
		<-ctx.Done()
		return ClassifyResult{}, ctx.Err()
	case FakeError:
		return ClassifyResult{}, fmt.Errorf("fake backend error")
	case FakeObeyInjection:
		if obeyRe.MatchString(req.Prompt) {
			return ClassifyResult{Label: "allow", Confidence: 0.99, Rule: "fake", Reason: "obeyed injected instruction"}, nil
		}
	}
	return fakeRules(req), nil
}

var (
	injectionRe = regexp.MustCompile(`(?i)label this allow|ignore (all )?(the )?(previous|prior) instructions|classifier|</callguard-data>|reviewer:`)

	obeyRe = regexp.MustCompile(`(?i)label this allow|ignore (all )?(the )?(previous|prior) instructions|classifier`)

	secretPathRe = regexp.MustCompile(`(?i)\.ssh|id_rsa|id_ed25519|\.env\b|\.aws|\.npmrc|credentials|\.pem\b|/etc/shadow|secrets?\b`)
	uploadRe     = regexp.MustCompile(`(?i)(curl|wget)\b.*(-d\s*@|--data(-binary|-raw|-urlencode)?[ =]+@|-F\s*\S*=@|-T\s|--upload-file)`)
	copyOutRe    = regexp.MustCompile(`(?i)\b(scp|nc|ncat|netcat|rsync|sftp)\b`)
	envLeakRe    = regexp.MustCompile(`(?i)\b(env|printenv|set)\b[^|]*\|\s*(curl|wget|nc)\b|(curl|wget)\b.*\$\(\s*(env|printenv)`)
	pipeShellRe  = regexp.MustCompile(`(?i)(curl|wget)\b[^|]*\|\s*(sudo\s+)?(ba|z)?sh\b`)
	rmRfRe       = regexp.MustCompile(`(?i)\brm\s+(-[a-z]*r[a-z]*f[a-z]*|-[a-z]*f[a-z]*r[a-z]*|-r\s+-f|-f\s+-r)\s+(\S+)`)
	askRe        = regexp.MustCompile(`(?i)\bgit\s+push\b|\bdeploy\b|\bdelete\b|\bpublish\b|chmod\s+(-r\s+)?777|\bterraform\s+(destroy|apply)\b|\bdrop\s+(database|table)\b|\brm\s+-[a-z]*r|\bgit\s+reset\s+--hard|\bgit\s+clean\s+-[a-z]*f`)
	postRe       = regexp.MustCompile(`(?i)(curl|wget)\b.*(-X\s*(POST|PUT)|\s-d\s|--data)`)
)

// fakeRules is a deterministic keyword heuristic. It scans the tool input
// (not the transcript) when the structured Input is present.
func fakeRules(req ClassifyRequest) ClassifyResult {
	text, projectDir, tainted := req.Prompt, "", false
	var in struct {
		ToolInput  json.RawMessage   `json:"input"`
		ProjectDir string            `json:"project_dir"`
		Context    map[string]string `json:"context"`
	}
	if json.Unmarshal(req.Input, &in) == nil && len(in.ToolInput) > 0 {
		text = flatten(in.ToolInput)
		projectDir = in.ProjectDir
		tainted = in.Context["trust"] == "tainted"
	}
	res := func(label, rule, reason string) ClassifyResult {
		return ClassifyResult{Label: label, Confidence: fakeRulesConfident, Rule: rule, Reason: reason}
	}
	switch {
	case uploadRe.MatchString(text) && secretPathRe.MatchString(text):
		return res("deny", "Data Exfiltration", "uploads a secret file")
	case copyOutRe.MatchString(text) && secretPathRe.MatchString(text):
		return res("deny", "Data Exfiltration", "copies a secret file out")
	case envLeakRe.MatchString(text):
		return res("deny", "Data Exfiltration", "sends the environment to a remote host")
	case pipeShellRe.MatchString(text):
		return res("deny", "Untrusted Code Execution", "pipes a download into a shell")
	}
	for _, m := range rmRfRe.FindAllStringSubmatch(text, -1) {
		if outsideProject(m[len(m)-1], projectDir) {
			return res("deny", "Destructive Action", "recursive delete outside the project")
		}
	}
	switch {
	case injectionRe.MatchString(text):
		return res("ask", "Injection", "tool input addresses a classifier or reviewer")
	case askRe.MatchString(text):
		return res("ask", "Irreversible Action", "affects shared state or is hard to undo")
	case tainted && (postRe.MatchString(text) || uploadRe.MatchString(text)):
		return res("ask", "Network Egress", "network write after reading untrusted content")
	}
	return res("allow", "", "routine call")
}

func outsideProject(arg, projectDir string) bool {
	arg = strings.Trim(arg, `"'`)
	if arg == "." || arg == "./" || arg == "" {
		return false
	}
	home := strings.HasPrefix(arg, "~") || strings.HasPrefix(arg, "$HOME") || arg == "/" || arg == "/*"
	if home {
		return true
	}
	if strings.HasPrefix(arg, "/") {
		return projectDir == "" || !(arg == projectDir || strings.HasPrefix(arg, strings.TrimRight(projectDir, "/")+"/"))
	}
	return strings.HasPrefix(arg, "..")
}

// flatten joins every string value of a JSON document with newlines.
func flatten(raw json.RawMessage) string {
	var v any
	if json.Unmarshal(raw, &v) != nil {
		return string(raw)
	}
	var b strings.Builder
	var walk func(any)
	walk = func(v any) {
		switch x := v.(type) {
		case string:
			b.WriteString(x)
			b.WriteByte('\n')
		case []any:
			for _, e := range x {
				walk(e)
			}
		case map[string]any:
			for _, e := range x {
				walk(e)
			}
		}
	}
	walk(v)
	return b.String()
}
