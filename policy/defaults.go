package policy

// BuiltinIDs are the ids of the built-in layer's rules (internal/rules).
// Only the system layer can list them in disable_builtin.
var BuiltinIDs = []string{
	"rm-root", "disk-wipe", "fork-bomb", "self-protect-write", "self-protect-shell",
}

// ProtectedDirs are the directories whose contents the default write rule
// does not auto-allow: they carry hooks, policy and VCS state.
var ProtectedDirs = []string{
	"**/.git/**", "**/.claude/**", "**/.callguard/**",
	"**/.opencode/**", "**/.pi/**", "**/.hermes/**",
}

// Bool and Float return pointers for the optional fields.
func Bool(b bool) *bool        { return &b }
func Float(f float64) *float64 { return &f }
func boolOr(p *bool, d bool) bool {
	if p == nil {
		return d
	}
	return *p
}

// LLMEnabled reports whether the LLM layer is on (default true).
func (p Policy) LLMEnabled() bool { return p.LLM == nil || boolOr(p.LLM.Enabled, true) }

// Default returns the built-in policy: the default rules plus the default
// value of every setting.
func Default() Policy {
	return WithDefaults(Policy{PolicyVersion: Version, Rules: DefaultRules()})
}

// WithDefaults fills every unset setting with its default. It does not add
// rules and does not modify the pointed-to values of p.
func WithDefaults(p Policy) Policy {
	if p.PolicyVersion == 0 {
		p.PolicyVersion = Version
	}
	if p.Mode == "" {
		p.Mode = ModeEnforce
	}
	if p.UnattendedAsk == "" {
		p.UnattendedAsk = "deny"
	}
	if p.DeadlineMS == 0 {
		p.DeadlineMS = 8000
	}
	nah := Nah{}
	if p.Nah != nil {
		nah = *p.Nah
	}
	if nah.Path == "" {
		nah.Path = "nah"
	}
	if nah.TimeoutMS == 0 {
		nah.TimeoutMS = 2000
	}
	if nah.Mode == "" {
		nah.Mode = ModeEnforce
	}
	p.Nah = &nah

	llm := LLM{}
	if p.LLM != nil {
		llm = *p.LLM
	}
	if llm.Enabled == nil {
		llm.Enabled = Bool(true)
	}
	if llm.Mode == "" {
		llm.Mode = ModeShadow
	}
	if llm.Backend == "" {
		llm.Backend = "anthropic"
	}
	if llm.TimeoutMS == 0 {
		llm.TimeoutMS = 3000
	}
	if llm.MinConfidence == nil {
		llm.MinConfidence = Float(0.7)
	}
	tr := Transcript{}
	if llm.Transcript != nil {
		tr = *llm.Transcript
	}
	if tr.MaxMessages == 0 {
		tr.MaxMessages = 20
	}
	if tr.MaxBytes == 0 {
		tr.MaxBytes = 24000
	}
	llm.Transcript = &tr
	p.LLM = &llm

	backends := make(map[string]Backend, len(p.Backends)+1)
	for k, v := range p.Backends {
		backends[k] = v
	}
	if _, ok := backends["anthropic"]; !ok {
		backends["anthropic"] = Backend{
			Type: "anthropic", Model: "claude-haiku-5-5", APIKeyEnv: "ANTHROPIC_API_KEY",
			BaseURL: "https://api.anthropic.com", DataClasses: []string{"open", "private"},
		}
	}
	p.Backends = backends
	return p
}

// DefaultRules are the rules of design §4 "Default rules".
func DefaultRules() []Rule {
	secretPaths := []string{
		"**/.ssh/**", "**/.aws/**", "**/.env", "**/.env.*", "**/*.pem",
		"**/id_rsa*", "**/id_ed25519*", "**/.netrc",
	}
	sh := []string{"shell"}
	return []Rule{
		{ID: "read-in-project", Decision: "allow", Description: "reads inside the project need no review",
			Match: Match{Kind: []string{"read"}, InProject: Bool(true)}},
		{ID: "write-in-project", Decision: "allow", Description: "writes inside the project (outside protected directories) need no review",
			Match: Match{Kind: []string{"write"}, InProject: Bool(true), NotPath: ProtectedDirs}},
		{ID: "secret-read", Decision: "ask", Description: "reads a common secret location",
			Match: Match{Kind: []string{"read"}, Path: secretPaths}},
		{ID: "secret-read-shell", Decision: "ask", Description: "shell command touches a common secret location",
			Match: Match{Kind: sh, Command: `\.ssh[\\/]id_|\.aws[\\/]credentials|\.netrc`}},
		{ID: "secret-exfil", Decision: "deny", Description: "sends a common secret location over the network",
			Match: Match{Kind: sh, Command: SecretExfilRE}},
		{ID: "pipe-to-shell", Decision: "deny", Description: "downloads and runs remote code without review (pipe to a shell or interpreter)",
			Match: Match{Kind: sh, Command: PipeToShellRE}},
		{ID: "git-force-push", Decision: "ask", Description: "force push rewrites shared history",
			Match: Match{Kind: sh, Command: GitForcePushRE}},
		{ID: "git-discard", Decision: "ask", Description: "discards uncommitted work",
			Match: Match{Kind: sh, Command: GitDiscardRE}},
		{ID: "infra-destroy", Decision: "ask", Description: "destroys infrastructure or remote resources",
			Match: Match{Kind: sh, Command: InfraDestroyRE}},
		{ID: "package-publish", Decision: "ask", Description: "publishes a package to a public registry",
			Match: Match{Kind: sh, Command: PackagePublishRE}},
		{ID: "sudo", Decision: "ask", Description: "runs a command with elevated privileges",
			Match: Match{Kind: sh, Command: SudoRE}},
		{ID: "classifier-injection", Decision: "ask", Description: "tool input contains instruction-like text aimed at a classifier",
			Match: Match{Field: map[string]string{"*": InjectionRE}}},
	}
}

// Command patterns of the default rules (RE2). Best effort, not a parser;
// they are exported so tests and docs can name them.
const (
	PipeToShellRE = `(?i)\b(?:curl|wget|iwr|irm|invoke-webrequest|invoke-restmethod)\b[^|]*\|\s*(?:sudo\s+)?(?:sh|bash|zsh|dash|python3?|perl|ruby|node|iex|invoke-expression)\b` +
		`|(?i)\b(?:sh|bash|zsh|dash)\s+(?:-c\s+)?["']?\$\(\s*(?:curl|wget)\b` +
		`|(?i)\b(?:sh|bash|zsh|dash)\s+<\(\s*(?:curl|wget)\b`
	GitForcePushRE   = `\bgit\b[^;&|\n]*\bpush\b[^;&|\n]*(?:\s--force(?:-with-lease)?\b|\s-[a-zA-Z]*f[a-zA-Z]*(?:\s|$)|\s\+\S)`
	GitDiscardRE     = `\bgit\b[^;&|\n]*(?:\breset\b[^;&|\n]*\s--hard\b|\bclean\b[^;&|\n]*\s(?:-[a-zA-Z]*f[a-zA-Z]*|--force)\b|\bcheckout\s+(?:--\s+)?\.(?:\s|$)|\bcheckout\b[^;&|\n]*\s--\s+\.|\brestore\b[^;&|\n]*\s\.(?:\s|$))`
	InfraDestroyRE   = `\b(?:terraform|tofu|pulumi|cdk|terragrunt)\b[^;&|\n]*\bdestroy\b|\bkubectl\b[^;&|\n]*\bdelete\b|\bgh\s+repo\s+delete\b`
	PackagePublishRE = `\b(?:npm|pnpm|yarn)\s+(?:[^;&|\n]*\s)?publish(?:\s|$)|\bcargo\s+publish(?:\s|$)|\btwine\s+upload\b|\bgem\s+push\b`
	SudoRE           = `(?:^|[;&|(]\s*|\s)sudo\s+\S`
	// Separators include _ - . so file names like IGNORE_PREVIOUS_INSTRUCTIONS match.
	InjectionRE = `(?i)ignore[\s_.-]+(?:(?:all|any)[\s_.-]+)?(?:previous|prior)[\s_.-]+instructions` +
		`|you[\s_.-]+are[\s_.-]+(?:now[\s_.-]+)?(?:(?:a|the)[\s_.-]+)?(?:security[\s_.-]+)?classifier` +
		`|(?:label|classify|mark|rate)[\s_.-]+(?:this|it|the)(?:[\s_.-]+call)?[\s_.-]+(?:as[\s_.-]+)?(?:allow|safe|benign)` +
		`|callguard\W+(?:allow|approve)|callguard-data`
	// SecretExfilRE: a network tool and a common secret location in one command.
	SecretExfilRE = `(?i)\b(?:` + netToolsRE + `)\b[^;&\n]*` + secretShellRE +
		`|(?i)` + secretShellRE + `[^;&\n]*\b(?:` + netToolsRE + `)\b`
	netToolsRE    = `curl|wget|scp|rsync|sftp|ftp|nc|ncat|socat|iwr|invoke-webrequest|invoke-restmethod`
	secretShellRE = `(?:\.ssh[\\/]id_|\.aws[\\/]credentials|\.netrc|\.env\b|\.pem\b)`
)
