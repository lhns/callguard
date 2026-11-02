// Package policy defines callguard's policy file format (policy_version 1)
// and its layered, tighten-only merge. See docs/design.md §5 and ADR 0003.
package policy

// Version is the only supported policy_version.
const Version = 1

// Mode values for Policy.Mode and per-layer modes.
const (
	ModeEnforce = "enforce"
	ModeShadow  = "shadow"
)

// Policy is one policy file, or the merged result of all layers.
// Pointer and nil-able fields distinguish "not set" from zero values so that
// layers can be merged.
type Policy struct {
	PolicyVersion  int                `json:"policy_version"`
	Final          bool               `json:"final,omitempty"`
	Mode           string             `json:"mode,omitempty"`     // enforce (default) | shadow
	Defaults       *bool              `json:"defaults,omitempty"` // include built-in default rules (default true)
	DisableBuiltin []string           `json:"disable_builtin,omitempty"`
	UnattendedAsk  string             `json:"unattended_ask,omitempty"` // deny (default) | ask
	Rules          []Rule             `json:"rules,omitempty"`
	Nah            *Nah               `json:"nah,omitempty"`
	LLM            *LLM               `json:"llm,omitempty"`
	Backends       map[string]Backend `json:"backends,omitempty"`
	DenyStreak     *DenyStreak        `json:"deny_streak,omitempty"`
	DeadlineMS     int                `json:"deadline_ms,omitempty"` // default 8000
	Log            *Log               `json:"log,omitempty"`
}

// Rule is one policy rule. Decision is deny, ask or allow.
type Rule struct {
	ID          string `json:"id"`
	Description string `json:"description,omitempty"`
	Decision    string `json:"decision"`
	Match       Match  `json:"match"`
}

// Match conditions are ANDed; list values are ORed. Regexes are RE2.
type Match struct {
	Tool       []string            `json:"tool,omitempty"`
	Kind       []string            `json:"kind,omitempty"`
	Command    string              `json:"command,omitempty"`
	URL        string              `json:"url,omitempty"`
	Field      map[string]string   `json:"field,omitempty"`
	Path       []string            `json:"path,omitempty"`
	InProject  *bool               `json:"in_project,omitempty"`
	Context    map[string][]string `json:"context,omitempty"`
	Unattended *bool               `json:"unattended,omitempty"`
	Harness    []string            `json:"harness,omitempty"`
}

// Nah configures the optional nah layer (ADR 0004).
type Nah struct {
	Enabled   bool   `json:"enabled"`
	Path      string `json:"path,omitempty"` // default "nah"
	Require   bool   `json:"require,omitempty"`
	TimeoutMS int    `json:"timeout_ms,omitempty"` // default 2000
	Mode      string `json:"mode,omitempty"`
}

// LLM configures the judge layer.
type LLM struct {
	Enabled         *bool       `json:"enabled,omitempty"`
	Mode            string      `json:"mode,omitempty"`
	Backend         string      `json:"backend,omitempty"`
	TimeoutMS       int         `json:"timeout_ms,omitempty"`     // default 3000
	MinConfidence   *float64    `json:"min_confidence,omitempty"` // default 0.7
	Transcript      *Transcript `json:"transcript,omitempty"`
	Environment     []string    `json:"environment,omitempty"`
	Block           []string    `json:"block,omitempty"`
	AllowExceptions []string    `json:"allow_exceptions,omitempty"`
}

// Transcript limits for the judge's view of the conversation.
type Transcript struct {
	MaxMessages int `json:"max_messages,omitempty"` // default 20
	MaxBytes    int `json:"max_bytes,omitempty"`    // default 24000
}

// Backend configures one LLM backend. Type is anthropic, openai, exec or fake.
type Backend struct {
	Type        string   `json:"type"`
	Model       string   `json:"model,omitempty"`
	BaseURL     string   `json:"base_url,omitempty"`
	APIKeyEnv   string   `json:"api_key_env,omitempty"`
	Command     []string `json:"command,omitempty"`
	MaxTokens   int      `json:"max_tokens,omitempty"`
	DataClasses []string `json:"data_classes,omitempty"`
	// Fake backend behaviour, for tests and offline eval: "rules" (default,
	// a deterministic heuristic), "allow", "ask", "deny", "garbage", "slow",
	// "error", "obey-injection".
	FakeMode string `json:"fake_mode,omitempty"`
}

// DenyStreak mirrors auto mode's 3-in-a-row / 20-total fallback.
type DenyStreak struct {
	Consecutive int `json:"consecutive,omitempty"`
	Total       int `json:"total,omitempty"`
}

// Log configures the decision log.
type Log struct {
	Path         string `json:"path,omitempty"`
	IncludeInput bool   `json:"include_input,omitempty"`
	Disabled     bool   `json:"disabled,omitempty"`
}
