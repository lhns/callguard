// Package callguard decides whether a pending coding-agent tool call may run
// without a human prompt. See docs/design.md for the contract.
package callguard

import "encoding/json"

// Schema identifiers (ADR 0002).
const (
	RequestSchema = "callguard/request/v1"
	VerdictSchema = "callguard/verdict/v1"
)

// Decision is the outcome for one tool call.
type Decision string

const (
	Allow Decision = "allow" // no human prompt needed
	Ask   Decision = "ask"   // a human should confirm
	Deny  Decision = "deny"  // do not run
)

// Valid reports whether d is one of the three decisions.
func (d Decision) Valid() bool { return d == Allow || d == Ask || d == Deny }

// Layer names recorded in Verdict.Layer.
const (
	LayerBuiltin  = "builtin"
	LayerNah      = "nah"
	LayerRules    = "rules"
	LayerLLM      = "llm"
	LayerNone     = "none"     // nothing decided; enforced is false
	LayerFallback = "fallback" // error, timeout, unavailable backend
)

// Request is callguard/request/v1.
type Request struct {
	Schema         string            `json:"schema,omitempty"`
	V              int               `json:"v,omitempty"`
	Harness        string            `json:"harness,omitempty"`
	SessionID      string            `json:"session_id,omitempty"`
	ToolUseID      string            `json:"tool_use_id,omitempty"`
	Cwd            string            `json:"cwd,omitempty"`
	ProjectDir     string            `json:"project_dir,omitempty"`
	Tool           ToolCall          `json:"tool"`
	Transcript     *Transcript       `json:"transcript,omitempty"`
	Context        map[string]string `json:"context,omitempty"`
	Unattended     bool              `json:"unattended,omitempty"`
	PermissionMode string            `json:"permission_mode,omitempty"`
}

// ToolCall is the pending call. Input is the harness's argument object.
type ToolCall struct {
	Name  string          `json:"name"`
	Input json.RawMessage `json:"input,omitempty"`
}

// Transcript points at, or carries, the conversation so far. Only user text
// and earlier tool calls are ever shown to the judge.
type Transcript struct {
	Path     string    `json:"path,omitempty"`
	Format   string    `json:"format,omitempty"` // "claude-jsonl"
	Messages []Message `json:"messages,omitempty"`
}

// Message is one reasoning-blind transcript entry.
type Message struct {
	Role  string          `json:"role"` // "user" or "tool_call"
	Text  string          `json:"text,omitempty"`
	Tool  string          `json:"tool,omitempty"`
	Input json.RawMessage `json:"input,omitempty"`
}

// Verdict is callguard/verdict/v1.
type Verdict struct {
	Schema     string   `json:"schema"`
	V          int      `json:"v"`
	ID         string   `json:"id"`
	Decision   Decision `json:"decision"`
	Enforced   bool     `json:"enforced"`
	Reason     string   `json:"reason"`
	Layer      string   `json:"layer"`
	Rule       string   `json:"rule,omitempty"`
	Confidence float64  `json:"confidence"`
	PolicyRev  string   `json:"policy_rev,omitempty"`
	Backend    string   `json:"backend,omitempty"`
	LatencyMS  int64    `json:"latency_ms"`
	Warnings   []string `json:"warnings,omitempty"`
}
