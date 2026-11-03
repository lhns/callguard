// Package callguard decides whether a pending coding-agent tool call may run
// without a human prompt. See docs/design.md for the contract.
package callguard

import (
	"encoding/json"

	"github.com/lhns/callguard/internal/hostmeta"
)

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
	// Meta and Facts are host observations; adapters never fill them from agent text.
	Meta  *Meta  `json:"meta,omitempty"`
	Facts *Facts `json:"facts,omitempty"`
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

// Message is one reasoning-blind transcript entry. Role is "user" or
// "assistant" (Text), "tool_call" (Tool, Input, optional ID), "outcome" (ID of
// the call, Outcome: ok, error, interrupted, rejected-by-user,
// blocked-by-permissions, blocked-by-classifier, blocked-by-callguard,
// classifier-unavailable) or "third_party" (no content; marks a teammate or
// task message so the assistant text before it is not taken as a referent).
type Message struct {
	Role    string          `json:"role"`
	Text    string          `json:"text,omitempty"`
	Tool    string          `json:"tool,omitempty"`
	Input   json.RawMessage `json:"input,omitempty"`
	ID      string          `json:"id,omitempty"`
	Outcome string          `json:"outcome,omitempty"`
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

// Meta carries host observations about the pending call. Only the host or
// adapter sets it, never from agent text.
type Meta = hostmeta.Meta

// GitStatus summarises the working tree (git status --porcelain).
type GitStatus = hostmeta.GitStatus

// RepoVisibility is the visibility of a push or publish destination:
// public, private, internal or unknown.
type RepoVisibility = hostmeta.RepoVisibility

// Facts is a deterministic parse of the pending call (from nah). Strings
// inside are untrusted data.
type Facts struct {
	Source   string        `json:"source,omitempty"`   // "nah-decide", "nah-wasm", or a host name
	Coverage string        `json:"coverage,omitempty"` // "full" or "partial"
	Guards   []string      `json:"guards,omitempty"`
	Commands []FactCommand `json:"commands,omitempty"` // unwrapped sub-commands
	Effects  []FactEffect  `json:"effects,omitempty"`
	Paths    []FactPath    `json:"paths,omitempty"`
	Git      []FactGit     `json:"git,omitempty"`
	Hosts    []FactHost    `json:"hosts,omitempty"`
	Decoded  []FactPayload `json:"decoded,omitempty"` // decoded payloads (base64, -EncodedCommand, ...)
	Gaps     []string      `json:"gaps,omitempty"`
}

// FactCommand is one unwrapped sub-command. Via names the wrapper that ran
// it: "bash -c", "eval", "xargs", "find -exec", "base64", ...
type FactCommand struct {
	Argv []string `json:"argv"`
	Cwd  string   `json:"cwd,omitempty"`
	Via  string   `json:"via,omitempty"`
}

// FactEffect is something the call does. Kind examples: fs.read fs.write
// fs.delete fs.move net.download net.upload net.request net.listen exec
// env.read env.write credential.read git.push git.history-rewrite.
type FactEffect struct {
	Kind      string `json:"kind"`
	Target    string `json:"target,omitempty"`
	Detail    string `json:"detail,omitempty"`
	Certainty string `json:"certainty,omitempty"`
}

// FactPath is a path the call touches. Scope: project home system temp
// outside unknown.
type FactPath struct {
	Path        string `json:"path"`
	Scope       string `json:"scope,omitempty"`
	Sensitivity string `json:"sensitivity,omitempty"`
	Tracked     *bool  `json:"tracked,omitempty"`
}

// FactGit is a git operation the call performs.
type FactGit struct {
	Op     string `json:"op"`
	Remote string `json:"remote,omitempty"`
	Ref    string `json:"ref,omitempty"`
	Force  bool   `json:"force,omitempty"`
}

// FactHost is a network host the call talks to.
type FactHost struct {
	Host      string `json:"host"`
	Operation string `json:"operation,omitempty"`
	Direction string `json:"direction,omitempty"`
}

// FactPayload is a decoded payload (base64, -EncodedCommand, ...).
type FactPayload struct {
	Encoding string `json:"encoding"`
	Text     string `json:"text"`
}
