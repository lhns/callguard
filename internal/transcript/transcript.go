// Package transcript extracts the reasoning-blind view of a conversation:
// user text messages and tool calls only.
package transcript

import (
	"encoding/json"
	"errors"
)

// STUB: worker B replaces this file.

// Message is one kept entry. Role is "user" (Text set) or "tool_call"
// (Tool and Input set).
type Message struct {
	Role  string          `json:"role"`
	Text  string          `json:"text,omitempty"`
	Tool  string          `json:"tool,omitempty"`
	Input json.RawMessage `json:"input,omitempty"`
}

// ReadClaudeJSONL reads a Claude Code transcript file and returns the newest
// user text blocks and assistant tool_use blocks, bounded by maxMessages and
// maxBytes.
func ReadClaudeJSONL(path string, maxMessages, maxBytes int) ([]Message, error) {
	return nil, errors.New("not implemented")
}

// Limit keeps the newest messages within maxMessages and maxBytes.
func Limit(msgs []Message, maxMessages, maxBytes int) []Message { return msgs }
