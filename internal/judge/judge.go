// Package judge builds the reasoning-blind prompt for the LLM layer, calls a
// backend and validates its answer.
package judge

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/lhns/callguard/backend"
	"github.com/lhns/callguard/internal/transcript"
)

// STUB: worker B replaces this file.

// Input is what the judge may see. It never contains assistant text or tool
// results.
type Input struct {
	Harness    string               `json:"harness,omitempty"`
	Tool       string               `json:"tool"`
	Kind       string               `json:"kind"`
	ToolInput  json.RawMessage      `json:"input,omitempty"`
	Cwd        string               `json:"cwd,omitempty"`
	ProjectDir string               `json:"project_dir,omitempty"`
	Context    map[string]string    `json:"context,omitempty"`
	Unattended bool                 `json:"unattended,omitempty"`
	Transcript []transcript.Message `json:"transcript,omitempty"`
}

// Config holds the policy's prose slots and threshold.
type Config struct {
	Environment     []string
	Block           []string
	AllowExceptions []string
	MinConfidence   float64
}

// Result is a validated judge answer. Decision is "allow", "ask" or "deny".
// If MinConfidence demoted an allow to ask, Demoted is true.
type Result struct {
	Decision     string
	Confidence   float64
	Rule         string
	Reason       string
	Demoted      bool
	InputTokens  int
	OutputTokens int
}

// Judge asks b about in. Any error (transport, timeout, invalid label or
// confidence, unparseable output) is returned as an error; the caller turns
// it into a fallback verdict. It never returns an allow on error.
func Judge(ctx context.Context, b backend.Backend, cfg Config, in Input) (Result, error) {
	return Result{}, errors.New("not implemented")
}
