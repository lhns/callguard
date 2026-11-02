// Package backend defines the LLM judge backend interface and its built-in
// implementations: anthropic, openai (OpenAI-compatible), exec and fake.
package backend

import (
	"context"
	"encoding/json"
)

// ClassifySchema identifies the exec plugin wire format.
const ClassifySchema = "callguard/classify/v1"

// ClassifyRequest is one judge question. System and Prompt are the rendered
// prompt for generative models; Input is the same data in structured form for
// non-generative plugins. Schema is the JSON schema the answer must follow.
type ClassifyRequest struct {
	System string          `json:"system"`
	Prompt string          `json:"prompt"`
	Labels []string        `json:"labels"`
	Schema json.RawMessage `json:"schema,omitempty"`
	Input  json.RawMessage `json:"input,omitempty"`
}

// ClassifyResult is a backend's answer. Label must be one of the request's
// labels; callers validate it. Confidence is in [0,1].
type ClassifyResult struct {
	Label        string  `json:"label"`
	Confidence   float64 `json:"confidence"`
	Rule         string  `json:"rule,omitempty"`
	Reason       string  `json:"reason,omitempty"`
	InputTokens  int     `json:"input_tokens,omitempty"`
	OutputTokens int     `json:"output_tokens,omitempty"`
}

// Backend classifies one request. Implementations must honour ctx
// cancellation and must not retry beyond ctx's deadline.
type Backend interface {
	// Name is "<type>:<model>" as recorded in verdicts, e.g.
	// "anthropic:claude-haiku-5-5".
	Name() string
	// DataClasses lists the context.data_class values this backend may
	// receive. Empty means only requests without a data class.
	DataClasses() []string
	Classify(ctx context.Context, req ClassifyRequest) (ClassifyResult, error)
}
