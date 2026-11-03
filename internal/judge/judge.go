// Package judge builds the reasoning-blind prompt for the LLM layer, calls a
// backend and validates its answer.
package judge

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/lhns/callguard/backend"
	"github.com/lhns/callguard/internal/hostmeta"
	"github.com/lhns/callguard/internal/transcript"
)

const (
	maxStringBytes = 8 << 10
	maxInputBytes  = 16 << 10
	maxFactString  = 2 << 10
	maxFactsBytes  = 8 << 10
	maxGitFiles    = 30
	maxGitFileLen  = 512
	maxReasonRunes = 500
	maxRuleRunes   = 64
	truncMarker    = "…[truncated]"
)

// ErrInvalidOutput means the backend answered, but not with a usable verdict.
var ErrInvalidOutput = errors.New("judge: invalid backend output")

// Input is what the judge may see. Assistant text appears only as the
// referent of a later user message, and tool results never appear.
type Input struct {
	Harness        string                    `json:"harness,omitempty"`
	Tool           string                    `json:"tool"`
	Kind           string                    `json:"kind"`
	ToolInput      json.RawMessage           `json:"input,omitempty"`
	Cwd            string                    `json:"cwd,omitempty"`
	ProjectDir     string                    `json:"project_dir,omitempty"`
	Context        map[string]string         `json:"context,omitempty"`
	Unattended     bool                      `json:"unattended,omitempty"`
	Transcript     []transcript.Message      `json:"transcript,omitempty"`
	GitStatus      *hostmeta.GitStatus       `json:"git_status,omitempty"`
	RepoVisibility []hostmeta.RepoVisibility `json:"repo_visibility,omitempty"`
	// Facts is the deterministic parse of the call (callguard.Facts as JSON).
	// Its strings are untrusted data.
	Facts json.RawMessage `json:"facts,omitempty"`
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

// Labels are the only decisions the judge may return.
var Labels = []string{"allow", "ask", "deny"}

// Schema is the JSON schema the backend must force the answer into. The
// reason comes first so the model reasons before it decides.
const Schema = `{"type":"object","properties":{` +
	`"reason":{"type":"string"},` +
	`"rule":{"type":"string"},` +
	`"decision":{"type":"string","enum":["allow","ask","deny"]},` +
	`"confidence":{"type":"number"}},` +
	`"required":["decision","confidence","rule","reason"],"additionalProperties":false}`

// Judge asks b about in. Any error (transport, timeout, invalid label or
// confidence, unparseable output) is returned as an error; the caller turns
// it into a fallback verdict. It never returns an allow on error.
func Judge(ctx context.Context, b backend.Backend, cfg Config, in Input) (Result, error) {
	in.Transcript = dropPending(in.Transcript, in) // before the input is capped
	in.ToolInput = capInput(in.ToolInput)
	in.Facts = capFacts(in.Facts)
	in.GitStatus = capGitStatus(in.GitStatus)
	structured, err := json.Marshal(in)
	if err != nil {
		return Result{}, fmt.Errorf("judge: encoding input: %w", err)
	}
	res, err := b.Classify(ctx, backend.ClassifyRequest{
		System: SystemPrompt(cfg),
		Prompt: UserPrompt(in),
		Labels: Labels,
		Schema: json.RawMessage(Schema),
		Input:  structured,
	})
	if err != nil {
		return Result{}, err
	}
	if !slices.Contains(Labels, res.Label) {
		return Result{}, fmt.Errorf("%w: label %q", ErrInvalidOutput, clipRunes(res.Label, 32))
	}
	if math.IsNaN(res.Confidence) || res.Confidence < 0 || res.Confidence > 1 {
		return Result{}, fmt.Errorf("%w: confidence %v", ErrInvalidOutput, res.Confidence)
	}
	out := Result{
		Decision:     res.Label,
		Confidence:   res.Confidence,
		Rule:         clipRunes(res.Rule, maxRuleRunes),
		Reason:       clipRunes(res.Reason, maxReasonRunes),
		InputTokens:  res.InputTokens,
		OutputTokens: res.OutputTokens,
	}
	// A HARD rule cannot be cleared by a human prompt. Unknown rule ids are
	// kept as the model wrote them.
	if out.Decision == "ask" && IsHard(out.Rule) {
		out.Decision = "deny"
	}
	if out.Decision == "allow" && out.Confidence < cfg.MinConfidence {
		out.Decision, out.Demoted = "ask", true
	}
	return out, nil
}

func clipRunes(s string, n int) string {
	s = strings.TrimSpace(s)
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	return string([]rune(s)[:n])
}

// capGitStatus keeps at most 30 files, each at most 512 bytes.
func capGitStatus(g *hostmeta.GitStatus) *hostmeta.GitStatus {
	if g == nil {
		return nil
	}
	c := *g
	if len(c.Files) > maxGitFiles {
		c.Files, c.FilesTruncated = c.Files[:maxGitFiles], true
	}
	c.Files = slices.Clone(c.Files)
	for i, f := range c.Files {
		c.Files[i] = cutString(f, maxGitFileLen)
	}
	return &c
}

// capFacts limits each facts string to 2 KiB and the document to 8 KiB.
func capFacts(raw json.RawMessage) json.RawMessage {
	if !nonEmptyObject(raw) {
		return nil
	}
	return capJSON(raw, maxFactString, maxFactsBytes)
}

// capInput limits each string in raw to 8 KiB and the whole document to
// 16 KiB, marking cuts with a "…[truncated]" suffix. If shrinking the strings
// is not enough, the document becomes one truncated string.
func capInput(raw json.RawMessage) json.RawMessage {
	return capJSON(raw, maxStringBytes, maxInputBytes)
}

func capJSON(raw json.RawMessage, maxString, maxTotal int) json.RawMessage {
	if len(raw) == 0 {
		return raw
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return capRaw(raw, maxTotal)
	}
	// Keep the original key order when nothing needs shrinking.
	var compact bytes.Buffer
	if json.Compact(&compact, raw) == nil && compact.Len() <= maxTotal && !hasLongString(v, maxString) {
		return compact.Bytes()
	}
	for limit := maxString; limit >= 128; limit /= 2 {
		out, err := json.Marshal(shrink(v, limit))
		if err != nil {
			break
		}
		if len(out) <= maxTotal {
			return out
		}
	}
	return capRaw(raw, maxTotal)
}

func hasLongString(v any, limit int) bool {
	switch x := v.(type) {
	case string:
		return len(x) > limit
	case []any:
		for _, e := range x {
			if hasLongString(e, limit) {
				return true
			}
		}
	case map[string]any:
		for k, e := range x {
			if len(k) > limit || hasLongString(e, limit) {
				return true
			}
		}
	}
	return false
}

func capRaw(raw json.RawMessage, maxTotal int) json.RawMessage {
	out, _ := json.Marshal(cutString(string(raw), maxTotal/2))
	return out
}

func shrink(v any, limit int) any {
	switch x := v.(type) {
	case string:
		return cutString(x, limit)
	case []any:
		out := make([]any, len(x))
		for i, e := range x {
			out[i] = shrink(e, limit)
		}
		return out
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, e := range x {
			out[cutString(k, limit)] = shrink(e, limit)
		}
		return out
	}
	return v
}

func cutString(s string, limit int) string {
	if len(s) <= limit {
		return s
	}
	n := limit
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n] + truncMarker
}
