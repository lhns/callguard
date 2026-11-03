package judge

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/lhns/callguard/internal/transcript"
)

//go:embed prompt.md
var promptFile string

// Slot markers in prompt.md.
const (
	slotEnvironment = "<!-- slot:environment -->"
	slotBlock       = "<!-- slot:block -->"
	slotAllow       = "<!-- slot:allow -->"
)

// SystemPrompt renders prompt.md without its leading provenance comment and
// with the policy's slots filled in. It has no timestamps or per-call data, so
// backends can cache it.
func SystemPrompt(cfg Config) string {
	s := strings.TrimSpace(promptFile)
	if strings.HasPrefix(s, "<!--") {
		if _, rest, ok := strings.Cut(s, "-->"); ok {
			s = strings.TrimSpace(rest)
		}
	}
	env := "No additional environment entries."
	if len(cfg.Environment) > 0 {
		env = "Additional environment entries from policy:\n" + bullets(cfg.Environment, "")
	}
	var block []string
	for i, t := range cfg.Block {
		block = append(block, fmt.Sprintf("`policy-block-%d` **Policy block**: %s", i+1, t))
	}
	allow := "No additional exceptions."
	if len(cfg.AllowExceptions) > 0 {
		allow = bullets(cfg.AllowExceptions, "**Policy exception**: ")
	}
	return strings.NewReplacer(
		slotEnvironment, env,
		slotBlock, bullets(block, ""),
		slotAllow, allow,
	).Replace(s)
}

func bullets(items []string, prefix string) string {
	var b strings.Builder
	for i, it := range items {
		if i > 0 {
			b.WriteByte('\n')
		}
		b.WriteString("- " + prefix + it)
	}
	return b.String()
}

// UserPrompt renders the session, history and pending action as one JSON
// object per line inside <transcript>. Every line is json.Marshal output, so
// <, > and & are escaped and newlines inside strings stay inside their
// string: no value can start a line or close the tag.
func UserPrompt(in Input) string {
	var b strings.Builder
	b.WriteString("<transcript>\n")
	line := func(v any) {
		raw, err := json.Marshal(v)
		if err != nil { // cannot happen for the types used here; never leave a hole
			raw = []byte(`{"meta":{"error":"unencodable line"}}`)
		}
		b.Write(raw)
		b.WriteByte('\n')
	}
	meta := func(key string, v any) { line(map[string]any{"meta": map[string]any{key: v}}) }

	if s := (sessionInfo{in.Harness, in.Cwd, in.ProjectDir, in.Unattended, in.Context}); s.set() {
		meta("session", s)
	}
	ids := map[string]string{}
	calls := 0
	for _, m := range in.Transcript {
		switch m.Role {
		case transcript.RoleUser:
			line(map[string]string{"user": m.Text})
		case transcript.RoleAssistant:
			line(map[string]string{"assistant": m.Text})
		case transcript.RoleToolCall:
			calls++
			id := fmt.Sprintf("c%d", calls)
			if m.ID != "" {
				ids[m.ID] = id
			}
			line(map[string]callLine{"call": {id, m.Tool, validRaw(m.Input)}})
		case transcript.RoleOutcome:
			if id, ok := ids[m.ID]; ok && transcript.ValidOutcome(m.Outcome) {
				line(outcomeLine{m.Outcome, id})
			}
		}
	}
	if in.GitStatus != nil {
		meta("gitStatus", in.GitStatus)
	}
	for _, rv := range in.RepoVisibility {
		meta("repoVisibility", rv)
	}
	if f := validRaw(in.Facts); nonEmptyObject(f) {
		meta("nah", f)
	}
	line(map[string]actionLine{"action": {in.Tool, in.Kind, validRaw(in.ToolInput)}})
	b.WriteString("</transcript>\nDecide the action on the last line.")
	return b.String()
}

type sessionInfo struct {
	Harness    string            `json:"harness,omitempty"`
	Cwd        string            `json:"cwd,omitempty"`
	ProjectDir string            `json:"project_dir,omitempty"`
	Unattended bool              `json:"unattended,omitempty"`
	Context    map[string]string `json:"context,omitempty"`
}

func (s sessionInfo) set() bool {
	return s.Harness != "" || s.Cwd != "" || s.ProjectDir != "" || s.Unattended || len(s.Context) > 0
}

type callLine struct {
	ID    string          `json:"id"`
	Tool  string          `json:"tool"`
	Input json.RawMessage `json:"input,omitempty"`
}

type outcomeLine struct {
	Outcome string `json:"outcome"`
	ID      string `json:"id"`
}

type actionLine struct {
	Tool  string          `json:"tool"`
	Kind  string          `json:"kind"`
	Input json.RawMessage `json:"input,omitempty"`
}

// validRaw returns raw if it is valid JSON, else raw as a JSON string, so
// marshalling a line cannot fail.
func validRaw(raw json.RawMessage) json.RawMessage {
	if len(raw) == 0 || json.Valid(raw) {
		return raw
	}
	s, _ := json.Marshal(string(raw))
	return s
}

func nonEmptyObject(raw json.RawMessage) bool {
	t := bytes.TrimSpace(raw)
	if len(t) == 0 || string(t) == "null" || string(t) == "{}" {
		return false
	}
	return true
}

// dropPending removes the trailing tool_call that duplicates the pending
// action: Claude writes the tool_use to the transcript before the hook runs.
func dropPending(msgs []transcript.Message, in Input) []transcript.Message {
	if n := len(msgs); n > 0 {
		if m := msgs[n-1]; m.Role == transcript.RoleToolCall && m.Tool == in.Tool && sameJSON(m.Input, in.ToolInput) {
			return msgs[:n-1]
		}
	}
	return msgs
}

func sameJSON(a, b json.RawMessage) bool {
	if len(a) == 0 && len(b) == 0 {
		return true
	}
	var ca, cb bytes.Buffer
	if json.Compact(&ca, a) != nil || json.Compact(&cb, b) != nil {
		return false
	}
	return ca.String() == cb.String()
}
