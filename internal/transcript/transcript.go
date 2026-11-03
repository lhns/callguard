// Package transcript extracts the reasoning-blind view of a conversation:
// user text, the assistant text a user reply referred to, tool calls and
// their outcome labels (design §7, ADR 0005). Tool output never gets here.
package transcript

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"slices"
	"strings"
	"unicode/utf8"
)

const (
	tailBytes       = 2 << 20
	defaultMessages = 20
	defaultBytes    = 24000
	truncMarker     = "…[truncated]"
)

// Roles of a Message.
const (
	RoleUser       = "user"
	RoleAssistant  = "assistant"
	RoleToolCall   = "tool_call"
	RoleOutcome    = "outcome"
	RoleThirdParty = "third_party" // internal marker, never rendered
)

// Outcomes of a tool call. They are derived from the harness's status and the
// start of its error text, never from tool output.
const (
	OutcomeOK                    = "ok"
	OutcomeError                 = "error"
	OutcomeInterrupted           = "interrupted"
	OutcomeRejectedByUser        = "rejected-by-user"
	OutcomeBlockedByPermissions  = "blocked-by-permissions"
	OutcomeBlockedByClassifier   = "blocked-by-classifier"
	OutcomeBlockedByCallguard    = "blocked-by-callguard"
	OutcomeClassifierUnavailable = "classifier-unavailable"
)

var outcomes = []string{
	OutcomeOK, OutcomeError, OutcomeInterrupted, OutcomeRejectedByUser, OutcomeBlockedByPermissions,
	OutcomeBlockedByClassifier, OutcomeBlockedByCallguard, OutcomeClassifierUnavailable,
}

// ValidOutcome reports whether s is a known outcome value.
func ValidOutcome(s string) bool { return slices.Contains(outcomes, s) }

// Message is one kept entry. "user" and "assistant" carry Text; "tool_call"
// carries Tool, Input and ID; "outcome" carries the ID of its call and an
// Outcome, never any tool output; "third_party" marks text from someone other
// than the user and carries nothing.
type Message struct {
	Role    string          `json:"role"`
	Text    string          `json:"text,omitempty"`
	Tool    string          `json:"tool,omitempty"`
	Input   json.RawMessage `json:"input,omitempty"`
	ID      string          `json:"id,omitempty"`
	Outcome string          `json:"outcome,omitempty"`
}

// ignoredUserPrefixes mark harness-injected text in user-role messages:
// reminders, slash-command echoes, shell and local command output.
var ignoredUserPrefixes = []string{
	"<system-reminder>", "<command-", "<local-command-", "<bash-stdout>", "<bash-stderr>",
}

// thirdPartyPrefixes mark user-role text that comes from a background task, a
// teammate agent or another session, not from the user.
var thirdPartyPrefixes = []string{"<task-notification>", "<teammate-message", "<cross-session-message"}

type entry struct {
	Type             string          `json:"type"`
	IsMeta           bool            `json:"isMeta"`
	IsSidechain      bool            `json:"isSidechain"` // a subagent's turn: its "user" text is the assistant's prompt
	IsCompactSummary bool            `json:"isCompactSummary"`
	ToolUseResult    json.RawMessage `json:"toolUseResult"`
	Message          struct {
		Content json.RawMessage `json:"content"`
	} `json:"message"`
}

type block struct {
	Type      string          `json:"type"`
	Text      string          `json:"text"`
	Name      string          `json:"name"`
	ID        string          `json:"id"`
	Input     json.RawMessage `json:"input"`
	ToolUseID string          `json:"tool_use_id"`
	IsError   bool            `json:"is_error"`
	Content   json.RawMessage `json:"content"`
}

// ReadClaudeJSONL reads a Claude Code transcript file and returns the newest
// messages within maxMessages and maxBytes: user text, the assistant text a
// user reply followed (see Referents), tool calls and their outcomes. Only the
// last 2 MiB of the file is read. Unparseable lines are skipped; a file with
// nothing usable yields an empty slice, not an error.
//
// Thinking and tool_result content are dropped, so tool output never reaches
// the judge; a tool_result only yields an outcome label.
func ReadClaudeJSONL(path string, maxMessages, maxBytes int) ([]Message, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	partial := false
	if st.Size() > tailBytes {
		if _, err := f.Seek(st.Size()-tailBytes, io.SeekStart); err != nil {
			return nil, err
		}
		partial = true
	}
	data, err := io.ReadAll(f)
	if err != nil {
		return nil, err
	}
	if partial { // the first line is cut in the middle
		if i := bytes.IndexByte(data, '\n'); i >= 0 {
			data = data[i+1:]
		} else {
			data = nil
		}
	}
	msgs := []Message{}
	for _, line := range bytes.Split(data, []byte{'\n'}) {
		line = bytes.TrimSpace(line)
		if len(line) == 0 {
			continue
		}
		msgs = append(msgs, parseLine(line)...)
	}
	return Limit(Referents(msgs), maxMessages, maxBytes), nil
}

func parseLine(line []byte) []Message {
	var e entry
	if json.Unmarshal(line, &e) != nil || e.IsMeta || e.IsSidechain || e.IsCompactSummary {
		return nil
	}
	if e.Type != "user" && e.Type != "assistant" {
		return nil
	}
	var text string
	if json.Unmarshal(e.Message.Content, &text) == nil {
		return textMessage(e.Type, text)
	}
	var blocks []block
	if json.Unmarshal(e.Message.Content, &blocks) != nil {
		return nil
	}
	// The entry-level toolUseResult is a plain string only when the user
	// rejected the call.
	var tur string
	rejected := json.Unmarshal(e.ToolUseResult, &tur) == nil && tur == "User rejected tool use"
	var out []Message
	for _, b := range blocks {
		switch {
		case b.Type == "text":
			out = append(out, textMessage(e.Type, b.Text)...)
		case e.Type == "assistant" && b.Type == "tool_use" && b.Name != "":
			out = append(out, Message{Role: RoleToolCall, Tool: b.Name, Input: b.Input, ID: b.ID})
		case e.Type == "user" && b.Type == "tool_result" && b.ToolUseID != "":
			o := resultOutcome(b)
			if rejected {
				o = OutcomeRejectedByUser
			}
			out = append(out, Message{Role: RoleOutcome, ID: b.ToolUseID, Outcome: o})
		}
	}
	return out
}

func textMessage(typ, text string) []Message {
	t := strings.TrimSpace(text)
	if t == "" {
		return nil
	}
	if typ == "assistant" {
		return []Message{{Role: RoleAssistant, Text: text}}
	}
	for _, p := range thirdPartyPrefixes {
		if strings.HasPrefix(t, p) {
			return []Message{{Role: RoleThirdParty}}
		}
	}
	for _, p := range ignoredUserPrefixes {
		if strings.HasPrefix(t, p) {
			return nil
		}
	}
	return []Message{{Role: RoleUser, Text: text}}
}

// Error texts the harness writes for a call that did not run. Rejections and
// denials always set is_error, and a failing Bash call starts with
// "Exit code N", so command output cannot reach these prefixes while is_error
// is set. They are matched only then: a successful result, whose text the
// tool or an attacker controls, can never forge a label.
var errorPrefixes = []struct{ prefix, outcome string }{
	{"The user doesn't want to proceed with this tool use", OutcomeRejectedByUser},
	{"[Request interrupted by user for tool use]", OutcomeInterrupted},
	{"Permission for this action was denied by the Claude Code auto mode classifier", OutcomeBlockedByClassifier},
	{"Permission for this command was denied by a built-in Claude Code safety check", OutcomeBlockedByPermissions},
	{"Permission to use ", OutcomeBlockedByPermissions},
	{"The server-side auto mode classifier gave no verdict", OutcomeClassifierUnavailable},
}

func resultOutcome(b block) string {
	if !b.IsError {
		return OutcomeOK
	}
	text := strings.TrimSpace(firstText(b.Content))
	for _, p := range errorPrefixes {
		if strings.HasPrefix(text, p.prefix) {
			return p.outcome
		}
	}
	return OutcomeError
}

// firstText is the content string, or the first text block of a content array.
func firstText(raw json.RawMessage) string {
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return s
	}
	var blocks []block
	if json.Unmarshal(raw, &blocks) == nil {
		for _, b := range blocks {
			if b.Type == "text" {
				return b.Text
			}
		}
	}
	return ""
}

// Referents keeps the assistant text a user reply can refer to ("yes, do
// that") and drops the rest. An assistant message stays only if the next
// message that is not a tool call or outcome is a user message; text with
// another assistant message or a third-party marker in between, and all
// assistant text after the last user message (the agent narrating the pending
// action), is dropped. Third-party markers are removed.
func Referents(msgs []Message) []Message {
	out := make([]Message, 0, len(msgs))
	for i, m := range msgs {
		switch m.Role {
		case RoleThirdParty:
			continue
		case RoleAssistant:
			j := i + 1
			for j < len(msgs) && (msgs[j].Role == RoleToolCall || msgs[j].Role == RoleOutcome) {
				j++
			}
			if j >= len(msgs) || msgs[j].Role != RoleUser {
				continue
			}
		}
		out = append(out, m)
	}
	return out
}

// MarkBlocked sets the outcome of every call whose ID is in ids to
// blocked-by-callguard, adding an outcome message after the call if it has
// none.
func MarkBlocked(msgs []Message, ids map[string]bool) []Message {
	if len(ids) == 0 {
		return msgs
	}
	out := make([]Message, 0, len(msgs)+1)
	for i, m := range msgs {
		switch {
		case m.Role == RoleOutcome && ids[m.ID]:
			m.Outcome = OutcomeBlockedByCallguard
		case m.Role == RoleToolCall && m.ID != "" && ids[m.ID]:
			out = append(out, m)
			if !hasOutcome(msgs[i+1:], m.ID) {
				out = append(out, Message{Role: RoleOutcome, ID: m.ID, Outcome: OutcomeBlockedByCallguard})
			}
			continue
		}
		out = append(out, m)
	}
	return out
}

func hasOutcome(msgs []Message, id string) bool {
	for _, m := range msgs {
		if m.Role == RoleOutcome && m.ID == id {
			return true
		}
	}
	return false
}

// Limit keeps the newest messages within maxMessages and maxBytes (a
// message's size is len(Text)+len(Input)). Outcomes are tiny and do not count
// toward maxMessages; those whose call was cut are dropped. Any single text or
// input over maxBytes/4 is truncated with a marker. Limits <= 0 default to 20
// and 24000.
func Limit(msgs []Message, maxMessages, maxBytes int) []Message {
	if maxMessages <= 0 {
		maxMessages = defaultMessages
	}
	if maxBytes <= 0 {
		maxBytes = defaultBytes
	}
	one := maxBytes / 4
	kept := []Message{}
	total, n := 0, 0
	for i := len(msgs) - 1; i >= 0 && n < maxMessages; i-- {
		m := truncate(msgs[i], one)
		size := len(m.Text) + len(m.Input)
		if total+size > maxBytes {
			break
		}
		total += size
		if m.Role != RoleOutcome {
			n++
		}
		kept = append(kept, m)
	}
	slices.Reverse(kept)
	calls := map[string]bool{}
	for _, m := range kept {
		if m.Role == RoleToolCall && m.ID != "" {
			calls[m.ID] = true
		}
	}
	return slices.DeleteFunc(kept, func(m Message) bool { return m.Role == RoleOutcome && !calls[m.ID] })
}

func truncate(m Message, limit int) Message {
	if len(m.Text) > limit {
		m.Text = cut(m.Text, limit)
	}
	if len(m.Input) > limit {
		// A cut JSON document is invalid, so the truncated input becomes a string.
		s, _ := json.Marshal(cut(string(m.Input), limit))
		m.Input = s
	}
	return m
}

// cut shortens s so that the result, marker included, fits in limit bytes
// (best effort for tiny limits) and ends on a rune boundary.
func cut(s string, limit int) string {
	n := limit - len(truncMarker)
	if n < 0 {
		n = 0
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n] + truncMarker
}
