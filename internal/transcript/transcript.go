// Package transcript extracts the reasoning-blind view of a conversation:
// user text messages and tool calls only (design §7, ADR 0005).
package transcript

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"strings"
	"unicode/utf8"
)

const (
	tailBytes       = 2 << 20
	defaultMessages = 20
	defaultBytes    = 24000
	truncMarker     = "…[truncated]"
)

// Message is one kept entry. Role is "user" (Text set) or "tool_call"
// (Tool and Input set).
type Message struct {
	Role  string          `json:"role"`
	Text  string          `json:"text,omitempty"`
	Tool  string          `json:"tool,omitempty"`
	Input json.RawMessage `json:"input,omitempty"`
}

// ignoredUserPrefixes mark harness-injected text in user-role messages:
// reminders, slash-command echoes, shell and local command output, and
// background task results.
var ignoredUserPrefixes = []string{
	"<system-reminder>", "<command-", "<local-command-", "<bash-stdout>", "<bash-stderr>", "<task-notification>",
}

type entry struct {
	Type             string `json:"type"`
	IsMeta           bool   `json:"isMeta"`
	IsSidechain      bool   `json:"isSidechain"` // a subagent's turn: its "user" text is the assistant's prompt
	IsCompactSummary bool   `json:"isCompactSummary"`
	Message          struct {
		Content json.RawMessage `json:"content"`
	} `json:"message"`
}

type block struct {
	Type  string          `json:"type"`
	Text  string          `json:"text"`
	Name  string          `json:"name"`
	Input json.RawMessage `json:"input"`
}

// ReadClaudeJSONL reads a Claude Code transcript file and returns the newest
// user text blocks and assistant tool_use blocks, bounded by maxMessages and
// maxBytes. Only the last 2 MiB of the file is read. Unparseable lines are
// skipped; a file with nothing usable yields an empty slice, not an error.
//
// Assistant text and thinking, and tool_result blocks (which arrive inside
// user-role messages), are dropped so that tool output never reaches the
// judge.
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
	return Limit(msgs, maxMessages, maxBytes), nil
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
		if e.Type == "user" && keepUserText(text) {
			return []Message{{Role: "user", Text: text}}
		}
		return nil
	}
	var blocks []block
	if json.Unmarshal(e.Message.Content, &blocks) != nil {
		return nil
	}
	var out []Message
	for _, b := range blocks {
		switch {
		case e.Type == "user" && b.Type == "text" && keepUserText(b.Text):
			out = append(out, Message{Role: "user", Text: b.Text})
		case e.Type == "assistant" && b.Type == "tool_use" && b.Name != "":
			out = append(out, Message{Role: "tool_call", Tool: b.Name, Input: b.Input})
		}
	}
	return out
}

func keepUserText(s string) bool {
	t := strings.TrimSpace(s)
	if t == "" {
		return false
	}
	for _, p := range ignoredUserPrefixes {
		if strings.HasPrefix(t, p) {
			return false
		}
	}
	return true
}

// Limit keeps the newest messages within maxMessages and maxBytes (a
// message's size is len(Text)+len(Input)). Any single text or input over
// maxBytes/4 is truncated with a marker. Limits <= 0 default to 20 and 24000.
func Limit(msgs []Message, maxMessages, maxBytes int) []Message {
	if maxMessages <= 0 {
		maxMessages = defaultMessages
	}
	if maxBytes <= 0 {
		maxBytes = defaultBytes
	}
	one := maxBytes / 4
	kept := []Message{}
	total := 0
	for i := len(msgs) - 1; i >= 0 && len(kept) < maxMessages; i-- {
		m := truncate(msgs[i], one)
		size := len(m.Text) + len(m.Input)
		if total+size > maxBytes {
			break
		}
		total += size
		kept = append(kept, m)
	}
	for i, j := 0, len(kept)-1; i < j; i, j = i+1, j-1 {
		kept[i], kept[j] = kept[j], kept[i]
	}
	return kept
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
