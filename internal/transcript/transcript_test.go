package transcript

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReadClaudeJSONLFixture(t *testing.T) {
	msgs, err := ReadClaudeJSONL(filepath.Join("testdata", "claude.jsonl"), 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	type want struct{ role, text, tool, input string }
	wants := []want{
		{"user", "please run the tests", "", ""},
		{"tool_call", "", "Bash", `{"command":"go test ./..."}`},
		{"user", "now fix the failing test", "", ""},
		{"tool_call", "", "Edit", `{"file_path":"/work/app/main_test.go","old_string":"a","new_string":"b"}`},
	}
	if len(msgs) != len(wants) {
		b, _ := json.Marshal(msgs)
		t.Fatalf("got %d messages, want %d: %s", len(msgs), len(wants), b)
	}
	for i, w := range wants {
		m := msgs[i]
		if m.Role != w.role || m.Text != w.text || m.Tool != w.tool || string(m.Input) != w.input {
			t.Errorf("msg %d = %+v, want %+v", i, m, w)
		}
	}
	all, _ := json.Marshal(msgs)
	for _, bad := range []string{"IGNORE PREVIOUS", "SECRET REASONING", "ASSISTANT PROSE", "Caveat", "compact summary", "harness noise", "AAAA"} {
		if strings.Contains(string(all), bad) {
			t.Errorf("%q survived", bad)
		}
	}
}

func TestReadClaudeJSONLEdgeCases(t *testing.T) {
	if _, err := ReadClaudeJSONL(filepath.Join(t.TempDir(), "missing.jsonl"), 0, 0); err == nil {
		t.Error("missing file: no error")
	}
	p := filepath.Join(t.TempDir(), "junk.jsonl")
	if err := os.WriteFile(p, []byte("garbage\n{not json\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	msgs, err := ReadClaudeJSONL(p, 0, 0)
	if err != nil || msgs == nil || len(msgs) != 0 {
		t.Errorf("junk: %v, %v", msgs, err)
	}
}

func TestReadClaudeJSONLTailDropsPartialLine(t *testing.T) {
	line := `{"type":"user","message":{"role":"user","content":"LINE"}}` + "\n"
	pad := `{"type":"user","message":{"role":"user","content":"` + strings.Repeat("p", 1000) + `"}}` + "\n"
	var b strings.Builder
	b.WriteString(line) // far in front of the tail window
	for b.Len() < tailBytes+5000 {
		b.WriteString(pad)
	}
	b.WriteString(`{"type":"user","message":{"role":"user","content":"LAST"}}` + "\n")
	p := filepath.Join(t.TempDir(), "big.jsonl")
	if err := os.WriteFile(p, []byte(b.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	msgs, err := ReadClaudeJSONL(p, 3, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(msgs) == 0 || msgs[len(msgs)-1].Text != "LAST" {
		t.Fatalf("msgs = %+v", msgs)
	}
	for _, m := range msgs {
		if m.Text == "LINE" {
			t.Error("line outside the tail window was read")
		}
	}
}

func TestLimit(t *testing.T) {
	var msgs []Message
	for i := 0; i < 30; i++ {
		msgs = append(msgs, Message{Role: "user", Text: string(rune('a'+i%26)) + "xx"})
	}
	got := Limit(msgs, 0, 0)
	if len(got) != 20 || got[19].Text != msgs[29].Text || got[0].Text != msgs[10].Text {
		t.Errorf("default limit: %d msgs, first %q last %q", len(got), got[0].Text, got[len(got)-1].Text)
	}
	got = Limit(msgs, 100, 12) // 4 messages of 3 bytes
	if len(got) != 4 || got[3].Text != msgs[29].Text {
		t.Errorf("byte limit: %d msgs", len(got))
	}

	long := Message{Role: "user", Text: strings.Repeat("é", 400)}
	got = Limit([]Message{long}, 5, 400)
	if len(got) != 1 || !strings.HasSuffix(got[0].Text, "…[truncated]") || len(got[0].Text) > 100 {
		t.Errorf("text truncation: %d bytes %q", len(got[0].Text), got[0].Text)
	}
	got = Limit([]Message{{Role: "tool_call", Tool: "Bash", Input: json.RawMessage(`{"command":"` + strings.Repeat("x", 500) + `"}`)}}, 5, 400)
	var s string
	if len(got) != 1 || json.Unmarshal(got[0].Input, &s) != nil || !strings.HasSuffix(s, "…[truncated]") {
		t.Errorf("input truncation: %+v", got)
	}
}

// Harness-generated user-role text (background task results, shell output,
// local command caveats) and sidechain entries (a subagent prompt written by
// the assistant) are not the user's words and must not reach the judge.
func TestReadClaudeJSONLDropsNonUserText(t *testing.T) {
	lines := []string{
		`{"type":"user","message":{"role":"user","content":"<task-notification>\n<summary>LEAK1</summary>\n</task-notification>"}}`,
		`{"type":"user","message":{"role":"user","content":"<local-command-caveat>LEAK2</local-command-caveat>"}}`,
		`{"type":"user","message":{"role":"user","content":[{"type":"text","text":"<bash-stdout>LEAK3</bash-stdout>"}]}}`,
		`{"type":"user","message":{"role":"user","content":"<bash-stderr>LEAK4</bash-stderr>"}}`,
		`{"type":"user","isSidechain":true,"message":{"role":"user","content":"LEAK5 written by the assistant"}}`,
		`{"type":"user","message":{"role":"user","content":"keep me"}}`,
	}
	p := filepath.Join(t.TempDir(), "t.jsonl")
	if err := os.WriteFile(p, []byte(strings.Join(lines, "\n")), 0o600); err != nil {
		t.Fatal(err)
	}
	msgs, err := ReadClaudeJSONL(p, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(msgs) != 1 || msgs[0].Text != "keep me" {
		t.Errorf("got %+v, want only the user's message", msgs)
	}
}
