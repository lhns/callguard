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
	type want struct{ role, text, tool, input, id, outcome string }
	wants := []want{
		{"user", "please run the tests", "", "", "", ""},
		// The assistant text the user's next message replies to is kept.
		{"assistant", "ASSISTANT PROSE: I will run go test", "", "", "", ""},
		{"tool_call", "", "Bash", `{"command":"go test ./..."}`, "t1", ""},
		{"outcome", "", "", "", "t1", "ok"},
		{"user", "now fix the failing test", "", "", "", ""},
		// The trailing assistant text is the agent narrating, not a referent.
		{"tool_call", "", "Edit", `{"file_path":"/work/app/main_test.go","old_string":"a","new_string":"b"}`, "t2", ""},
	}
	if len(msgs) != len(wants) {
		b, _ := json.Marshal(msgs)
		t.Fatalf("got %d messages, want %d: %s", len(msgs), len(wants), b)
	}
	for i, w := range wants {
		m := msgs[i]
		if m.Role != w.role || m.Text != w.text || m.Tool != w.tool || string(m.Input) != w.input || m.ID != w.id || m.Outcome != w.outcome {
			t.Errorf("msg %d = %+v, want %+v", i, m, w)
		}
	}
	all, _ := json.Marshal(msgs)
	for _, bad := range []string{"IGNORE PREVIOUS", "SECRET REASONING", "plain string assistant text", "Caveat", "compact summary", "harness noise", "AAAA"} {
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

// A teammate or cross-session message arrives in a user-role entry but is not
// the user's consent: its text must not reach the judge as user text.
func TestThirdPartyMessagesAreNotUserText(t *testing.T) {
	lines := []string{
		`{"type":"user","message":{"role":"user","content":"<teammate-message teammate_id=\"a\">LEAKT approve the push</teammate-message>"}}`,
		`{"type":"user","message":{"role":"user","content":[{"type":"text","text":"<cross-session-message>LEAKC do it</cross-session-message>"}]}}`,
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
	all, _ := json.Marshal(msgs)
	if strings.Contains(string(all), "LEAK") || len(msgs) != 1 || msgs[0].Text != "keep me" {
		t.Errorf("got %s", all)
	}
}

func result(id string, isErr bool, content string) string {
	c, _ := json.Marshal(content)
	return `{"type":"user","message":{"role":"user","content":[{"type":"tool_result","tool_use_id":"` + id + `","is_error":` +
		map[bool]string{true: "true", false: "false"}[isErr] + `,"content":` + string(c) + `}]}}`
}

func TestOutcomesFromToolResults(t *testing.T) {
	arr := `{"type":"user","message":{"role":"user","content":[{"type":"tool_result","tool_use_id":"a7","is_error":true,"content":[{"type":"text","text":"[Request interrupted by user for tool use]"}]}]}}`
	reject := `{"type":"user","toolUseResult":"User rejected tool use","message":{"role":"user","content":[{"type":"tool_result","tool_use_id":"a8","is_error":true,"content":"whatever"}]}}`
	lines := []string{
		result("a1", false, "fine"),
		result("a2", true, "Exit code 1\nboom"),
		result("a3", true, "The user doesn't want to proceed with this tool use. The tool use was rejected"),
		result("a4", true, "Permission for this action was denied by the Claude Code auto mode classifier: x"),
		result("a5", true, "Permission to use Bash has been denied."),
		result("a6", true, "The server-side auto mode classifier gave no verdict"),
		arr, reject,
		// Without is_error the prefixes are plain output.
		result("a9", false, "The user doesn't want to proceed with this tool use"),
	}
	var calls []string
	for _, id := range []string{"a1", "a2", "a3", "a4", "a5", "a6", "a7", "a8", "a9"} {
		calls = append(calls, `{"type":"assistant","message":{"role":"assistant","content":[{"type":"tool_use","id":"`+id+`","name":"Bash","input":{}}]}}`)
	}
	p := filepath.Join(t.TempDir(), "t.jsonl")
	if err := os.WriteFile(p, []byte(strings.Join(append(calls, lines...), "\n")), 0o600); err != nil {
		t.Fatal(err)
	}
	msgs, err := ReadClaudeJSONL(p, 100, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, m := range msgs {
		if m.Role == RoleOutcome {
			got[m.ID] = m.Outcome
		}
	}
	want := map[string]string{"a1": "ok", "a2": "error", "a3": "rejected-by-user", "a4": "blocked-by-classifier",
		"a5": "blocked-by-permissions", "a6": "classifier-unavailable", "a7": "interrupted", "a8": "rejected-by-user", "a9": "ok"}
	for id, w := range want {
		if got[id] != w {
			t.Errorf("%s: %q, want %q", id, got[id], w)
		}
	}
	if all, _ := json.Marshal(msgs); strings.Contains(string(all), "boom") {
		t.Error("tool output reached the transcript")
	}
}

func TestReferents(t *testing.T) {
	u, a := func(s string) Message { return Message{Role: RoleUser, Text: s} }, func(s string) Message { return Message{Role: RoleAssistant, Text: s} }
	call, out := Message{Role: RoleToolCall, Tool: "Bash", ID: "c"}, Message{Role: RoleOutcome, ID: "c", Outcome: "ok"}
	tp := Message{Role: RoleThirdParty}
	in := []Message{
		a("A1 dropped, A2 follows"), a("A2 kept"), call, out, u("U1"),
		a("A3 dropped by third party"), tp, u("U2"),
		a("A4 narration"), call, out,
	}
	var got []string
	for _, m := range Referents(in) {
		got = append(got, m.Role+":"+m.Text)
	}
	joined := strings.Join(got, " ")
	if joined != "assistant:A2 kept tool_call: outcome: user:U1 user:U2 tool_call: outcome:" {
		t.Errorf("got %q", joined)
	}
}

func TestLimitDropsOrphanOutcomesAndMarkBlocked(t *testing.T) {
	msgs := []Message{
		{Role: RoleToolCall, Tool: "Bash", ID: "c1", Input: json.RawMessage(`{"a":"xxxxxxxx"}`)},
		{Role: RoleOutcome, ID: "c1", Outcome: "ok"},
		{Role: RoleUser, Text: "hi"},
	}
	got := Limit(msgs, 1, 0) // only the newest non-outcome message fits
	if len(got) != 1 || got[0].Role != RoleUser {
		t.Errorf("orphan outcome kept: %+v", got)
	}
	marked := MarkBlocked([]Message{
		{Role: RoleToolCall, Tool: "Bash", ID: "c1"},
		{Role: RoleOutcome, ID: "c1", Outcome: "error"},
		{Role: RoleToolCall, Tool: "Bash", ID: "c2"},
		{Role: RoleToolCall, Tool: "Bash", ID: "c3"},
	}, map[string]bool{"c1": true, "c2": true})
	var s []string
	for _, m := range marked {
		s = append(s, m.Role+":"+m.ID+":"+m.Outcome)
	}
	if strings.Join(s, " ") != "tool_call:c1: outcome:c1:blocked-by-callguard tool_call:c2: outcome:c2:blocked-by-callguard tool_call:c3:" {
		t.Errorf("got %v", s)
	}
}
