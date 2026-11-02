package declog

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state", "callguard", "decisions.jsonl")
	l := New(path)
	in := Entry{
		TS: "2026-11-02T10:00:00.123456789Z", ID: "abc", SessionID: "s1", Harness: "claude", Tool: "Bash", Kind: "shell",
		InputSHA256: "ff", Decision: "deny", Enforced: true, Layer: "llm", Rule: "r", Confidence: 0.9, Backend: "fake:x",
		PolicyRev: "sha256:1", LatencyMS: 12, Unattended: true, InputTokens: 100, OutputTokens: 5,
		Reason: "why", Input: json.RawMessage(`{"command":"x"}`),
	}
	if err := l.Append(in); err != nil {
		t.Fatal(err)
	}
	if err := l.Append(Entry{ID: "b", SessionID: "other", Layer: "rules"}); err != nil {
		t.Fatal(err)
	}
	got, err := ReadTail(path, "s1")
	if err != nil || len(got) != 1 {
		t.Fatalf("read: %v %v", got, err)
	}
	if fmt.Sprint(got[0]) != fmt.Sprint(in) {
		t.Errorf("round trip:\n got %+v\nwant %+v", got[0], in)
	}
	data, _ := os.ReadFile(path)
	if strings.Count(string(data), "\n") != 2 {
		t.Errorf("one line per entry: %q", data)
	}
	if runtime.GOOS != "windows" {
		st, _ := os.Stat(path)
		ds, _ := os.Stat(filepath.Dir(path))
		if st.Mode().Perm() != 0o600 || ds.Mode().Perm() != 0o700 {
			t.Errorf("modes: file %v dir %v", st.Mode().Perm(), ds.Mode().Perm())
		}
	}
	// Optional fields stay out of the line when empty.
	line := strings.Split(string(data), "\n")[1]
	for _, k := range []string{`"reason"`, `"input"`, `"backend"`} {
		if strings.Contains(line, k) {
			t.Errorf("%s should be omitted: %s", k, line)
		}
	}
}

func TestReadTailMissingAndCorrupt(t *testing.T) {
	d := t.TempDir()
	if e, err := ReadTail(filepath.Join(d, "none"), "s"); err != nil || e != nil {
		t.Errorf("missing file: %v %v", e, err)
	}
	p := filepath.Join(d, "log")
	_ = os.WriteFile(p, []byte("garbage\n{\"id\":\"1\",\"session_id\":\"s\"}\n{\"id\":\n"), 0o600)
	if e, _ := ReadTail(p, "s"); len(e) != 1 || e[0].ID != "1" {
		t.Errorf("corrupt lines skipped: %+v", e)
	}
}

func TestReadTailBounded(t *testing.T) {
	p := filepath.Join(t.TempDir(), "log")
	// ~250 byte lines: 8000 of them exceed the 1 MiB tail.
	pad := strings.Repeat("x", 150)
	var b strings.Builder
	for i := 0; i < 8000; i++ {
		line, _ := json.Marshal(Entry{ID: fmt.Sprint(i), SessionID: "s", Reason: pad})
		b.Write(line)
		b.WriteString("\n")
	}
	if err := os.WriteFile(p, []byte(b.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	e, err := ReadTail(p, "s")
	if err != nil || len(e) == 0 || len(e) >= 8000 {
		t.Fatalf("tail should be a bounded suffix, got %d: %v", len(e), err)
	}
	if e[len(e)-1].ID != "7999" {
		t.Errorf("newest entry missing: %s", e[len(e)-1].ID)
	}
	if e[0].ID == "0" {
		t.Error("oldest entry should be cut")
	}
}

func TestLLMDenies(t *testing.T) {
	d := func(layer, dec string, enf bool) Entry { return Entry{Layer: layer, Decision: dec, Enforced: enf} }
	tests := []struct {
		name     string
		entries  []Entry
		cons, to int
	}{
		{"empty", nil, 0, 0},
		{"three in a row", []Entry{d("llm", "deny", true), d("llm", "deny", true), d("llm", "deny", true)}, 3, 3},
		{"allow breaks the run", []Entry{d("llm", "deny", true), d("llm", "deny", true), d("llm", "allow", true), d("llm", "deny", true)}, 1, 3},
		{"other layers neither count nor break", []Entry{d("llm", "deny", true), d("rules", "deny", true), d("builtin", "allow", true), d("llm", "deny", true)}, 2, 2},
		{"shadow denies do not count and break the run", []Entry{d("llm", "deny", true), d("llm", "deny", false)}, 0, 1},
		{"escalated ask neither counts nor breaks", []Entry{d("llm", "deny", true), d("llm", "deny", true), d("llm", "deny", true), {Layer: "llm", Decision: "ask", Enforced: true, Escalated: true}}, 3, 3},
		{"ask breaks", []Entry{d("llm", "deny", true), d("llm", "ask", true)}, 0, 1},
	}
	for _, tc := range tests {
		if c, n := LLMDenies(tc.entries); c != tc.cons || n != tc.to {
			t.Errorf("%s: got %d/%d, want %d/%d", tc.name, c, n, tc.cons, tc.to)
		}
	}
}

func TestDefaultPath(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", filepath.Join("x", "state"))
	if got := DefaultPath(); got != filepath.Join("x", "state", "callguard", "decisions.jsonl") {
		t.Errorf("XDG: %s", got)
	}
	t.Setenv("XDG_STATE_HOME", "")
	got := DefaultPath()
	if !strings.HasSuffix(got, filepath.Join("callguard", "decisions.jsonl")) {
		t.Errorf("default: %s", got)
	}
	switch runtime.GOOS {
	case "windows":
		t.Setenv("LocalAppData", `C:\L`)
		if got := DefaultPath(); got != `C:\L\callguard\decisions.jsonl` {
			t.Errorf("windows: %s", got)
		}
	case "darwin":
		if !strings.Contains(got, filepath.Join("Library", "Application Support")) {
			t.Errorf("darwin: %s", got)
		}
	default:
		if !strings.Contains(got, filepath.Join(".local", "state")) {
			t.Errorf("linux: %s", got)
		}
	}
}
