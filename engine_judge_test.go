package callguard

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/lhns/callguard/internal/declog"
	"github.com/lhns/callguard/internal/hostmeta"
	"github.com/lhns/callguard/internal/transcript"
	"github.com/lhns/callguard/policy"
)

func roles(msgs []transcript.Message) string {
	var s string
	for _, m := range msgs {
		s += m.Role[:1] + ":" + m.Text + m.ID + m.Outcome + " "
	}
	return s
}

func TestInlineTranscriptRolesAndReferents(t *testing.T) {
	e, v := newTestEngine(t, testPolicy(), Options{}, answer("allow", 0.9))
	req := bash("go test")
	req.Transcript = &Transcript{Messages: []Message{
		{Role: "assistant", Text: "A1 dropped"},
		{Role: "assistant", Text: "A2 shall I run the tests?"},
		{Role: "tool_call", Tool: "Bash", ID: "t1", Input: json.RawMessage(`{"command":"ls"}`)},
		{Role: "outcome", ID: "t1", Outcome: "rejected-by-user"},
		{Role: "outcome", ID: "t1", Outcome: "made-up"},
		{Role: "user", Text: "yes"},
		{Role: "assistant", Text: "A3 lost to a teammate"},
		{Role: "third_party"},
		{Role: "user", Text: "ok"},
		{Role: "assistant", Text: "A4 narration"},
		{Role: "system", Text: "ignored"},
	}}
	e.Decide(context.Background(), req)
	got := roles(v.last.Load().Transcript)
	want := "a:A2 shall I run the tests? t:t1 o:t1rejected-by-user u:yes u:ok "
	if got != want {
		t.Errorf("got  %q\nwant %q", got, want)
	}
}

func TestPriorCallguardBlocksMarkTheCall(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "d.jsonl")
	e, v := newTestEngine(t, testPolicy(), Options{LogPath: logPath}, answer("allow", 0.9))
	// An enforced deny of tool use "t1" in this session, a non-enforced one for
	// "t2", and an enforced deny of "t3" in another session.
	for _, en := range []declog.Entry{
		{ID: "1", SessionID: "s1", ToolUseID: "t1", Decision: "deny", Enforced: true},
		{ID: "2", SessionID: "s1", ToolUseID: "t2", Decision: "deny"},
		{ID: "3", SessionID: "other", ToolUseID: "t3", Decision: "deny", Enforced: true},
	} {
		if err := e.impl.logger.Append(en); err != nil {
			t.Fatal(err)
		}
	}
	req := bash("go test")
	req.Transcript = &Transcript{Messages: []Message{
		{Role: "user", Text: "go"},
		{Role: "tool_call", Tool: "Bash", ID: "t1", Input: json.RawMessage(`{"command":"a"}`)},
		{Role: "outcome", ID: "t1", Outcome: "error"},
		{Role: "tool_call", Tool: "Bash", ID: "t2", Input: json.RawMessage(`{"command":"b"}`)},
		{Role: "tool_call", Tool: "Bash", ID: "t3", Input: json.RawMessage(`{"command":"c"}`)},
	}}
	e.Decide(context.Background(), req)
	got := roles(v.last.Load().Transcript)
	want := "u:go t:t1 o:t1blocked-by-callguard t:t2 t:t3 "
	if got != want {
		t.Errorf("got  %q\nwant %q", got, want)
	}
}

func TestToolUseIDIsLogged(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "d.jsonl")
	e, _ := newTestEngine(t, testPolicy(), Options{LogPath: logPath}, answer("allow", 0.9))
	req := bash("go test")
	req.ToolUseID = "toolu_9"
	e.Decide(context.Background(), req)
	entries, _ := declog.ReadTail(logPath, "s1")
	if len(entries) != 1 || entries[0].ToolUseID != "toolu_9" {
		t.Errorf("%+v", entries)
	}
}

func TestFactsReachTheJudge(t *testing.T) {
	t.Setenv("NAH_FAKE", "delegate-partial")
	run := func(o Options, mut func(*Request)) *json.RawMessage {
		t.Helper()
		n := policy.Nah{Enabled: true, TimeoutMS: 5000}
		e, v := newTestEngine(t, testPolicy(func(p *policy.Policy) { p.Nah = &n }), o, answer("allow", 0.9))
		e.impl.nahArgv = []string{os.Args[0], "-test.run=TestHelperProcess", "--"}
		req := bash("go test")
		if mut != nil {
			mut(req)
		}
		e.Decide(context.Background(), req)
		f := v.last.Load().Facts
		return &f
	}
	if f := *run(Options{}, nil); string(f) != `{"source":"nah-decide","coverage":"partial"}` {
		t.Errorf("nah-decide summary: %s", f)
	}
	host := func(r *Request) { r.Facts = &Facts{Source: "nah-wasm", Coverage: "full"} }
	if f := *run(Options{}, host); string(f) != `{"source":"nah-wasm","coverage":"full"}` {
		t.Errorf("host facts win: %s", f)
	}
	if f := *run(Options{OmitFacts: true}, host); len(f) != 0 {
		t.Errorf("OmitFacts: %s", f)
	}
	// Without nah and without host facts there is nothing to show.
	e, v := newTestEngine(t, testPolicy(), Options{}, answer("allow", 0.9))
	e.Decide(context.Background(), bash("go test"))
	if f := v.last.Load().Facts; len(f) != 0 {
		t.Errorf("no facts expected: %s", f)
	}
}

func TestHostMetaProbe(t *testing.T) {
	e, v := newTestEngine(t, testPolicy(), Options{}, answer("allow", 0.9))
	var gotCwd, gotCmd string
	var gotHave *hostmeta.Meta
	e.impl.probe = func(_ context.Context, cwd, command string, have *hostmeta.Meta) *hostmeta.Meta {
		gotCwd, gotCmd, gotHave = cwd, command, have
		return &hostmeta.Meta{GitStatus: &hostmeta.GitStatus{Clean: true}, RepoVisibility: []hostmeta.RepoVisibility{{Remote: "github.com/o/r", Visibility: "public"}}}
	}
	req := bash("go test ./...")
	req.Meta = &Meta{RepoVisibility: []RepoVisibility{{Remote: "x", Visibility: "private"}}}
	e.Decide(context.Background(), req)
	in := v.last.Load()
	if gotCwd != cwd || gotCmd != "go test ./..." || gotHave != req.Meta || in.GitStatus == nil || !in.GitStatus.Clean || len(in.RepoVisibility) != 1 {
		t.Errorf("probe args %q %q, judge input %+v", gotCwd, gotCmd, in)
	}

	// Not a shell call, or no cwd: no probing, but a host-supplied meta passes.
	gotCmd = "untouched"
	read := call("WebFetch", `{"url":"https://example.com"}`)
	read.Meta = &Meta{GitStatus: &GitStatus{Clean: false, Untracked: 1}}
	e.Decide(context.Background(), read)
	if gotCmd != "untouched" || v.last.Load().GitStatus == nil || v.last.Load().GitStatus.Untracked != 1 {
		t.Errorf("non-shell: %q %+v", gotCmd, v.last.Load().GitStatus)
	}
	nocwd := bash("go test")
	nocwd.Cwd = ""
	e.Decide(context.Background(), nocwd)
	if gotCmd != "untouched" {
		t.Error("probed without a cwd")
	}
}
