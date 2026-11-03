package hostmeta

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// script maps "name arg arg" to a canned answer; missing entries fail.
type script struct {
	answers map[string]string
	calls   atomic.Int32
}

func (s *script) run(_ context.Context, _ []string, name string, args ...string) ([]byte, error) {
	s.calls.Add(1)
	if a, ok := s.answers[name+" "+strings.Join(args, " ")]; ok {
		return []byte(a), nil
	}
	return nil, errors.New("no such command")
}

func TestParseStatus(t *testing.T) {
	st := ParseStatus("?? .env\nM  main.go\n MM both.go\nA  new.go\n")
	if st.Clean || st.Untracked != 1 || st.Staged != 2 || st.Modified != 1 || len(st.Files) != 4 {
		t.Errorf("%+v", st)
	}
	both := ParseStatus("MM x.go\n")
	if both.Staged != 1 || both.Modified != 1 {
		t.Errorf("both: %+v", both)
	}
	if c := ParseStatus(""); !c.Clean || c.Files != nil {
		t.Errorf("clean: %+v", c)
	}
}

func TestNeedsStatus(t *testing.T) {
	yes := []string{"git reset --hard HEAD~1", "git checkout -- .", "git checkout .", "git restore f", "git clean -fd",
		"git stash drop", "git stash clear", "git worktree remove ../w", "rm -rf build", "rm -fr x", "rm -r x", "cd x && rm -Rf y",
		"Remove-Item -Path x -Recurse -Force", "git add -A", "git stage f", "git commit -m x", "git push origin main", "git -C /r reset --hard"}
	no := []string{"git status", "git log", "git checkout main", "git reset --soft HEAD~1", "git stash", "rm file.txt", "echo rm -rf", "ls"}
	for _, c := range yes {
		if !NeedsStatus(c) {
			t.Errorf("want status for %q", c)
		}
	}
	for _, c := range no {
		if NeedsStatus(c) && c != "echo rm -rf" { // quoted text is best effort
			t.Errorf("no status for %q", c)
		}
	}
}

func TestDestinations(t *testing.T) {
	cases := map[string][]Destination{
		"git push":                                {{Raw: "origin"}},
		"git push -u upstream main":               {{Raw: "upstream"}},
		"git push https://h.io/o/r.git":           {{Raw: "https://h.io/o/r.git"}},
		"git remote add x git@github.com:o/r.git": {{Raw: "git@github.com:o/r.git"}},
		"gh pr create --title x":                  {{Raw: "origin"}},
		"gh issue comment 3 -R o/r -b hi":         {{Raw: "o/r", GH: true}},
		"gh repo edit --repo=h/o/r":               {{Raw: "h/o/r", GH: true}},
		"git push && gh release upload v1 f":      {{Raw: "origin"}},
		"gh pr view 3":                            nil,
		"git status":                              nil,
	}
	for cmd, want := range cases {
		if got := Destinations(cmd); !reflect.DeepEqual(got, want) {
			t.Errorf("%q: %+v, want %+v", cmd, got, want)
		}
	}
}

func TestNormalizeRemote(t *testing.T) {
	for in, want := range map[string]string{
		"https://github.com/o/r.git":     "github.com/o/r",
		"https://user@github.com/o/r":    "github.com/o/r",
		"git@github.com:o/r.git":         "github.com/o/r",
		"ssh://git@host.example:22/o/r/": "host.example/o/r",
		"/srv/git/r.git":                 "",
		`C:\repo`:                        "",
	} {
		if got := NormalizeRemote(in); got != want {
			t.Errorf("%q: %q, want %q", in, got, want)
		}
	}
}

func TestProbe(t *testing.T) {
	s := &script{answers: map[string]string{
		"git -C /w -c core.fsmonitor=false status --porcelain=v1":        "?? .env\nM  main.go\n",
		"git -C /w remote get-url origin":                                "git@github.com:o/r.git\n",
		"gh repo view github.com/o/r --json visibility --jq .visibility": "PUBLIC\n",
	}}
	got := Probe(context.Background(), s.run, "/w", "git add . && git push", nil)
	if got == nil || got.GitStatus == nil || got.GitStatus.Untracked != 1 || got.GitStatus.Staged != 1 || !reflect.DeepEqual(got.RepoVisibility, []RepoVisibility{{"github.com/o/r", "public"}}) {
		t.Errorf("%+v", got)
	}

	// What the request supplied is not probed again.
	have := &Meta{GitStatus: &GitStatus{Clean: true}, RepoVisibility: []RepoVisibility{{"h/o/r", "private"}}}
	s.calls.Store(0)
	if got := Probe(context.Background(), s.run, "/w", "git push", have); got != have || s.calls.Load() != 0 {
		t.Errorf("%+v, %d calls", got, s.calls.Load())
	}
	// No cwd, no probing; a harmless command spawns nothing.
	if got := Probe(context.Background(), s.run, "", "git push", nil); got != nil || s.calls.Load() != 0 {
		t.Errorf("no cwd: %+v", got)
	}
	if got := Probe(context.Background(), s.run, "/w", "ls", nil); got != nil || s.calls.Load() != 0 {
		t.Errorf("ls: %+v", got)
	}
	// Failures: no status, unknown visibility with the resolved remote.
	f := &script{answers: map[string]string{"git -C /w remote get-url origin": "https://gitlab.com/o/r.git"}}
	got = Probe(context.Background(), f.run, "/w", "git commit -m x && git push", nil)
	if got == nil || got.GitStatus != nil || !reflect.DeepEqual(got.RepoVisibility, []RepoVisibility{{"gitlab.com/o/r", "unknown"}}) {
		t.Errorf("failures: %+v", got)
	}
}

func TestProbeHonoursBudget(t *testing.T) {
	slow := func(ctx context.Context, _ []string, _ string, _ ...string) ([]byte, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	start := time.Now()
	got := Probe(context.Background(), slow, "/w", "git push", nil)
	if time.Since(start) > 2*Budget || got == nil || got.RepoVisibility[0].Visibility != "unknown" {
		t.Errorf("%v %+v", time.Since(start), got)
	}
}
