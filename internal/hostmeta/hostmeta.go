// Package hostmeta observes the repository around a pending shell call (git
// status, remote visibility) so the judge need not guess. It runs a few short
// processes under one deadline and never fails the call: anything that goes
// wrong leaves the observation out or marks the visibility unknown.
package hostmeta

import (
	"bytes"
	"context"
	"net/url"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"sync"
	"time"
)

// Budget is the deadline for all probing of one call.
const Budget = 300 * time.Millisecond

// Meta carries host observations about the pending call. Only the host or
// adapter sets it, never from agent text.
type Meta struct {
	GitStatus      *GitStatus       `json:"git_status,omitempty"`
	RepoVisibility []RepoVisibility `json:"repo_visibility,omitempty"`
}

// GitStatus summarises `git status --porcelain=v1`.
type GitStatus struct {
	Clean          bool     `json:"clean"`
	Staged         int      `json:"staged,omitempty"`
	Modified       int      `json:"modified,omitempty"`
	Untracked      int      `json:"untracked,omitempty"`
	Files          []string `json:"files,omitempty"`
	FilesTruncated bool     `json:"files_truncated,omitempty"`
}

// RepoVisibility is the visibility of one push or publish destination:
// "public", "private", "internal" or "unknown". Remote is host/owner/repo,
// or "" if it could not be resolved.
type RepoVisibility struct {
	Remote     string `json:"remote"`
	Visibility string `json:"visibility"`
}

// Runner runs a program and returns its stdout. env is appended to the
// process environment.
type Runner func(ctx context.Context, env []string, name string, args ...string) ([]byte, error)

// ExecRunner is the Runner that starts real processes.
func ExecRunner(ctx context.Context, env []string, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = append(os.Environ(), env...)
	cmd.WaitDelay = 50 * time.Millisecond
	var out bytes.Buffer
	cmd.Stdout = &out
	err := cmd.Run()
	return out.Bytes(), err
}

// Probe fills in what have lacks, for a shell command run in cwd: the git
// status when the command can destroy or publish uncommitted work, and the
// destination's visibility when it pushes or publishes. It returns have plus
// the new observations, or nil if there are none. cwd == "" skips probing.
func Probe(ctx context.Context, run Runner, cwd, command string, have *Meta) *Meta {
	out := Meta{}
	if have != nil {
		out = *have
	}
	if cwd == "" || command == "" {
		return have
	}
	wantStatus := out.GitStatus == nil && NeedsStatus(command)
	dests := Destinations(command)
	wantVis := len(out.RepoVisibility) == 0 && len(dests) > 0
	if !wantStatus && !wantVis {
		return have
	}
	ctx, cancel := context.WithTimeout(ctx, Budget)
	defer cancel()
	var wg sync.WaitGroup
	if wantStatus {
		wg.Add(1)
		go func() {
			defer wg.Done()
			out.GitStatus = Status(ctx, run, cwd)
		}()
	}
	if wantVis {
		wg.Add(1)
		go func() {
			defer wg.Done()
			out.RepoVisibility = Visibilities(ctx, run, cwd, dests)
		}()
	}
	wg.Wait()
	if out.GitStatus == nil && len(out.RepoVisibility) == 0 {
		return have
	}
	return &out
}

// Status runs git status in cwd. Any failure is nil.
func Status(ctx context.Context, run Runner, cwd string) *GitStatus {
	raw, err := run(ctx, []string{"GIT_OPTIONAL_LOCKS=0"}, "git", "-C", cwd, "-c", "core.fsmonitor=false", "status", "--porcelain=v1")
	if err != nil {
		return nil
	}
	return ParseStatus(string(raw))
}

// ParseStatus counts the entries of `git status --porcelain=v1` output.
func ParseStatus(porcelain string) *GitStatus {
	st := &GitStatus{}
	for _, line := range strings.Split(porcelain, "\n") {
		line = strings.TrimRight(line, "\r")
		if len(line) < 3 {
			continue
		}
		x, y := line[0], line[1]
		if x == '!' {
			continue
		}
		st.Files = append(st.Files, line)
		if x == '?' && y == '?' {
			st.Untracked++
			continue
		}
		if x != ' ' && x != '?' {
			st.Staged++
		}
		if y != ' ' && y != '?' {
			st.Modified++
		}
	}
	st.Clean = len(st.Files) == 0
	return st
}

var (
	rmRecursiveRe = regexp.MustCompile(`(?i)(^|[\s;&|(])rm\s+(-[a-z]*r|--recursive)`)
	removeItemRe  = regexp.MustCompile(`(?i)\bRemove-Item\b[^;&|\n]*-Recurse`)
	sepRe         = regexp.MustCompile(`&&|\|\||[;|\n&]`)
)

// NeedsStatus reports whether command can destroy uncommitted work or stage,
// commit or publish it.
func NeedsStatus(command string) bool {
	if rmRecursiveRe.MatchString(command) || removeItemRe.MatchString(command) {
		return true
	}
	for _, seg := range sepRe.Split(command, -1) {
		g, ok := parseGit(strings.Fields(seg))
		if !ok {
			continue
		}
		switch g.sub {
		case "add", "stage", "commit", "push", "restore", "clean":
			return true
		case "reset":
			if contains(g.args, "--hard") {
				return true
			}
		case "checkout":
			if contains(g.args, "--") || contains(g.args, ".") {
				return true
			}
		case "stash":
			if len(g.args) > 0 && (g.args[0] == "drop" || g.args[0] == "clear") {
				return true
			}
		case "worktree":
			if len(g.args) > 0 && g.args[0] == "remove" {
				return true
			}
		}
	}
	return false
}

type gitCall struct {
	sub  string
	args []string
}

// parseGit finds `git [global options] <sub> <args>` in fields.
func parseGit(fields []string) (gitCall, bool) {
	for i, f := range fields {
		if f != "git" && !strings.HasSuffix(f, "/git") && !strings.HasSuffix(f, `\git`) && f != "git.exe" {
			continue
		}
		rest := fields[i+1:]
		for len(rest) > 0 && strings.HasPrefix(rest[0], "-") {
			if (rest[0] == "-C" || rest[0] == "-c") && len(rest) > 1 {
				rest = rest[2:]
			} else {
				rest = rest[1:]
			}
		}
		if len(rest) == 0 {
			return gitCall{}, false
		}
		return gitCall{sub: rest[0], args: rest[1:]}, true
	}
	return gitCall{}, false
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

// A Destination is where a command pushes or publishes: a remote name, a URL
// or a gh repo argument. Raw == "origin" is the default.
type Destination struct {
	Raw string
	GH  bool // from a gh command: OWNER/REPO means github.com
}

var ghPublish = map[string]map[string]bool{
	"pr":      {"create": true, "merge": true, "comment": true},
	"issue":   {"create": true, "comment": true},
	"release": {"create": true, "upload": true},
	"repo":    {"create": true, "fork": true, "edit": true},
	"gist":    {"create": true, "edit": true},
}

// Destinations lists the push and publish destinations of command: the first
// non-flag argument of `git push` (default origin), the URL of `git remote
// add|set-url`, and the --repo/-R value of publishing gh commands (default
// origin).
func Destinations(command string) []Destination {
	var out []Destination
	seen := map[Destination]bool{}
	add := func(d Destination) {
		if !seen[d] {
			seen[d] = true
			out = append(out, d)
		}
	}
	for _, seg := range sepRe.Split(command, -1) {
		fields := strings.Fields(seg)
		if g, ok := parseGit(fields); ok {
			switch g.sub {
			case "push":
				add(Destination{Raw: firstNonFlag(g.args, 0, "origin")})
			case "remote":
				if len(g.args) > 0 && (g.args[0] == "add" || g.args[0] == "set-url") {
					if u := firstNonFlag(g.args[1:], 1, ""); u != "" {
						add(Destination{Raw: u})
					}
				}
			}
			continue
		}
		if sub, rest, ok := parseGH(fields); ok && ghPublish[sub[0]][sub[1]] {
			repo := "origin"
			for i, f := range rest {
				switch {
				case (f == "--repo" || f == "-R") && i+1 < len(rest):
					repo = rest[i+1]
				case strings.HasPrefix(f, "--repo="):
					repo = strings.TrimPrefix(f, "--repo=")
				}
			}
			add(Destination{Raw: repo, GH: repo != "origin"})
		}
	}
	return out
}

func parseGH(fields []string) (sub [2]string, rest []string, ok bool) {
	for i, f := range fields {
		if f == "gh" || f == "gh.exe" || strings.HasSuffix(f, "/gh") {
			if len(fields) < i+3 {
				return sub, nil, false
			}
			return [2]string{fields[i+1], fields[i+2]}, fields[i+3:], true
		}
	}
	return sub, nil, false
}

// firstNonFlag returns the n-th (0-based) argument not starting with "-".
func firstNonFlag(args []string, n int, def string) string {
	for _, a := range args {
		if strings.HasPrefix(a, "-") {
			continue
		}
		if n == 0 {
			return strings.Trim(a, `"'`)
		}
		n--
	}
	return def
}

// Visibilities resolves each destination to host/owner/repo and asks gh for
// its visibility. Whatever cannot be resolved is "unknown".
func Visibilities(ctx context.Context, run Runner, cwd string, dests []Destination) []RepoVisibility {
	out := make([]RepoVisibility, len(dests))
	var wg sync.WaitGroup
	for i, d := range dests {
		wg.Add(1)
		go func() {
			defer wg.Done()
			out[i] = visibility(ctx, run, cwd, d)
		}()
	}
	wg.Wait()
	return out
}

func visibility(ctx context.Context, run Runner, cwd string, d Destination) RepoVisibility {
	remote := ""
	switch {
	case d.GH && !strings.Contains(d.Raw, "://") && !strings.Contains(d.Raw, "@"):
		remote = d.Raw // OWNER/REPO or HOST/OWNER/REPO
		if strings.Count(remote, "/") == 1 {
			remote = "github.com/" + remote
		}
	case strings.Contains(d.Raw, "://") || strings.Contains(d.Raw, "@") || strings.Contains(d.Raw, ":"):
		remote = NormalizeRemote(d.Raw)
	default:
		raw, err := run(ctx, nil, "git", "-C", cwd, "remote", "get-url", d.Raw)
		if err == nil {
			remote = NormalizeRemote(strings.TrimSpace(string(raw)))
		}
	}
	res := RepoVisibility{Remote: remote, Visibility: "unknown"}
	host, _, _ := strings.Cut(remote, "/")
	if remote == "" || (host != "github.com" && host != os.Getenv("GH_HOST")) {
		return res
	}
	raw, err := run(ctx, nil, "gh", "repo", "view", remote, "--json", "visibility", "--jq", ".visibility")
	if err != nil {
		return res
	}
	switch v := strings.ToLower(strings.TrimSpace(string(raw))); v {
	case "public", "private", "internal":
		res.Visibility = v
	}
	return res
}

var scpRe = regexp.MustCompile(`^(?:[^@/\s]+@)?([^:/\s]+):(.+)$`)

// NormalizeRemote turns https://host/o/r(.git), git@host:o/r(.git) and
// ssh://git@host/o/r into host/o/r. It returns "" for anything else, such as
// a local path.
func NormalizeRemote(raw string) string {
	raw = strings.TrimSpace(raw)
	var host, path string
	if strings.Contains(raw, "://") {
		u, err := url.Parse(raw)
		if err != nil || u.Hostname() == "" {
			return ""
		}
		host, path = u.Hostname(), u.Path
	} else if m := scpRe.FindStringSubmatch(raw); m != nil && len(m[1]) > 1 { // a one-letter host is a Windows drive
		host, path = m[1], m[2]
	} else {
		return ""
	}
	path = strings.TrimSuffix(strings.Trim(path, "/"), ".git")
	if path == "" {
		return ""
	}
	return strings.ToLower(host) + "/" + path
}
