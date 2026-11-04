// Conformance driver: nah's corpus through the spike binary and through the
// official nah release binary, against the same real directories, recorded per
// row and config. Adapted from internal/nahwasm/conformance_test.go on the
// nah-wasm branch; analyse the JSONL with analyse.py.
//
//	go run . -nah BIN -spike BIN -corpus DIR -platform linux|windows \
//	  -configs oracle,none,60000 -load 0 -out rows.jsonl
package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"
)

// T stands in for testing.T in the code taken over from the test.
type T struct{}

func (*T) Helper()                   {}
func (*T) Fatal(a ...any)            { log.Fatal(a...) }
func (*T) Fatalf(s string, a ...any) { log.Fatalf(s, a...) }

type Guard struct {
	Name    string `json:"name"`
	Enabled bool   `json:"enabled"`
}

// tempRoot is the current fixture's root, in the host's path form.
var tempRoot string

type record struct {
	ID, Fixture, Tool, Config string
	Input                     string
	Expected, ExpectedGuard   string
	Verdict                   string
	Coverage                  string
	Rules                     []string
	Refusals                  []string
	Warnings                  []string
	Failures                  []string
	Deadline                  bool
	Error                     string `json:",omitempty"`
	MS                        float64
}

func main() {
	nahBin := flag.String("nah", "", "official nah binary")
	spikeBin := flag.String("spike", "", "spike binary (also lists the guard catalog)")
	cgBin := flag.String("callguard", "", "callguard binary, for the config callguard:<budget ms>")
	corpus := flag.String("corpus", "", "nah corpus dir")
	platform := flag.String("platform", runtime.GOOS, "fixtures of this platform")
	configs := flag.String("configs", "oracle,none", "oracle, none (100 ms decide_with), or budget ms")
	load := flag.Int("load", 0, "CPU spinners to run alongside")
	filter := flag.String("filter", "", "row id substring")
	out := flag.String("out", "rows.jsonl", "output")
	every := flag.Int("every", 1, "only every Nth compared row")
	flag.Parse()
	log.SetFlags(log.Ltime)

	for i := 0; i < *load; i++ {
		go func() {
			x := uint64(1)
			for {
				x = x*31 + 7
			}
		}()
	}
	cfgs := strings.Split(*configs, ",")
	guardsOut, err := exec.Command(*spikeBin, "guards").Output()
	if err != nil {
		log.Fatal(err)
	}
	var catalog []Guard
	if err := json.Unmarshal(guardsOut, &catalog); err != nil {
		log.Fatal(err)
	}
	defaults := map[string]bool{}
	for _, g := range catalog {
		defaults[g.Name] = g.Enabled
	}
	t := &T{}
	fixtures := loadFixtures(t, filepath.Join(*corpus, "FIXTURES.json"))
	rows := loadRows(t, *corpus, *filter)
	byFixture := map[string][]row{}
	for _, r := range rows {
		byFixture[r.ObservationFixture] = append(byFixture[r.ObservationFixture], r)
	}
	names := make([]string, 0, len(byFixture))
	for n := range byFixture {
		names = append(names, n)
	}
	sort.Strings(names)
	f, err := os.Create(*out)
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	skipped := map[string]int{}
	compared, seen := 0, 0
	for _, name := range names {
		fx := fixtures.Observations[name]
		group := byFixture[name]
		if fx.Platform != *platform {
			skipped["platform "+fx.Platform] += len(group)
			continue
		}
		root, err := os.MkdirTemp("", "nahconf")
		if err != nil {
			log.Fatal(err)
		}
		if r, err := filepath.EvalSymlinks(root); err == nil {
			root = r
		}
		tempRoot = root
		rw := relocator(root, *platform)
		materialize(t, fx, rw)
		restore := setEnv(fx.Env, rw)
		for _, r := range group {
			c := fixtures.Contexts[r.CtxFixture]
			switch {
			case c.Enforcement != "":
				skipped["nap posture"]++
				continue
			case c.Platform != *platform:
				skipped["platform "+c.Platform]++
				continue
			case r.Code != "":
				skipped["code row"]++
				continue
			}
			seen++
			if seen%*every != 0 {
				continue
			}
			overrides, err := posture(c.ShippedGuards, defaults)
			if err != nil {
				log.Fatalf("%s: %v", r.ID, err)
			}
			home := rw(c.Home)
			writePosture(t, home, overrides)
			tool, input := r.call(rw)
			cwd := rw(fx.Cwd)
			req, _ := json.Marshal(map[string]any{"v": 1, "tool": tool, "input": input, "cwd": cwd})
			guards, _ := json.Marshal(overrides)
			for _, cfg := range cfgs {
				var cmd *exec.Cmd
				ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
				var stdin []byte = req
				if cfg == "oracle" {
					cmd = exec.CommandContext(ctx, *nahBin, "decide")
				} else if budget, ok := strings.CutPrefix(cfg, "callguard:"); ok {
					// callguard's own child process: `__engine` takes a NahRequest.
					ms, _ := strconv.Atoi(budget)
					stdin, _ = json.Marshal(map[string]any{
						"tool": tool, "input": json.RawMessage(input), "cwd": cwd, "project_dir": cwd,
						"guards": json.RawMessage(guards), "budget_ms": ms, "timeout_ms": 80000,
					})
					cmd = exec.CommandContext(ctx, *cgBin, "__engine")
				} else {
					args := []string{"decide", "--home", home, "--guards", string(guards)}
					if cfg != "none" {
						args = append(args, "--budget-ms", cfg)
					}
					cmd = exec.CommandContext(ctx, *spikeBin, args...)
				}
				cmd.Stdin = bytes.NewReader(stdin)
				cmd.Env = append(os.Environ(), "HOME="+home, "USERPROFILE="+home)
				cmd.Dir = cwdFor(cwd)
				var so, se bytes.Buffer
				cmd.Stdout, cmd.Stderr = &so, &se
				started := time.Now()
				runErr := cmd.Run()
				ms := float64(time.Since(started).Microseconds()) / 1e3
				cancel()
				rec := record{ID: r.ID, Fixture: name, Tool: tool, Config: cfg, Input: trunc(string(input)),
					Expected: r.Expected.Verdict, ExpectedGuard: r.Expected.Guard, MS: ms}
				var o output
				if strings.HasPrefix(cfg, "callguard:") {
					o = callguardOutput(so.Bytes())
				} else if err := json.Unmarshal(so.Bytes(), &o); err != nil || (o.Verdict == "" && o.Error == "") {
					rec.Error = fmt.Sprintf("unparseable (%v): %q %q", runErr, trunc(so.String()), trunc(se.String()))
				} else {
					rec.Verdict, rec.Coverage, rec.Refusals, rec.Warnings, rec.Failures, rec.Error =
						o.Verdict, o.Coverage, o.Refusals, o.Warnings, o.Failures, o.Error
					for _, a := range o.Attributions {
						rec.Rules = append(rec.Rules, a.Name)
					}
					sort.Strings(rec.Rules)
					rec.Deadline = strings.Contains(se.String(), "deadline-exceeded") ||
						slices.Contains(o.Refusals, "deadline-exceeded") ||
						slices.ContainsFunc(o.Warnings, func(w string) bool { return strings.Contains(w, "deadline-exceeded") })
				}
				if err := enc.Encode(rec); err != nil {
					log.Fatal(err)
				}
			}
			compared++
		}
		restore()
		os.RemoveAll(root)
		log.Printf("%s: %d rows, %d compared so far", name, len(group), compared)
	}
	log.Printf("rows %d compared %d skipped %v", len(rows), compared, skipped)
}

type output struct {
	Verdict      string   `json:"verdict"`
	Coverage     string   `json:"coverage"`
	Error        string   `json:"error"`
	Refusals     []string `json:"refusals"`
	Warnings     []string `json:"warnings"`
	Failures     []string `json:"failures"`
	Attributions []struct {
		Name string `json:"name"`
	} `json:"policy_attributions"`
}

// callguardOutput reads the `__engine` reply (one JSON line) as nah's output.
func callguardOutput(b []byte) output {
	var reply struct {
		Result *struct {
			Verdict  string   `json:"verdict"`
			Coverage string   `json:"coverage"`
			Warnings []string `json:"warnings"`
			Facts    *struct {
				Guards []string `json:"guards"`
			} `json:"facts"`
		} `json:"result"`
		Error string `json:"error"`
	}
	var o output
	if err := json.Unmarshal(bytes.TrimSpace(b), &reply); err != nil {
		return o
	}
	o.Error = reply.Error
	if r := reply.Result; r != nil {
		o.Verdict, o.Coverage, o.Warnings = r.Verdict, r.Coverage, r.Warnings
		if r.Facts != nil {
			for _, g := range r.Facts.Guards {
				o.Attributions = append(o.Attributions, struct {
					Name string `json:"name"`
				}{g})
			}
		}
	}
	return o
}

func trunc(s string) string {
	if len(s) > 400 {
		return s[:400]
	}
	return s
}

// cwdFor is the process cwd of both engines; a fixture cwd that is not there
// falls back to the temp directory.
func cwdFor(cwd string) string {
	if st, err := os.Stat(cwd); err == nil && st.IsDir() {
		return cwd
	}
	return os.TempDir()
}

// relocator rewrites fixture-owned roots to the same path under root.
func relocator(root, platform string) func(string) string {
	if platform == "windows" {
		bs := filepath.FromSlash(root)
		fs := filepath.ToSlash(root)
		return strings.NewReplacer(
			`C:\workspace`, bs+`\workspace`, `C:/workspace`, fs+`/workspace`,
			`C:\Users\test`, bs+`\Users\test`, `C:/Users/test`, fs+`/Users/test`,
		).Replace
	}
	return unixRelocator(root)
}

// ---- corpus ----

type fixtureFile struct {
	Contexts     map[string]ctxFixture `json:"ctx_fixtures"`
	Observations map[string]obsFixture `json:"observation_fixtures"`
}

type ctxFixture struct {
	ShippedGuards json.RawMessage `json:"shipped_guards"`
	Enforcement   string          `json:"enforcement"`
	Home          string          `json:"home"`
	Platform      string          `json:"platform"`
}

type obsFixture struct {
	Platform string             `json:"platform"`
	Cwd      string             `json:"cwd"`
	Env      map[string]*string `json:"env"`
	Paths    []pathFixture      `json:"paths"`
	Roots    []struct {
		Kind string `json:"kind"`
		Path string `json:"path"`
	} `json:"roots"`
	GitState []struct {
		Path           string   `json:"path"`
		TopLevel       string   `json:"top_level"`
		TrackedChanges bool     `json:"tracked_changes"`
		StashEntries   bool     `json:"stash_entries"`
		Untracked      []string `json:"untracked"`
		Ignored        []string `json:"ignored"`
	} `json:"git_state"`
}

type pathFixture struct {
	Exists      bool        `json:"exists"`
	Kind        string      `json:"kind"`
	Requested   string      `json:"requested"`
	Resolved    string      `json:"resolved"`
	Realpath    string      `json:"realpath"`
	TargetKind  string      `json:"target_kind"`
	Contents    *string     `json:"contents"`
	Descendants []string    `json:"descendants"`
	Links       [][2]string `json:"links"`
	Executable  *bool       `json:"executable"`
}

type row struct {
	ID                 string          `json:"id"`
	Command            string          `json:"command"`
	Tool               string          `json:"tool"`
	Input              json.RawMessage `json:"input"`
	Code               string          `json:"code"`
	CtxFixture         string          `json:"ctx_fixture"`
	ObservationFixture string          `json:"observation_fixture"`
	Expected           struct {
		Verdict string `json:"verdict"`
		Guard   string `json:"guard"`
	} `json:"expected"`
}

// call is the row's tool call with fixture-owned paths relocated.
func (r row) call(rw func(string) string) (string, json.RawMessage) {
	if r.Command != "" {
		b, _ := json.Marshal(map[string]string{"command": rw(r.Command)})
		return "Bash", b
	}
	var v any
	if err := json.Unmarshal(r.Input, &v); err != nil {
		return r.Tool, r.Input
	}
	b, _ := json.Marshal(relocateJSON(v, rw))
	return r.Tool, b
}

func relocateJSON(v any, rw func(string) string) any {
	switch x := v.(type) {
	case string:
		return rw(x)
	case []any:
		for i := range x {
			x[i] = relocateJSON(x[i], rw)
		}
	case map[string]any:
		for k := range x {
			x[k] = relocateJSON(x[k], rw)
		}
	}
	return v
}

func loadFixtures(t *T, path string) fixtureFile {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var f fixtureFile
	if err := json.Unmarshal(b, &f); err != nil {
		t.Fatal(err)
	}
	return f
}

func loadRows(t *T, dir, filter string) []row {
	t.Helper()
	files, err := filepath.Glob(filepath.Join(dir, "*.jsonl"))
	if err != nil || len(files) == 0 {
		t.Fatalf("no corpus files in %s", dir)
	}
	sort.Strings(files)
	var rows []row
	for _, f := range files {
		fh, err := os.Open(f)
		if err != nil {
			t.Fatal(err)
		}
		sc := bufio.NewScanner(fh)
		sc.Buffer(make([]byte, 1<<20), 1<<24)
		for sc.Scan() {
			line := bytes.TrimSpace(sc.Bytes())
			if len(line) == 0 {
				continue
			}
			var r row
			if err := json.Unmarshal(line, &r); err != nil {
				t.Fatalf("%s: %v", f, err)
			}
			if filter == "" || strings.Contains(r.ID, filter) {
				rows = append(rows, r)
			}
		}
		fh.Close()
	}
	return rows
}

// ---- materialization ----

// relocatedRoots are the fixture-owned top-level trees moved under the temp
// root; every other absolute path stays the host's.
var relocatedRoots = []string{"/workspace", "/home", "/srv", "/opt", "/mnt", "/backup", "/repo", "/ws", "/tools"}

// relocator rewrites every occurrence of a relocated root in s, on path
// boundaries, to the same path under root.
func unixRelocator(root string) func(string) string {
	return func(s string) string {
		var b strings.Builder
		for i := 0; i < len(s); {
			if s[i] == '/' && (i == 0 || !pathChar(s[i-1])) {
				matched := ""
				for _, r := range relocatedRoots {
					if strings.HasPrefix(s[i:], r) && (i+len(r) == len(s) || !wordChar(s[i+len(r)])) {
						matched = r
						break
					}
				}
				if matched != "" {
					b.WriteString(root)
					b.WriteString(matched)
					i += len(matched)
					continue
				}
			}
			b.WriteByte(s[i])
			i++
		}
		return b.String()
	}
}

func pathChar(c byte) bool { return wordChar(c) || c == '.' || c == '/' || c == '~' }
func wordChar(c byte) bool {
	return c == '_' || c == '-' || c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
}

func materialize(t *T, fx obsFixture, rw func(string) string) {
	t.Helper()
	owned := func(p string) bool {
		return p != "" && strings.HasPrefix(filepath.ToSlash(p), filepath.ToSlash(tempRoot)+"/")
	}
	mkdir := func(p string) {
		if owned(p) {
			_ = os.MkdirAll(p, 0o755)
		}
	}
	writeFile := func(p string, contents *string, executable *bool) {
		if !owned(p) {
			return
		}
		_ = os.MkdirAll(filepath.Dir(p), 0o755)
		if st, err := os.Lstat(p); err == nil && st.IsDir() {
			return
		}
		data := ""
		if contents != nil {
			data = rw(*contents)
		}
		mode := os.FileMode(0o644)
		if executable != nil && *executable {
			mode = 0o755
		}
		_ = os.WriteFile(p, []byte(data), mode)
		_ = os.Chmod(p, mode)
	}
	mkdir(rw(fx.Cwd))
	if h, ok := fx.Env["HOME"]; ok && h != nil {
		mkdir(rw(*h))
	}
	var links []pathFixture
	for _, p := range fx.Paths {
		if !p.Exists {
			continue
		}
		real := rw(p.Realpath)
		if real == "" {
			real = rw(p.Resolved)
		}
		switch p.Kind {
		case "file":
			writeFile(real, p.Contents, p.Executable)
		case "directory":
			mkdir(real)
			// a directory with descendants: entries that prefix another are
			// directories, the rest files
			ds := slices.Clone(p.Descendants)
			sort.Strings(ds)
			for i, d := range ds {
				d = rw(d)
				if i+1 < len(ds) && strings.HasPrefix(rw(ds[i+1]), d+"/") {
					mkdir(d)
				} else {
					writeFile(d, nil, nil)
				}
			}
		case "symlink":
			links = append(links, p)
		case "fifo":
			if owned(real) {
				_ = os.MkdirAll(filepath.Dir(real), 0o755)
				mkfifo(real)
			}
		}
	}
	for _, p := range links {
		at, target := rw(p.Resolved), rw(p.Realpath)
		if !owned(at) || target == "" {
			continue
		}
		switch p.TargetKind {
		case "file":
			writeFile(target, p.Contents, p.Executable)
		case "directory":
			mkdir(target)
		}
		_ = os.MkdirAll(filepath.Dir(at), 0o755)
		_ = os.Remove(at)
		_ = os.Symlink(target, at)
	}
	for _, p := range fx.Paths {
		for _, l := range p.Links {
			at := rw(l[0])
			if owned(at) {
				_ = os.MkdirAll(filepath.Dir(at), 0o755)
				_ = os.Symlink(rw(l[1]), at)
			}
		}
	}
	git := func(dir string, args ...string) {
		cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
		cmd.Env = append(os.Environ(), "GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@t", "GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@t")
		_ = cmd.Run()
	}
	initRepo := func(dir string) {
		if !owned(dir) {
			return
		}
		mkdir(dir)
		if _, err := os.Stat(filepath.Join(dir, ".git")); err != nil {
			git(dir, "init", "-q")
		}
	}
	for _, r := range fx.Roots {
		if r.Kind == "project" {
			initRepo(rw(r.Path))
		}
	}
	for _, g := range fx.GitState {
		top := rw(g.Path)
		if g.TopLevel != "" {
			top = rw(g.TopLevel)
		}
		if !owned(top) {
			continue
		}
		initRepo(top)
		mkdir(rw(g.Path))
		if g.TrackedChanges || g.StashEntries {
			tracked := filepath.Join(top, "tracked.txt")
			_ = os.WriteFile(tracked, []byte("v1\n"), 0o644)
			git(top, "add", "tracked.txt")
			git(top, "commit", "-q", "-m", "init")
			if g.StashEntries {
				_ = os.WriteFile(tracked, []byte("stash\n"), 0o644)
				git(top, "stash", "-q")
			}
			if g.TrackedChanges {
				_ = os.WriteFile(tracked, []byte("v2\n"), 0o644)
			}
		}
		base := rw(g.Path)
		for _, u := range g.Untracked {
			if strings.HasSuffix(u, "/") {
				mkdir(filepath.Join(base, u))
				writeFile(filepath.Join(base, u, "file"), nil, nil)
			} else {
				writeFile(filepath.Join(base, u), nil, nil)
			}
		}
		if len(g.Ignored) > 0 {
			_ = os.WriteFile(filepath.Join(base, ".gitignore"), []byte(strings.Join(g.Ignored, "\n")+"\n"), 0o644)
			for _, ig := range g.Ignored {
				if strings.HasSuffix(ig, "/") {
					writeFile(filepath.Join(base, ig, "file"), nil, nil)
				} else {
					writeFile(filepath.Join(base, ig), nil, nil)
				}
			}
		}
	}
}

// setEnv applies the fixture's environment (nil unsets) to this process,
// which both engines read: the native child inherits it and the module's
// host answers from it. It returns the restore function.
func setEnv(env map[string]*string, rw func(string) string) func() {
	saved := map[string]*string{}
	for name, v := range env {
		if old, ok := os.LookupEnv(name); ok {
			saved[name] = &old
		} else {
			saved[name] = nil
		}
		if v == nil {
			os.Unsetenv(name)
		} else {
			os.Setenv(name, rw(*v))
		}
	}
	return func() {
		for name, v := range saved {
			if v == nil {
				os.Unsetenv(name)
			} else {
				os.Setenv(name, *v)
			}
		}
	}
}

// posture turns a context fixture's shipped-guard posture into overrides of
// the factory defaults, the form native nah's built-ins.json takes.
func posture(raw json.RawMessage, defaults map[string]bool) (map[string]bool, error) {
	want := map[string]bool{}
	var named string
	if err := json.Unmarshal(raw, &named); err == nil {
		switch named {
		case "factory-defaults":
			return map[string]bool{}, nil
		case "factory-defaults-without-secrets-store-read":
			return map[string]bool{"secrets-store-read": false}, nil
		case "all-enabled":
			for n := range defaults {
				want[n] = true
			}
		case "all-disabled":
			for n := range defaults {
				want[n] = false
			}
		default:
			return nil, fmt.Errorf("unknown posture %q", named)
		}
	} else {
		var states struct {
			States []Guard `json:"states"`
		}
		if err := json.Unmarshal(raw, &states); err != nil {
			return nil, err
		}
		for n := range defaults {
			want[n] = false
		}
		for _, s := range states.States {
			want[s.Name] = s.Enabled
		}
	}
	out := map[string]bool{}
	for n, on := range want {
		if def, ok := defaults[n]; ok && def != on {
			out[n] = on
		}
	}
	return out, nil
}

func writePosture(t *T, home string, overrides map[string]bool) {
	t.Helper()
	dir := filepath.Join(home, ".nah")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(struct {
		V         int             `json:"v"`
		Overrides map[string]bool `json:"overrides"`
	}{2, overrides})
	if err := os.WriteFile(filepath.Join(dir, "built-ins.json"), append(b, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
}
