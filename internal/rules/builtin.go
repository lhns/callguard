package rules

import (
	"path/filepath"
	"regexp"
	"strings"

	"github.com/lhns/callguard/policy"
)

// Hit is a built-in rule that fired.
type Hit struct {
	ID       string
	Decision string // "deny" or "ask"
	Reason   string
}

// protectedGlobs are the files that carry hook and policy configuration.
var protectedGlobs = []string{
	"**/.claude/settings.json", "**/.claude/settings.local.json",
	"**/.callguard/**", "/etc/callguard/**",
	"**/.hermes/config.yaml", "**/.hermes/shell-hooks-allowlist.json",
	"**/.config/opencode/plugins/**", "**/.opencode/plugins/**",
	"**/.pi/agent/extensions/**", "**/.pi/extensions/**",
}

// protectedShell finds those paths in a slash-normalized command line.
var protectedShell = regexp.MustCompile(`(?i)\.claude/settings(?:\.local)?\.json|\.callguard\b|/etc/callguard|programdata/callguard` +
	`|\.hermes/(?:config\.yaml|shell-hooks-allowlist\.json)|\.config/opencode/plugins|\.opencode/plugins|\.pi/(?:agent/)?extensions`)

var (
	diskWipe = []*regexp.Regexp{
		regexp.MustCompile(`(?m)(?:^|[;&|])\s*(?:sudo\s+)?mkfs(?:\.\w+)?\b`),
		regexp.MustCompile(`\bdd\b[^;&|\n]*\bof=/dev/(?:sd|nvme|disk|hd)`),
		regexp.MustCompile(`>\s*/dev/(?:sd|nvme|disk|hd)`),
		regexp.MustCompile(`(?i)(?:^|[;&|])\s*format(?:\.com)?\s+[a-z]:`),
	}
	forkBomb = regexp.MustCompile(`:\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:`)

	segmentSplit = regexp.MustCompile(`[;&|\n]+`)
	rmDanger     = regexp.MustCompile(`(?i)^(?:/+\*?|~/?\*?|(?:\$home|\$\{home\}|\$env:(?:userprofile|home)|%userprofile%)/?\*?|(?:\./)?\.git/?|[a-z]:/?\*?)$`)
	shortFlags   = regexp.MustCompile(`^-[a-zA-Z]{1,4}$`) // -rf, -Rf; not PowerShell's -Force
	winFlag      = regexp.MustCompile(`^/[a-zA-Z]$`)
)

// removers are commands that delete files; wrappers run another command.
var (
	removers = map[string]bool{"rm": true, "rmdir": true, "rd": true, "del": true, "erase": true, "remove-item": true, "ri": true}
	wrappers = map[string]bool{"sudo": true, "doas": true, "env": true, "command": true, "exec": true, "nohup": true, "time": true, "nice": true, "xargs": true}
)

// RmRoot reports whether a shell command recursively deletes a root-like
// target (/, ~, $HOME, a drive root, .git) or passes --no-preserve-root.
// It looks at the command position of each ;, &, | or newline separated
// segment, so text inside a quoted argument does not fire it.
func RmRoot(command string) bool {
	for _, seg := range segmentSplit.Split(command, -1) {
		toks := strings.Fields(seg)
		i := 0
		for i < len(toks) {
			t := strings.Trim(toks[i], `"'`)
			if wrappers[strings.ToLower(t)] || strings.HasPrefix(t, "-") || strings.Contains(t, "=") {
				i++
				continue
			}
			break
		}
		if i >= len(toks) {
			continue
		}
		name := strings.ToLower(strings.TrimSuffix(filepath.Base(strings.ReplaceAll(strings.Trim(toks[i], `"'`), `\`, "/")), ".exe"))
		if !removers[name] {
			continue
		}
		recursive := false
		var targets []string
		for _, t := range toks[i+1:] {
			t = strings.Trim(t, `"'`)
			switch {
			case t == "--no-preserve-root":
				return true
			case t == "--recursive" || strings.EqualFold(t, "-recurse") || shortFlags.MatchString(t) && strings.ContainsAny(t, "rR"):
				recursive = true
			case strings.HasPrefix(t, "-"):
			case winFlag.MatchString(t) && name != "rm":
				recursive = recursive || strings.EqualFold(t, "/s")
			default:
				targets = append(targets, strings.ReplaceAll(t, `\`, "/"))
			}
		}
		if !recursive {
			continue
		}
		for _, t := range targets {
			if rmDanger.MatchString(t) {
				return true
			}
		}
	}
	return false
}

// Builtin is the always-on layer 0.
type Builtin struct {
	env       Env
	disabled  map[string]bool
	protected []*regexp.Regexp
}

// NewBuiltin compiles the built-in rules, minus the disabled ids. extra are
// further files for the self-protection rules (e.g. an explicit policy file).
func NewBuiltin(env Env, disabled []string, extra ...string) (*Builtin, error) {
	b := &Builtin{env: env, disabled: map[string]bool{}}
	for _, id := range disabled {
		b.disabled[id] = true
	}
	globs := append([]string(nil), protectedGlobs...)
	globs = append(globs, env.slash(filepath.Dir(policy.SystemPath()))+"/**")
	for _, g := range globs {
		re, err := env.CompileGlob(g)
		if err != nil {
			return nil, err
		}
		b.protected = append(b.protected, re)
	}
	for _, p := range extra {
		pat := "^" + regexp.QuoteMeta(env.slash(p)) + "$"
		if env.Windows {
			pat = "(?i)" + pat
		}
		b.protected = append(b.protected, regexp.MustCompile(pat))
	}
	return b, nil
}

// Check returns the first built-in rule that fires for c. Hard denies are
// checked before the self-protection ask.
func (b *Builtin) Check(c Call) (Hit, bool) {
	on := func(id string) bool { return !b.disabled[id] }
	if c.Kind == KindWrite && c.Path != "" && on("self-protect-write") && anyMatch(b.protected, c.Path) {
		return Hit{"self-protect-write", "deny", "callguard denies edits to hook and policy files (" + c.Path + "); ask the user to change them"}, true
	}
	if c.Kind == KindShell && c.Command != "" {
		cmd := c.Command
		if on("rm-root") && RmRoot(cmd) {
			return Hit{"rm-root", "deny", "recursive deletion of a root, home or .git directory"}, true
		}
		if on("disk-wipe") {
			for _, re := range diskWipe {
				if re.MatchString(cmd) {
					return Hit{"disk-wipe", "deny", "command formats or overwrites a disk"}, true
				}
			}
		}
		if on("fork-bomb") && forkBomb.MatchString(cmd) {
			return Hit{"fork-bomb", "deny", "fork bomb"}, true
		}
		if on("self-protect-shell") && protectedShell.MatchString(b.env.slash(cmd)) {
			return Hit{"self-protect-shell", "ask", "command names a hook or policy file; a human should confirm"}, true
		}
	}
	return Hit{}, false
}
