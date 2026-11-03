package rules

import (
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
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
// A glob in the file name (`.claude/*.json`) counts as naming them.
var protectedShell = regexp.MustCompile(`(?i)\.claude/(?:settings|[^/\s]*[*?\[])|\.callguard\b|/etc/callguard|programdata/callguard` +
	`|\.hermes/(?:config\.yaml|shell-hooks-allowlist\.json|[^/\s]*[*?\[])|\.config/opencode/plugins|\.opencode/plugins|\.pi/(?:agent/)?extensions`)

// diskDevRE matches the names of whole-disk and partition block devices.
const diskDevRE = `(?:sd|hd|vd|xvd|nvme|mmcblk|disk)`

var (
	diskWipe = []*regexp.Regexp{
		regexp.MustCompile(`(?m)(?:^|[;&|(])\s*(?:(?:sudo|doas)\b[^;&|\n]*\s)?(?:\S*/)?mkfs(?:\.\w+)?\b`),
		regexp.MustCompile(`\bdd\b[^;&|\n]*\bof=/dev/` + diskDevRE),
		regexp.MustCompile(`>\s*/dev/` + diskDevRE),
		regexp.MustCompile(`(?i)(?:^|[;&|])\s*format(?:\.com)?\s+[a-z]:`),
	}
	forkBomb = regexp.MustCompile(`:\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:`)

	// segmentSplit cuts a command line at separators, subshells and command
	// substitutions, so each piece starts at a command position.
	segmentSplit = regexp.MustCompile("[;&|\\n\\r()`]+")
	rmDanger     = regexp.MustCompile(`(?i)^(?:/+\*?|~/?\*?|(?:\$home|\$\{home\}|\$env:(?:userprofile|home)|%userprofile%)/?\*?|(?:\./)?\.git/?|[a-z]:/?\*?)$`)
	unixFlags    = regexp.MustCompile(`^-[a-zA-Z]+$`) // -rf, -Rfv
	winFlag      = regexp.MustCompile(`^/[a-zA-Z]$`)
	unquote      = strings.NewReplacer(`"`, "", `'`, "")
)

// removers are commands that delete files.
var removers = map[string]bool{"rm": true, "rmdir": true, "rd": true, "del": true, "erase": true, "remove-item": true, "ri": true}

// wrappers run the rest of their arguments as a command (shells with -c
// too). The value lists the options that take a separate argument, and
// "#n" says that n positional arguments precede the command.
var wrappers = map[string][]string{
	"sudo": {"-u", "-g", "-C", "-D", "-h", "-p", "-r", "-t", "-T", "-U", "--user", "--group", "--chdir", "--chroot",
		"--close-from", "--host", "--prompt", "--role", "--type", "--command-timeout", "--other-user"},
	"doas": {"-u", "-C"}, "env": {"-u", "-C", "-S", "--unset", "--chdir", "--split-string"},
	"nice": {"-n", "--adjustment"}, "ionice": {"-c", "-n", "-p"}, "timeout": {"-s", "-k", "--signal", "--kill-after", "#1"},
	"stdbuf": {"-i", "-o", "-e"}, "chroot": {"#1"}, "xargs": {"-a", "-d", "-E", "-I", "-L", "-n", "-P", "-s"},
	"exec": {"-a"}, "time": {"-f", "-o"}, "command": nil, "nohup": nil, "setsid": nil, "busybox": nil,
	"sh": nil, "bash": nil, "zsh": nil, "dash": nil, "{": nil, "!": nil, "if": nil, "then": nil, "else": nil, "do": nil,
}

// commandName is the lower-case base name of a command word.
func commandName(tok string) string {
	return strings.ToLower(strings.TrimSuffix(path.Base(strings.ReplaceAll(tok, `\`, "/")), ".exe"))
}

// skipWrapper returns the index of the command a wrapper at toks[i] runs.
func skipWrapper(toks []string, i int, valued []string) int {
	positional := 0
	for _, o := range valued {
		if strings.HasPrefix(o, "#") {
			positional, _ = strconv.Atoi(o[1:])
		}
	}
	for i < len(toks) {
		t := toks[i]
		switch {
		case t == "--":
			return i + 1
		case strings.HasPrefix(t, "-") && len(t) > 1:
			i++
			if slices.Contains(valued, t) {
				i++ // the option's value
			}
		case strings.Contains(t, "="): // env VAR=value
			i++
		case positional > 0:
			positional--
			i++
		default:
			return i
		}
	}
	return i
}

// RmRoot reports whether a shell command recursively deletes a root-like
// target (/, ~, $HOME, a drive root, .git) or passes --no-preserve-root.
// It looks at the command position of each separated segment (after
// wrappers such as sudo, timeout or sh -c), so text inside an ordinary
// argument does not fire it.
func RmRoot(command string) bool {
	for _, seg := range segmentSplit.Split(command, -1) {
		toks := strings.Fields(unquote.Replace(seg))
		i := 0
		for i < len(toks) {
			if valued, ok := wrappers[commandName(toks[i])]; ok {
				i = skipWrapper(toks, i+1, valued)
				continue
			}
			if strings.Contains(toks[i], "=") { // VAR=value prefix
				i++
				continue
			}
			break
		}
		if i >= len(toks) {
			continue
		}
		name := commandName(toks[i])
		if !removers[name] {
			continue
		}
		recursive := false
		var targets []string
		for _, t := range toks[i+1:] {
			lower := strings.ToLower(t)
			switch {
			case t == "--no-preserve-root":
				return true
			case t == "--recursive",
				len(t) > 1 && strings.HasPrefix("-recurse", lower), // PowerShell accepts -r, -rec, ...
				(name == "rm" || name == "rmdir") && unixFlags.MatchString(t) && strings.ContainsAny(t, "rR"):
				recursive = true
			case strings.HasPrefix(t, "-"):
			case winFlag.MatchString(t) && name != "rm":
				recursive = recursive || lower == "/s"
			default:
				targets = append(targets, path.Clean(strings.ReplaceAll(t, `\`, "/")))
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
	protected []*regexp.Regexp // write targets
	extra     []string         // extra files as they may appear in a command, folded
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
		p = env.slash(p)
		pat := "^" + regexp.QuoteMeta(p) + "$"
		if env.caseless() {
			pat = "(?i)" + pat
		}
		b.protected = append(b.protected, regexp.MustCompile(pat))
		b.extra = append(b.extra, env.fold(p))
		if home := strings.TrimSuffix(env.slash(env.Home), "/"); home != "" && env.InDir(p, home) && len(p) >= len(home) {
			rest := p[len(home):]
			b.extra = append(b.extra, env.fold("~"+rest), env.fold("$HOME"+rest))
		}
	}
	return b, nil
}

// namesProtected reports whether text (a command line or a tool input)
// names a hook or policy file.
func (b *Builtin) namesProtected(text string) bool {
	text = b.env.slash(text)
	if protectedShell.MatchString(text) {
		return true
	}
	folded := b.env.fold(text)
	for _, p := range b.extra {
		if strings.Contains(folded, p) {
			return true
		}
	}
	return false
}

// Check returns the first built-in rule that fires for c. Hard denies are
// checked before the self-protection ask.
func (b *Builtin) Check(c Call) (Hit, bool) {
	on := func(id string) bool { return !b.disabled[id] }
	if c.Kind == KindWrite && on("self-protect-write") {
		if c.Path != "" && anyMatch(b.protected, c.Path) {
			return Hit{"self-protect-write", "deny", "callguard denies edits to hook and policy files (" + c.Path + "); ask the user to change them"}, true
		}
		// Patch tools carry their target paths inside the input.
		if c.Path == "" && b.namesProtected(c.Whole) {
			return Hit{"self-protect-write", "ask", "edit names a hook or policy file; a human should confirm"}, true
		}
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
		if on("self-protect-shell") && b.namesProtected(cmd) {
			return Hit{"self-protect-shell", "ask", "command names a hook or policy file; a human should confirm"}, true
		}
	}
	return Hit{}, false
}
