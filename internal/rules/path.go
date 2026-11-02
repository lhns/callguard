package rules

import (
	"fmt"
	"os"
	"path"
	"regexp"
	"runtime"
	"strings"
	"unicode/utf8"
)

// Env carries what path handling needs from the host. Symlinks are never
// resolved: a link inside the project that points outside it counts as inside.
type Env struct {
	Home    string // user home directory, "" if unknown
	Windows bool   // backslash separators, drive letters, case-insensitive paths
}

// DefaultEnv describes the running host.
func DefaultEnv() Env {
	home, _ := os.UserHomeDir()
	return Env{Home: home, Windows: runtime.GOOS == "windows"}
}

func (e Env) slash(s string) string {
	if e.Windows {
		return strings.ReplaceAll(s, `\`, "/")
	}
	return s
}

func (e Env) isAbs(s string) bool {
	if strings.HasPrefix(s, "/") {
		return true
	}
	return e.Windows && len(s) >= 3 && s[1] == ':' && s[2] == '/' &&
		(s[0]|0x20 >= 'a' && s[0]|0x20 <= 'z')
}

// Normalize expands ~, makes p absolute against cwd and cleans it, using
// forward slashes. A relative p with no cwd stays relative.
func (e Env) Normalize(p, cwd string) string {
	p = e.slash(p)
	if e.Home != "" && (p == "~" || strings.HasPrefix(p, "~/")) {
		p = e.slash(e.Home) + p[1:]
	}
	if !e.isAbs(p) && cwd != "" {
		p = e.slash(cwd) + "/" + p
	}
	p = path.Clean(p)
	if e.Windows && len(p) == 2 && p[1] == ':' {
		p += "/" // path.Clean("C:/") drops the slash
	}
	return p
}

func (e Env) fold(s string) string {
	if e.Windows {
		return strings.ToLower(s)
	}
	return s
}

// InDir reports whether the normalized path p is dir or below it.
func (e Env) InDir(p, dir string) bool {
	if dir == "" {
		return false
	}
	p, dir = e.fold(p), e.fold(strings.TrimSuffix(dir, "/"))
	return p == dir || strings.HasPrefix(p, dir+"/")
}

// CompileGlob compiles a path glob. `*` and `?` stay inside one path
// segment, `**` crosses segments, `**/` also matches nothing and a trailing
// `/**` also matches the directory itself. A leading `~/` is expanded. The
// result matches normalized (slash, absolute) paths.
func (e Env) CompileGlob(glob string) (*regexp.Regexp, error) {
	g := e.slash(glob)
	if e.Home != "" && strings.HasPrefix(g, "~/") {
		g = e.slash(e.Home) + g[1:]
	}
	var b strings.Builder
	if e.Windows {
		b.WriteString("(?i)")
	}
	b.WriteString("^")
	for i := 0; i < len(g); {
		c := g[i]
		switch {
		case c == '/' && g[i:] == "/**":
			b.WriteString("(?:/.*)?")
			i += 3
		case c == '*' && i+1 < len(g) && g[i+1] == '*':
			j := i
			for j < len(g) && g[j] == '*' {
				j++
			}
			if j < len(g) && g[j] == '/' && (i == 0 || g[i-1] == '/') {
				b.WriteString("(?:.*/)?")
				j++
			} else {
				b.WriteString(".*")
			}
			i = j
		case c == '*':
			b.WriteString("[^/]*")
			i++
		case c == '?':
			b.WriteString("[^/]")
			i++
		case c == '[':
			end := strings.IndexByte(g[i:], ']')
			if end < 0 {
				return nil, fmt.Errorf("glob %q: unclosed [", glob)
			}
			class := g[i+1 : i+end]
			if strings.HasPrefix(class, "!") {
				class = "^" + class[1:]
			}
			b.WriteString("[" + class + "]")
			i += end + 1
		default:
			_, n := utf8.DecodeRuneInString(g[i:])
			b.WriteString(regexp.QuoteMeta(g[i : i+n]))
			i += n
		}
	}
	b.WriteString("$")
	re, err := regexp.Compile(b.String())
	if err != nil {
		return nil, fmt.Errorf("glob %q: %w", glob, err)
	}
	return re, nil
}
