// Package rules maps tool calls to kinds, extracts paths and commands from
// their input, and evaluates the built-in and policy rules.
package rules

// Tool kinds (design §4).
const (
	KindShell = "shell"
	KindRead  = "read"
	KindWrite = "write"
	KindFetch = "fetch"
	KindAgent = "agent"
	KindMCP   = "mcp"
	KindOther = "other"
)

// kindOf holds the tool names of every supported harness. Names are
// case-sensitive and do not collide across harnesses, so one table serves all
// of them (a request from an unknown harness still maps sensibly).
var kindOf = map[string]string{
	// Claude Code
	"Bash": KindShell, "PowerShell": KindShell,
	"Read": KindRead, "Glob": KindRead, "Grep": KindRead, "LS": KindRead,
	"Write": KindWrite, "Edit": KindWrite, "MultiEdit": KindWrite, "NotebookEdit": KindWrite,
	"WebFetch": KindFetch, "WebSearch": KindFetch,
	"Task": KindAgent, "Agent": KindAgent,
	// opencode
	"bash": KindShell,
	"read": KindRead, "glob": KindRead, "grep": KindRead, "list": KindRead,
	"write": KindWrite, "edit": KindWrite, "patch": KindWrite,
	"webfetch": KindFetch, "websearch": KindFetch,
	"task": KindAgent,
	// pi (bash, read, write, edit above)
	"find": KindRead, "ls": KindRead, "multi-edit": KindWrite,
	// Hermes
	"terminal": KindShell, "execute_code": KindShell, "process": KindShell,
	"read_file": KindRead, "search_files": KindRead,
	"write_file": KindWrite,
	"web_search": KindFetch, "web_extract": KindFetch,
}

// KindOf returns the kind of the tool called name.
func KindOf(tool string) string {
	if k, ok := kindOf[tool]; ok {
		return k
	}
	if len(tool) > 5 && tool[:5] == "mcp__" {
		return KindMCP
	}
	return KindOther
}
