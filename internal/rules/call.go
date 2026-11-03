package rules

import (
	"bytes"
	"encoding/json"
	"sort"
	"strings"
)

// CallInput is the raw material for a Call.
type CallInput struct {
	Harness    string
	Tool       string
	Input      json.RawMessage
	Cwd        string
	ProjectDir string
	Context    map[string]string
	Unattended bool
}

// Call is a tool call prepared for matching.
type Call struct {
	Harness    string
	Tool       string
	Kind       string
	Command    string // shell command text, "" if none
	URL        string
	Path       string // normalized absolute path, "" if none
	InProject  bool
	Fields     map[string]string // top-level input fields; non-strings JSON-encoded
	Whole      string            // compact input JSON plus every string leaf, for the "*" field
	Context    map[string]string
	Unattended bool
	Cwd        string
	ProjectDir string
}

// joinContinuations joins shell (backslash) and PowerShell (backtick) line
// continuations, so a command split over lines is matched as one line.
var joinContinuations = strings.NewReplacer("\\\r\n", " ", "\\\n", " ", "`\r\n", " ", "`\n", " ")

var pathKeys = []string{"file_path", "path", "notebook_path", "filePath"}

// NewCall extracts command, URL and path from the tool input.
func NewCall(in CallInput, env Env) Call {
	c := Call{
		Harness: in.Harness, Tool: in.Tool, Kind: KindOf(in.Tool),
		Context: in.Context, Unattended: in.Unattended, Cwd: in.Cwd, ProjectDir: in.ProjectDir,
		Fields: map[string]string{},
	}
	var obj map[string]json.RawMessage
	if len(in.Input) > 0 {
		_ = json.Unmarshal(in.Input, &obj) // not an object: no fields
		var compact bytes.Buffer
		if json.Compact(&compact, in.Input) == nil {
			c.Whole = compact.String()
		} else {
			c.Whole = string(in.Input)
		}
		var leaves []string
		var anyv any
		if json.Unmarshal(in.Input, &anyv) == nil {
			collectStrings(anyv, &leaves)
		}
		if len(leaves) > 0 {
			c.Whole += "\n" + strings.Join(leaves, "\n")
		}
	}
	for k, raw := range obj {
		var s string
		if json.Unmarshal(raw, &s) == nil {
			c.Fields[k] = s
		} else {
			c.Fields[k] = string(raw)
		}
	}
	if c.Kind == KindShell {
		c.Command = c.Fields["command"]
		if c.Command == "" && in.Tool == "execute_code" {
			c.Command = c.Fields["code"]
		}
		c.Command = joinContinuations.Replace(c.Command)
	}
	c.URL = c.Fields["url"]
	rawPath := ""
	for _, k := range pathKeys {
		if v := c.Fields[k]; v != "" {
			rawPath = v
			break
		}
	}
	if rawPath == "" && c.Kind == KindRead {
		rawPath = in.Cwd // Glob, Grep and LS default to the working directory
	}
	if rawPath != "" {
		c.Path = env.Normalize(rawPath, in.Cwd)
		if in.ProjectDir != "" {
			c.InProject = env.InDir(c.Path, env.Normalize(in.ProjectDir, in.Cwd))
		}
	}
	return c
}

func collectStrings(v any, out *[]string) {
	switch t := v.(type) {
	case string:
		*out = append(*out, t)
	case []any:
		for _, e := range t {
			collectStrings(e, out)
		}
	case map[string]any:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			collectStrings(t[k], out)
		}
	}
}
