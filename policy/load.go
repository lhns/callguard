package policy

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strings"
)

// Layer names used in File.Layer.
const (
	LayerSystem  = "system"
	LayerUser    = "user"
	LayerProject = "project"
)

// File is one parsed policy file.
type File struct {
	Path     string
	Layer    string
	Policy   Policy
	Unknown  []string // unknown keys, as dotted paths
	Problems []string // structural problems (see Validate)
}

// LoadOptions select the policy files. Same meaning as callguard.LoadOptions.
type LoadOptions struct {
	SystemPolicy  string
	ProjectDir    string
	UserConfigDir string // "-" skips the user layer
}

// Loaded is the merged policy and how it came about.
type Loaded struct {
	Policy   Policy
	Files    []File   // files actually read, lowest authority first
	Warnings []string // unknown keys and dropped (loosening) settings
}

// Problems lists the structural problems of all files.
func (l Loaded) Problems() []string {
	var out []string
	for _, f := range l.Files {
		for _, p := range f.Problems {
			out = append(out, f.Path+": "+p)
		}
	}
	return out
}

// SystemPath is the platform default system policy path.
func SystemPath() string {
	if runtime.GOOS == "windows" {
		pd := os.Getenv("ProgramData")
		if pd == "" {
			pd = `C:\ProgramData`
		}
		return filepath.Join(pd, "callguard", "policy.json")
	}
	return "/etc/callguard/policy.json"
}

// ReadFile parses one policy file. It fails on I/O errors, JSON errors and a
// wrong policy_version; other findings are recorded in the File.
func ReadFile(path, layer string) (File, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return File{}, err
	}
	data = bytes.TrimPrefix(data, []byte("\xef\xbb\xbf"))
	f := File{Path: path, Layer: layer}
	if err := json.Unmarshal(data, &f.Policy); err != nil {
		return f, fmt.Errorf("%s: %w", path, err)
	}
	if f.Policy.PolicyVersion != Version {
		return f, fmt.Errorf("%s: unsupported policy_version %d (want %d)", path, f.Policy.PolicyVersion, Version)
	}
	f.Unknown = UnknownKeys(data)
	f.Problems = Validate(f.Policy, false)
	return f, nil
}

// Load reads the system, user and project files and merges them over Default().
func Load(o LoadOptions) (Loaded, error) {
	out := Loaded{Policy: Default()}
	apply := func(path, layer string, mustExist bool) (bool, error) {
		f, err := ReadFile(path, layer)
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) && !mustExist {
				return false, nil
			}
			return false, err
		}
		out.Files = append(out.Files, f)
		for _, k := range f.Unknown {
			out.Warnings = append(out.Warnings, fmt.Sprintf("%s: unknown key %q ignored", path, k))
		}
		if layer == LayerSystem {
			out.Policy = MergeSystem(out.Policy, f.Policy)
			return true, nil
		}
		var w []string
		out.Policy, w = MergeTighten(out.Policy, f.Policy, path)
		out.Warnings = append(out.Warnings, w...)
		return true, nil
	}

	sysPath, explicit := o.SystemPolicy, o.SystemPolicy != ""
	if !explicit {
		sysPath = SystemPath()
	}
	if _, err := apply(sysPath, LayerSystem, explicit); err != nil {
		return out, err
	}
	if out.Policy.Final {
		return out, nil
	}
	if o.UserConfigDir != "-" {
		dir := o.UserConfigDir
		if dir == "" {
			dir, _ = os.UserConfigDir() // empty on failure: the layer is skipped
		}
		if dir != "" {
			if _, err := apply(filepath.Join(dir, "callguard", "policy.json"), LayerUser, false); err != nil {
				return out, err
			}
		}
	}
	if o.ProjectDir != "" {
		if _, err := apply(filepath.Join(o.ProjectDir, ".callguard", "policy.json"), LayerProject, false); err != nil {
			return out, err
		}
	}
	return out, nil
}

// UnknownKeys lists JSON keys in data that Policy does not define, as dotted
// paths ("rules[0].match.foo"), sorted within each object.
func UnknownKeys(data []byte) []string {
	var raw any
	if json.Unmarshal(data, &raw) != nil {
		return nil
	}
	var out []string
	walkUnknown(raw, reflect.TypeOf(Policy{}), "", &out)
	return out
}

func walkUnknown(raw any, t reflect.Type, path string, out *[]string) {
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	switch t.Kind() {
	case reflect.Struct:
		m, ok := raw.(map[string]any)
		if !ok {
			return
		}
		known := map[string]reflect.Type{}
		for i := 0; i < t.NumField(); i++ {
			name := strings.Split(t.Field(i).Tag.Get("json"), ",")[0]
			if name != "" && name != "-" {
				known[name] = t.Field(i).Type
			}
		}
		keys := make([]string, 0, len(m))
		for k := range m {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			p := k
			if path != "" {
				p = path + "." + k
			}
			ft, ok := known[k]
			if !ok {
				*out = append(*out, p)
				continue
			}
			walkUnknown(m[k], ft, p, out)
		}
	case reflect.Slice:
		arr, ok := raw.([]any)
		if !ok {
			return
		}
		for i, el := range arr {
			walkUnknown(el, t.Elem(), fmt.Sprintf("%s[%d]", path, i), out)
		}
	case reflect.Map:
		m, ok := raw.(map[string]any)
		if !ok {
			return
		}
		keys := make([]string, 0, len(m))
		for k := range m {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			walkUnknown(m[k], t.Elem(), path+"."+k, out)
		}
	}
}

// Validate lists structural problems of p. Regexes and globs are checked by
// rules.Compile. With merged, cross-references (llm.backend) are checked too.
func Validate(p Policy, merged bool) []string {
	var out []string
	add := func(f string, a ...any) { out = append(out, fmt.Sprintf(f, a...)) }
	oneOf := func(v string, ok ...string) bool {
		if v == "" {
			return true
		}
		for _, o := range ok {
			if v == o {
				return true
			}
		}
		return false
	}
	if !oneOf(p.Mode, ModeEnforce, ModeShadow) {
		add("mode %q must be enforce or shadow", p.Mode)
	}
	if !oneOf(p.UnattendedAsk, "deny", "ask") {
		add("unattended_ask %q must be deny or ask", p.UnattendedAsk)
	}
	if p.DeadlineMS < 0 {
		add("deadline_ms must not be negative")
	}
	for _, id := range p.DisableBuiltin {
		if !contains(BuiltinIDs, id) {
			add("disable_builtin: unknown built-in rule %q", id)
		}
	}
	for i, r := range p.Rules {
		name := fmt.Sprintf("rules[%d]", i)
		if r.ID != "" {
			name += " (" + r.ID + ")"
		}
		if r.ID == "" {
			add("%s: missing id", name)
		}
		if r.Decision != "allow" && r.Decision != "ask" && r.Decision != "deny" {
			add("%s: decision %q must be allow, ask or deny", name, r.Decision)
		}
		if r.Match.IsEmpty() {
			add("%s: rule has no match conditions", name)
		}
	}
	if n := p.Nah; n != nil {
		if !oneOf(n.Mode, ModeEnforce, ModeShadow) {
			add("nah.mode %q must be enforce or shadow", n.Mode)
		}
		if n.TimeoutMS < 0 {
			add("nah.timeout_ms must not be negative")
		}
	}
	if l := p.LLM; l != nil {
		if !oneOf(l.Mode, ModeEnforce, ModeShadow) {
			add("llm.mode %q must be enforce or shadow", l.Mode)
		}
		if l.MinConfidence != nil && (*l.MinConfidence < 0 || *l.MinConfidence > 1) {
			add("llm.min_confidence must be in [0,1]")
		}
		if l.TimeoutMS < 0 {
			add("llm.timeout_ms must not be negative")
		}
		if merged && p.LLMEnabled() && l.Backend != "" {
			if _, ok := p.Backends[l.Backend]; !ok {
				add("llm.backend %q is not defined in backends", l.Backend)
			}
		}
	}
	names := make([]string, 0, len(p.Backends))
	for k := range p.Backends {
		names = append(names, k)
	}
	sort.Strings(names)
	for _, k := range names {
		b := p.Backends[k]
		switch b.Type {
		case "anthropic", "openai", "fake":
		case "exec":
			if len(b.Command) == 0 {
				add("backends.%s: exec backend needs command", k)
			}
		default:
			add("backends.%s: unknown type %q (anthropic, openai, exec, fake)", k, b.Type)
		}
		if strings.HasSuffix(b.Model, "-latest") {
			add("backends.%s: model %q is a moving alias; use an exact model id", k, b.Model)
		}
	}
	if d := p.DenyStreak; d != nil && (d.Consecutive < 0 || d.Total < 0) {
		add("deny_streak values must not be negative")
	}
	return out
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}
