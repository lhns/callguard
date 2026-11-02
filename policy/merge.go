package policy

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
)

// IsEmpty reports whether m has no condition at all (an invalid rule).
func (m Match) IsEmpty() bool {
	return len(m.Tool) == 0 && len(m.Kind) == 0 && m.Command == "" && m.URL == "" &&
		len(m.Field) == 0 && len(m.Path) == 0 && len(m.NotPath) == 0 && m.InProject == nil &&
		len(m.Context) == 0 && m.Unattended == nil && len(m.Harness) == 0
}

// Rev returns "sha256:<hex>" of the canonical JSON of p.
func Rev(p Policy) string {
	b, _ := json.Marshal(p) // a Policy always marshals
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// upsertRule replaces the rule with the same id in place, else appends.
func upsertRule(rules []Rule, r Rule) []Rule {
	for i := range rules {
		if rules[i].ID == r.ID {
			rules[i] = r
			return rules
		}
	}
	return append(rules, r)
}

// MergeSystem applies the system layer over base with full authority.
// Rules with an id already present replace that rule; others are appended.
func MergeSystem(base, sys Policy) Policy {
	out := base
	out.Rules = append([]Rule(nil), base.Rules...)
	if sys.Final {
		out.Final = true
	}
	if sys.Mode != "" {
		out.Mode = sys.Mode
	}
	if sys.Defaults != nil {
		out.Defaults = sys.Defaults
		if !*sys.Defaults {
			out.Rules = nil // base holds only the default rules at this point
		}
	}
	out.DisableBuiltin = append(append([]string(nil), base.DisableBuiltin...), sys.DisableBuiltin...)
	if sys.UnattendedAsk != "" {
		out.UnattendedAsk = sys.UnattendedAsk
	}
	if sys.DeadlineMS > 0 {
		out.DeadlineMS = sys.DeadlineMS
	}
	for _, r := range sys.Rules {
		out.Rules = upsertRule(out.Rules, r)
	}
	if sys.Nah != nil {
		n := *base.Nah
		n.Enabled = sys.Nah.Enabled
		n.Require = sys.Nah.Require
		if sys.Nah.Path != "" {
			n.Path = sys.Nah.Path
		}
		if sys.Nah.TimeoutMS > 0 {
			n.TimeoutMS = sys.Nah.TimeoutMS
		}
		if sys.Nah.Mode != "" {
			n.Mode = sys.Nah.Mode
		}
		out.Nah = &n
	}
	if sys.LLM != nil {
		out.LLM = mergeLLM(*base.LLM, *sys.LLM)
	}
	if len(sys.Backends) > 0 {
		out.Backends = map[string]Backend{}
		for k, v := range base.Backends {
			out.Backends[k] = v
		}
		for k, v := range sys.Backends {
			out.Backends[k] = v
		}
	}
	if sys.DenyStreak != nil {
		out.DenyStreak = sys.DenyStreak
	}
	if sys.Log != nil {
		out.Log = sys.Log
	}
	return out
}

func mergeLLM(b, s LLM) *LLM {
	if s.Enabled != nil {
		b.Enabled = s.Enabled
	}
	if s.Mode != "" {
		b.Mode = s.Mode
	}
	if s.Backend != "" {
		b.Backend = s.Backend
	}
	if s.TimeoutMS > 0 {
		b.TimeoutMS = s.TimeoutMS
	}
	if s.MinConfidence != nil {
		b.MinConfidence = s.MinConfidence
	}
	if s.Transcript != nil {
		t := *b.Transcript
		if s.Transcript.MaxMessages > 0 {
			t.MaxMessages = s.Transcript.MaxMessages
		}
		if s.Transcript.MaxBytes > 0 {
			t.MaxBytes = s.Transcript.MaxBytes
		}
		b.Transcript = &t
	}
	if s.Environment != nil {
		b.Environment = s.Environment
	}
	b.Block = append(append([]string(nil), b.Block...), s.Block...)
	if s.AllowExceptions != nil {
		b.AllowExceptions = s.AllowExceptions
	}
	return &b
}

// MergeTighten applies a user or project layer: it may add deny and ask
// rules, append llm.block and raise llm.min_confidence. Everything else is
// dropped; each drop is reported as a warning naming src (the file) and the key.
func MergeTighten(base, layer Policy, src string) (Policy, []string) {
	var warns []string
	drop := func(key, why string) {
		warns = append(warns, fmt.Sprintf("%s: %s ignored: %s", src, key, why))
	}
	const only = "this layer can only add deny/ask rules, append llm.block and raise llm.min_confidence"
	out := base
	out.Rules = append([]Rule(nil), base.Rules...)
	if layer.Final {
		drop("final", only)
	}
	if layer.Mode != "" {
		drop("mode", only)
	}
	if layer.Defaults != nil {
		drop("defaults", only)
	}
	if len(layer.DisableBuiltin) > 0 {
		drop("disable_builtin", only)
	}
	if layer.UnattendedAsk != "" {
		drop("unattended_ask", only)
	}
	if layer.Nah != nil {
		drop("nah", only)
	}
	if len(layer.Backends) > 0 {
		drop("backends", only)
	}
	if layer.DenyStreak != nil {
		drop("deny_streak", only)
	}
	if layer.DeadlineMS != 0 {
		drop("deadline_ms", only)
	}
	if layer.Log != nil {
		drop("log", only)
	}
	for _, r := range layer.Rules {
		if r.Decision == "allow" {
			drop("rules."+r.ID, "allow rules are not accepted from this layer")
			continue
		}
		out.Rules = append(out.Rules, r) // never replaces a lower layer's rule by id
	}
	if l := layer.LLM; l != nil {
		cp := *base.LLM
		if l.Enabled != nil {
			drop("llm.enabled", only)
		}
		if l.Mode != "" {
			drop("llm.mode", only)
		}
		if l.Backend != "" {
			drop("llm.backend", only)
		}
		if l.TimeoutMS != 0 {
			drop("llm.timeout_ms", only)
		}
		if l.Transcript != nil {
			drop("llm.transcript", only)
		}
		if l.Environment != nil {
			drop("llm.environment", only)
		}
		if l.AllowExceptions != nil {
			drop("llm.allow_exceptions", only)
		}
		cp.Block = append(append([]string(nil), cp.Block...), l.Block...)
		if l.MinConfidence != nil {
			if *l.MinConfidence > *cp.MinConfidence {
				cp.MinConfidence = l.MinConfidence
			} else {
				drop("llm.min_confidence", "may only be raised")
			}
		}
		out.LLM = &cp
	}
	return out, warns
}
