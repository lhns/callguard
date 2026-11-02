package rules

import (
	"fmt"
	"regexp"

	"github.com/lhns/callguard/policy"
)

type compiled struct {
	rule    policy.Rule
	command *regexp.Regexp
	url     *regexp.Regexp
	fields  map[string]*regexp.Regexp
	path    []*regexp.Regexp
	notPath []*regexp.Regexp
}

// Set is a compiled, ordered list of policy rules.
type Set struct{ rules []compiled }

// Compile validates and compiles rules. The error names the offending rule.
func Compile(rules []policy.Rule, env Env) (*Set, error) {
	s := &Set{}
	for _, r := range rules {
		c, err := compileRule(r, env)
		if err != nil {
			return nil, fmt.Errorf("rule %q: %w", r.ID, err)
		}
		s.rules = append(s.rules, c)
	}
	return s, nil
}

func compileRule(r policy.Rule, env Env) (compiled, error) {
	c := compiled{rule: r}
	if r.ID == "" {
		return c, fmt.Errorf("missing id")
	}
	if r.Decision != "allow" && r.Decision != "ask" && r.Decision != "deny" {
		return c, fmt.Errorf("decision %q must be allow, ask or deny", r.Decision)
	}
	if r.Match.IsEmpty() {
		return c, fmt.Errorf("no match conditions")
	}
	var err error
	if r.Match.Command != "" {
		if c.command, err = regexp.Compile(r.Match.Command); err != nil {
			return c, fmt.Errorf("match.command: %w", err)
		}
	}
	if r.Match.URL != "" {
		if c.url, err = regexp.Compile(r.Match.URL); err != nil {
			return c, fmt.Errorf("match.url: %w", err)
		}
	}
	if len(r.Match.Field) > 0 {
		c.fields = map[string]*regexp.Regexp{}
		for k, v := range r.Match.Field {
			if c.fields[k], err = regexp.Compile(v); err != nil {
				return c, fmt.Errorf("match.field[%q]: %w", k, err)
			}
		}
	}
	for _, g := range r.Match.Path {
		re, err := env.CompileGlob(g)
		if err != nil {
			return c, fmt.Errorf("match.path: %w", err)
		}
		c.path = append(c.path, re)
	}
	for _, g := range r.Match.NotPath {
		re, err := env.CompileGlob(g)
		if err != nil {
			return c, fmt.Errorf("match.not_path: %w", err)
		}
		c.notPath = append(c.notPath, re)
	}
	return c, nil
}

func anyMatch(res []*regexp.Regexp, s string) bool {
	for _, re := range res {
		if re.MatchString(s) {
			return true
		}
	}
	return false
}

func has(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

func (c *compiled) matches(call Call) bool {
	m := c.rule.Match
	if len(m.Tool) > 0 && !has(m.Tool, call.Tool) {
		return false
	}
	if len(m.Kind) > 0 && !has(m.Kind, call.Kind) {
		return false
	}
	if len(m.Harness) > 0 && !has(m.Harness, call.Harness) {
		return false
	}
	if m.Unattended != nil && *m.Unattended != call.Unattended {
		return false
	}
	for k, allowed := range m.Context {
		if v, ok := call.Context[k]; !ok || !has(allowed, v) {
			return false
		}
	}
	if c.command != nil && (call.Command == "" || !c.command.MatchString(call.Command)) {
		return false
	}
	if c.url != nil && (call.URL == "" || !c.url.MatchString(call.URL)) {
		return false
	}
	for k, re := range c.fields {
		if k == "*" {
			if !re.MatchString(call.Whole) {
				return false
			}
			continue
		}
		if v, ok := call.Fields[k]; !ok || !re.MatchString(v) {
			return false
		}
	}
	if m.InProject != nil && (call.Path == "" || *m.InProject != call.InProject) {
		return false
	}
	if len(c.path) > 0 && (call.Path == "" || !anyMatch(c.path, call.Path)) {
		return false
	}
	if call.Path != "" && anyMatch(c.notPath, call.Path) {
		return false
	}
	return true
}

var rank = map[string]int{"allow": 1, "ask": 2, "deny": 3}

// Match returns the deciding rule among all matching ones: deny beats ask
// beats allow, ties go to the first in order.
func (s *Set) Match(call Call) (policy.Rule, bool) {
	var best *compiled
	for i := range s.rules {
		c := &s.rules[i]
		if !c.matches(call) {
			continue
		}
		if best == nil || rank[c.rule.Decision] > rank[best.rule.Decision] {
			best = c
		}
	}
	if best == nil {
		return policy.Rule{}, false
	}
	return best.rule, true
}
