package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"

	"github.com/lhns/callguard/internal/rules"
	"github.com/lhns/callguard/policy"
)

const policyUsage = `usage: callguard policy check [--policy file] [--project-dir dir] [--no-user-policy] [--json]
`

// cmdPolicy implements "callguard policy check".
func cmdPolicy(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || args[0] != "check" {
		fmt.Fprint(stderr, policyUsage)
		return 64
	}
	fs := flag.NewFlagSet("policy check", flag.ContinueOnError)
	fs.SetOutput(stderr)
	policyFile := fs.String("policy", "", "system policy `file` (default: the platform path)")
	projectDir := fs.String("project-dir", "", "project `dir` whose .callguard/policy.json is included")
	noUser := fs.Bool("no-user-policy", false, "skip the user policy layer")
	asJSON := fs.Bool("json", false, "print the report as JSON")
	if err := fs.Parse(args[1:]); err != nil {
		return 64
	}

	lo := policy.LoadOptions{SystemPolicy: *policyFile, ProjectDir: *projectDir}
	if *noUser {
		lo.UserConfigDir = "-"
	}
	rep := checkPolicy(lo)
	if *asJSON {
		b, _ := json.MarshalIndent(rep, "", "  ")
		fmt.Fprintf(stdout, "%s\n", b)
	} else {
		rep.print(stdout)
	}
	if len(rep.Errors) > 0 {
		return 1
	}
	return 0
}

type policyReport struct {
	Files     []string       `json:"files"`
	PolicyRev string         `json:"policy_rev,omitempty"`
	Policy    *policy.Policy `json:"policy,omitempty"`
	Warnings  []string       `json:"warnings"`
	Errors    []string       `json:"errors"`
}

func checkPolicy(lo policy.LoadOptions) policyReport {
	rep := policyReport{Files: []string{}, Warnings: []string{}, Errors: []string{}}
	l, err := policy.Load(lo)
	if err != nil {
		rep.Errors = append(rep.Errors, err.Error())
		return rep
	}
	seen := map[string]bool{}
	for _, f := range l.Files {
		rep.Files = append(rep.Files, fmt.Sprintf("%s (%s)", f.Path, f.Layer))
		for _, k := range f.Unknown {
			rep.Errors = append(rep.Errors, fmt.Sprintf("%s: unknown key %q", f.Path, k))
		}
		for _, p := range f.Problems {
			seen[p] = true
			rep.Errors = append(rep.Errors, f.Path+": "+p)
		}
	}
	for _, p := range policy.Validate(l.Policy, true) {
		if !seen[p] {
			rep.Errors = append(rep.Errors, "merged policy: "+p)
		}
	}
	env := rules.DefaultEnv()
	for _, r := range l.Policy.Rules {
		if _, err := rules.Compile([]policy.Rule{r}, env); err != nil {
			rep.Errors = append(rep.Errors, err.Error())
		}
	}
	rep.Warnings = append(rep.Warnings, l.Warnings...)
	rep.PolicyRev = policy.Rev(l.Policy)
	rep.Policy = &l.Policy
	return rep
}

func (r policyReport) print(w io.Writer) {
	fmt.Fprintln(w, "files read:")
	if len(r.Files) == 0 {
		fmt.Fprintln(w, "  (none: built-in defaults only)")
	}
	for _, f := range r.Files {
		fmt.Fprintln(w, "  "+f)
	}
	if r.Policy != nil {
		b, _ := json.MarshalIndent(r.Policy, "", "  ")
		fmt.Fprintf(w, "merged policy:\n%s\npolicy_rev: %s\n", b, r.PolicyRev)
	}
	for _, x := range r.Warnings {
		fmt.Fprintln(w, "warning: "+x)
	}
	for _, x := range r.Errors {
		fmt.Fprintln(w, "error: "+x)
	}
	if len(r.Errors) == 0 {
		fmt.Fprintln(w, "ok")
	}
}
