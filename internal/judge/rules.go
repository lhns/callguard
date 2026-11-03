package judge

import "regexp"

// RuleIDs are the rule ids the prompt defines; true marks a HARD rule. The
// dynamic ids policy-block-N (one per policy block entry) are HARD too, see
// IsHard. prompt.md and this table must list the same ids.
var RuleIDs = map[string]bool{
	"data-exfiltration":              true,
	"git-destructive":                false,
	"code-leaks-when-run":            false,
	"code-from-external":             false,
	"data-store-mass-delete":         false,
	"production-deploy":              false,
	"remote-shell-writes":            false,
	"sensitive-remote-exec":          false,
	"production-reads":               false,
	"blind-apply":                    false,
	"protected-iac-apply":            false,
	"logging-audit-tampering":        false,
	"permission-grant":               false,
	"account-standing-rule-changes":  false,
	"tls-auth-weaken":                false,
	"secret-store-writes":            false,
	"dns-domain-cert-changes":        false,
	"security-weaken":                false,
	"security-test-removal":          false,
	"safety-bypass-flag":             false,
	"create-unsafe-agents":           false,
	"interfere-with-workloads":       false,
	"shared-cluster-mutation":        false,
	"ci-bypass":                      false,
	"modify-shared-resources":        false,
	"irreversible-local-destruction": false,
	"unverifiable-deletion-target":   false,
	"shared-scratch-sweep":           false,
	"irreversible-deletion":          false,
	"unverifiable-deletion-scope":    false,
	"create-rce-surface":             false,
	"expose-local-services":          false,
	"external-ingress-tunnel":        false,
	"credential-leakage":             false,
	"credential-materialization":     false,
	"credential-exploration":         false,
	"pii-data-handling":              false,
	"exfil-scouting":                 false,
	"traffic-redirection":            false,
	"remote-repoint":                 false,
	"out-of-place-publication":       false,
	"sensitive-source-provenance":    false,
	"excess-sensitive-detail":        false,
	"containment-escape":             false,
	"create-public-surface":          false,
	"public-data-sharing-upload":     false,
	"untrusted-code-integration":     false,
	"package-registry-bypass":        false,
	"unauthorized-persistence":       false,
	"self-modification":              false,
	"instruction-poisoning":          false,
	"guard-bypass":                   false,
	"session-transcript-tampering":   false,
	"unrequested-commit":             false,
	"external-system-writes":         false,
	"merge-without-review":           false,
	"self-approval":                  false,
	"chatops-trigger":                false,
	"feature-flag-writes":            false,
	"node-lifecycle":                 false,
	"cluster-wide-workload":          false,
	"real-world-transactions":        false,
	"third-party-attack":             false,
	"unverifiable-payload":           false,
	"user-boundary":                  false,
	"rejected-retry":                 false,
}

var policyBlockRe = regexp.MustCompile(`^policy-block-\d+$`)

// IsHard reports whether rule is a HARD rule id: a hard block of the prompt or
// a policy block entry.
func IsHard(rule string) bool {
	return RuleIDs[rule] || policyBlockRe.MatchString(rule)
}
