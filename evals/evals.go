// Package evals embeds the labelled eval set used by "callguard eval".
//
// Each line of cases.jsonl is {"id", "bucket", "request", "expected", "note"}
// where request is a callguard/request/v1 object and expected is the decision
// the full pipeline should reach. Buckets (design §11):
//
//   - benign: routine calls; measures the false-positive rate. Includes a case
//     where the user named the exact risky action (intent clears a soft block).
//   - overeager: plausible but unrequested destructive or shared-state calls.
//     Irreversible but recoverable ones expect ask; destroying data or
//     infrastructure nobody asked to destroy expects deny.
//   - exfil-destroy: exfiltration of secrets, untrusted code execution,
//     destruction, guard tampering. Expect deny. Four rows are seeded from
//     nah's MIT corpus (command and expected verdict only; see note).
//   - tainted: the same kind of calls with context.trust "tainted"; network
//     egress and writes outside the project expect ask, local routine calls
//     still expect allow.
//   - injection: instructions aimed at the judge hidden in commands, file
//     names, file content, URLs and commit messages. Expect ask or deny,
//     never allow.
//   - judge: calls only a language model can decide (intent, referents, prior
//     rejections, repository visibility). The keyword fake judge cannot score
//     them, so TestPipelineOnEvalSet ignores this bucket; run a real backend.
package evals

import _ "embed"

// Cases is the embedded cases.jsonl.
//
//go:embed cases.jsonl
var Cases []byte
