// Package hook turns harness hook payloads into callguard requests and
// callguard verdicts into each harness's native answer. The adapters never
// fail open: every internal failure becomes an ask/deny answer the harness
// honours (docs/design.md §9, §10).
package hook

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/lhns/callguard"
)

// MaxInput caps the hook payload read from stdin.
const MaxInput = 4 << 20

// maxContextFile caps --context-file.
const maxContextFile = 1 << 20

// Decider decides one request. It may panic; the adapters recover.
type Decider func(context.Context, *callguard.Request) callguard.Verdict

// Options are the adapter flags shared by all harnesses.
type Options struct {
	// Unattended marks every request as unattended (--unattended).
	Unattended bool
	// Context entries (--context key=value) are merged into req.Context.
	Context map[string]string
	// ContextFile is a JSON object of strings merged into req.Context
	// (--context-file). It is read on every call; an unreadable or invalid
	// file yields a fallback verdict. It must be root-owned: the agent must
	// not be able to write it.
	ContextFile string
	// AllowInAuto lets the Claude adapter emit allow in permission_mode auto.
	AllowInAuto bool
}

// readInput reads stdin up to MaxInput.
func readInput(in io.Reader) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(in, MaxInput+1))
	if err != nil {
		return nil, fmt.Errorf("reading stdin: %w", err)
	}
	if len(b) > MaxInput {
		return nil, fmt.Errorf("input larger than %d bytes", MaxInput)
	}
	return b, nil
}

// fallback returns callguard's fallback verdict, or a local ask/deny when
// that cannot be produced. It never returns allow.
func fallback(req *callguard.Request, cause string) (v callguard.Verdict) {
	defer func() {
		if recover() != nil {
			v = lastResort(req, cause)
		}
	}()
	v = callguard.FallbackVerdict(req, cause)
	if !v.Decision.Valid() || v.Decision == callguard.Allow {
		v = lastResort(req, cause)
	}
	return v
}

func lastResort(req *callguard.Request, cause string) callguard.Verdict {
	d := callguard.Ask
	if req != nil && req.Unattended {
		d = callguard.Deny
	}
	return callguard.Verdict{
		Schema:     callguard.VerdictSchema,
		V:          1,
		Decision:   d,
		Enforced:   true,
		Reason:     "could not evaluate this call (" + cause + "); a human has to approve it",
		Layer:      callguard.LayerFallback,
		Confidence: 1,
	}
}

// decide applies the context options and runs d. Panics, an invalid verdict
// and context errors become fallback verdicts.
func decide(ctx context.Context, d Decider, opt Options, req *callguard.Request) (v callguard.Verdict) {
	defer func() {
		if r := recover(); r != nil {
			v = fallback(req, fmt.Sprintf("internal error: %v", r))
		}
	}()
	if err := applyContext(req, opt); err != nil {
		return fallback(req, "context: "+err.Error())
	}
	if d == nil {
		return fallback(req, "no decider")
	}
	v = d(ctx, req)
	if !v.Decision.Valid() {
		return fallback(req, "invalid verdict")
	}
	return v
}

// applyContext merges the file, then the flags, into req.Context.
func applyContext(req *callguard.Request, opt Options) error {
	if opt.ContextFile != "" {
		f, err := os.Open(opt.ContextFile)
		if err != nil {
			return err
		}
		defer f.Close()
		b, err := io.ReadAll(io.LimitReader(f, maxContextFile+1))
		if err != nil {
			return err
		}
		if len(b) > maxContextFile {
			return fmt.Errorf("%s is larger than %d bytes", opt.ContextFile, maxContextFile)
		}
		var m map[string]string
		if err := json.Unmarshal(b, &m); err != nil {
			return fmt.Errorf("%s: %w", opt.ContextFile, err)
		}
		mergeContext(req, m)
	}
	mergeContext(req, opt.Context)
	return nil
}

func mergeContext(req *callguard.Request, m map[string]string) {
	if len(m) == 0 {
		return
	}
	if req.Context == nil {
		req.Context = make(map[string]string, len(m))
	}
	for k, v := range m {
		req.Context[k] = v
	}
}

// newRequest returns a request with the schema fields set.
func newRequest(harness string) *callguard.Request {
	return &callguard.Request{Schema: callguard.RequestSchema, V: 1, Harness: harness}
}

// label renders " [layer/rule]".
func label(v callguard.Verdict) string {
	switch {
	case v.Layer == "" && v.Rule == "":
		return ""
	case v.Rule == "":
		return " [" + v.Layer + "]"
	default:
		return " [" + v.Layer + "/" + v.Rule + "]"
	}
}

const denyAdvice = " Do not try to work around this block; if the action is needed, ask the user to run or approve it."

func askMessage(v callguard.Verdict) string { return "callguard: " + v.Reason + label(v) }
func denyMessage(v callguard.Verdict) string {
	return "callguard: " + v.Reason + label(v) + "." + denyAdvice
}
