// Package nahlayer runs the optional nah guard as a subprocess (ADR 0004).
package nahlayer

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"time"
)

// Schema is nah's output schema.
const Schema = "nah/decide/v1"

// Verdict values.
const (
	Block    = "block"
	Delegate = "delegate"
)

// Result is a parsed nah answer.
type Result struct {
	Verdict  string // Block or Delegate
	Reason   string
	Rule     string // first policy attribution name, "" if none
	Coverage string // how much of the call nah could parse ("full", "partial"), "" if unreported
}

type output struct {
	Schema       string          `json:"schema"`
	Verdict      string          `json:"verdict"`
	Reason       string          `json:"reason"`
	Coverage     json.RawMessage `json:"coverage"`
	Attributions []struct {
		Kind string `json:"kind"`
		Name string `json:"name"`
	} `json:"policy_attributions"`
}

// Run executes `<argv...> decide` with the call on stdin. argv is the command
// prefix (normally just the nah path); tests pass a re-exec of the test binary.
// Any failure (missing binary, timeout, exit code 3 or 4, bad output) is an error.
func Run(ctx context.Context, argv []string, timeout time.Duration, tool string, input json.RawMessage, cwd string) (Result, error) {
	if len(argv) == 0 {
		return Result{}, errors.New("nah: no command")
	}
	if len(input) == 0 {
		input = json.RawMessage("{}")
	}
	stdin, err := json.Marshal(struct {
		V     int             `json:"v"`
		Tool  string          `json:"tool"`
		Input json.RawMessage `json:"input"`
		Cwd   string          `json:"cwd"`
	}{1, tool, input, cwd})
	if err != nil {
		return Result{}, fmt.Errorf("nah: encode request: %w", err)
	}
	if timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}
	cmd := exec.CommandContext(ctx, argv[0], append(append([]string(nil), argv[1:]...), "decide")...)
	cmd.Stdin = bytes.NewReader(stdin)
	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	cmd.WaitDelay = 500 * time.Millisecond
	runErr := cmd.Run()
	if ctx.Err() != nil {
		return Result{}, fmt.Errorf("nah: %w", ctx.Err())
	}
	code := 0
	if runErr != nil {
		var ee *exec.ExitError
		if !errors.As(runErr, &ee) {
			return Result{}, fmt.Errorf("nah: %w", runErr)
		}
		code = ee.ExitCode()
	}
	if code > 2 || code < 0 {
		return Result{}, fmt.Errorf("nah: exit code %d", code)
	}
	var out output
	if err := json.Unmarshal(stdout.Bytes(), &out); err != nil {
		return Result{}, fmt.Errorf("nah: unparseable output: %w", err)
	}
	if out.Schema != Schema {
		return Result{}, fmt.Errorf("nah: unexpected schema %q", out.Schema)
	}
	if out.Verdict != Block && out.Verdict != Delegate {
		return Result{}, fmt.Errorf("nah: unknown verdict %q", out.Verdict)
	}
	if (code == 1 && out.Verdict != Block) || (code == 2 && out.Verdict != Delegate) {
		return Result{}, fmt.Errorf("nah: exit code %d contradicts verdict %q", code, out.Verdict)
	}
	res := Result{Verdict: out.Verdict, Reason: out.Reason}
	_ = json.Unmarshal(out.Coverage, &res.Coverage) // anything but a string is ignored
	if len(out.Attributions) > 0 {
		res.Rule = out.Attributions[0].Name
	}
	return res, nil
}
