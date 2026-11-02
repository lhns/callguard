package hook

import (
	"context"
	"encoding/json"
	"fmt"
	"io"

	"github.com/lhns/callguard"
)

type genericInput struct {
	Harness    string            `json:"harness"`
	Tool       string            `json:"tool"`
	Input      json.RawMessage   `json:"input"`
	Cwd        string            `json:"cwd"`
	SessionID  string            `json:"session_id"`
	ProjectDir string            `json:"project_dir"`
	Context    map[string]string `json:"context"`
	Unattended bool              `json:"unattended"`
}

// lastResortJSON is written when even a verdict cannot be marshalled.
const lastResortJSON = `{"schema":"callguard/verdict/v1","v":1,"id":"","decision":"deny","enforced":true,` +
	`"reason":"callguard could not produce a verdict","layer":"fallback","confidence":1,"latency_ms":0}` + "\n"

// Generic runs the adapter for the opencode and pi plugins: request fields on
// stdin, a callguard verdict on stdout, exit 0 always. The plugins fail
// closed on anything else.
func Generic(in io.Reader, out, errOut io.Writer, opt Options, d Decider) int {
	defer func() {
		if r := recover(); r != nil {
			fmt.Fprintf(errOut, "callguard: internal error: %v\n", r)
			_, _ = io.WriteString(out, lastResortJSON)
		}
	}()

	req := newRequest("generic")
	req.Unattended = opt.Unattended
	var v callguard.Verdict
	var in0 genericInput

	body, err := readInput(in)
	if err == nil {
		err = json.Unmarshal(body, &in0)
	}
	switch {
	case err != nil:
		v = fallback(req, "bad hook input: "+err.Error())
	case in0.Tool == "":
		v = fallback(req, "bad hook input: missing tool")
	default:
		if in0.Harness != "" {
			req.Harness = in0.Harness
		}
		req.SessionID = in0.SessionID
		req.Cwd = in0.Cwd
		req.ProjectDir = in0.ProjectDir
		req.Tool = callguard.ToolCall{Name: in0.Tool, Input: in0.Input}
		req.Context = in0.Context
		req.Unattended = opt.Unattended || in0.Unattended
		v = decide(context.Background(), d, opt, req)
	}

	b, err := json.Marshal(v)
	if err != nil {
		_, _ = io.WriteString(out, lastResortJSON)
		return 0
	}
	b = append(b, '\n')
	if _, err := out.Write(b); err != nil {
		fmt.Fprintf(errOut, "callguard: could not write the verdict: %v\n", err)
	}
	return 0
}
