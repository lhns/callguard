package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"

	"github.com/lhns/callguard"
)

const maxRequestBytes = 4 << 20

// cmdDecide reads a request on stdin and prints the verdict. Exit codes:
// 0 allow, 1 deny, 2 ask, 3 bad request or policy error (a fallback verdict
// is still printed), 64 bad flags.
func cmdDecide(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("decide", flag.ContinueOnError)
	fs.SetOutput(stderr)
	policyFile := fs.String("policy", "", "system policy `file` (default: the platform path)")
	noUser := fs.Bool("no-user-policy", false, "skip the user policy layer")
	logPath := fs.String("log", "", "decision log `path`, or - to disable")
	unattended := fs.Bool("unattended", false, "no human can answer a prompt")
	if err := fs.Parse(args); err != nil {
		return 64
	}

	req := &callguard.Request{}
	fail := func(cause string) int {
		req.Unattended = req.Unattended || *unattended
		printJSON(stdout, callguard.FallbackVerdict(req, cause))
		return 3
	}
	data, err := io.ReadAll(io.LimitReader(stdin, maxRequestBytes+1))
	if err != nil {
		return fail("cannot read the request: " + err.Error())
	}
	if len(data) > maxRequestBytes {
		return fail(fmt.Sprintf("request is larger than %d bytes", maxRequestBytes))
	}
	if err := json.Unmarshal(data, req); err != nil {
		*req = callguard.Request{}
		return fail("bad request JSON: " + err.Error())
	}
	if *unattended {
		req.Unattended = true
	}
	if req.Tool.Name == "" {
		return fail("request has no tool.name")
	}

	lo := callguard.LoadOptions{SystemPolicy: *policyFile, ProjectDir: callguard.ResolveProjectDir(req)}
	lo.LogPath = *logPath
	if *noUser {
		lo.UserConfigDir = "-"
	}
	eng, err := callguard.Load(lo)
	if err != nil {
		return fail("policy: " + err.Error())
	}
	v := eng.Decide(context.Background(), req)
	printJSON(stdout, v)
	switch v.Decision {
	case callguard.Allow:
		return 0
	case callguard.Deny:
		return 1
	}
	return 2
}

func printJSON(w io.Writer, v any) {
	b, _ := json.Marshal(v)
	fmt.Fprintf(w, "%s\n", b)
}
