package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/lhns/callguard"
	"github.com/lhns/callguard/backend"
	"github.com/lhns/callguard/evals"
	"github.com/lhns/callguard/internal/evalrun"
)

// cmdEval runs the labelled eval set through the full pipeline. Metrics are
// informational: it exits 0 when it ran, 1 on setup errors.
func cmdEval(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("eval", flag.ContinueOnError)
	fs.SetOutput(stderr)
	casesPath := fs.String("cases", "", "cases JSONL file (default: the embedded set)")
	policyPath := fs.String("policy", "", "system policy file")
	backendName := fs.String("backend", "", "backend name from the policy's backends, or fake / fake:<mode>")
	bucket := fs.String("bucket", "", "run only this bucket")
	concurrency := fs.Int("concurrency", 4, "parallel decisions")
	asJSON := fs.Bool("json", false, "print the report as JSON")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 64
	}
	fail := func(format string, a ...any) int {
		fmt.Fprintf(stderr, "callguard eval: "+format+"\n", a...)
		return 1
	}

	data := evals.Cases
	if *casesPath != "" {
		var err error
		if data, err = os.ReadFile(*casesPath); err != nil {
			return fail("%v", err)
		}
	}
	cases, err := evalrun.ParseCases(data)
	if err != nil {
		return fail("cases: %v", err)
	}
	if *bucket != "" {
		kept := cases[:0:0]
		for _, c := range cases {
			if c.Bucket == *bucket {
				kept = append(kept, c)
			}
		}
		if len(kept) == 0 {
			return fail("no cases in bucket %q", *bucket)
		}
		cases = kept
	}

	opts := callguard.LoadOptions{
		SystemPolicy:  *policyPath,
		UserConfigDir: "-",
		Options:       callguard.Options{LogPath: "-"},
	}
	if *backendName != "" {
		b, err := chooseBackend(*backendName, opts)
		if err != nil {
			return fail("%v", err)
		}
		opts.Backend = b
	}
	eng, err := callguard.Load(opts)
	if err != nil {
		return fail("loading policy: %v", err)
	}

	rep := evalrun.Run(context.Background(), cases, func(ctx context.Context, r *callguard.Request) callguard.Verdict {
		return eng.Decide(ctx, r)
	}, *concurrency)
	if *asJSON {
		if err := rep.WriteJSON(stdout); err != nil {
			return fail("%v", err)
		}
		return 0
	}
	if opts.Backend != nil {
		fmt.Fprintf(stdout, "backend: %s\n\n", opts.Backend.Name())
	}
	rep.WriteText(stdout)
	return 0
}

// chooseBackend resolves --backend: fake / fake:<mode> need no policy entry,
// any other name is looked up in the policy's backends.
func chooseBackend(name string, opts callguard.LoadOptions) (backend.Backend, error) {
	if name == "fake" || strings.HasPrefix(name, "fake:") {
		return backend.NewFake(strings.TrimPrefix(strings.TrimPrefix(name, "fake"), ":"))
	}
	probe, err := callguard.Load(opts) // no backend override: only to read the policy
	if err != nil {
		return nil, fmt.Errorf("loading policy: %w", err)
	}
	cfg, ok := probe.Policy().Backends[name]
	if !ok {
		return nil, fmt.Errorf("backend %q is not defined in the policy's backends", name)
	}
	return backend.FromConfig(cfg)
}
