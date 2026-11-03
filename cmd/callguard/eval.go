package main

import (
	"context"
	"encoding/json"
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
	"github.com/lhns/callguard/policy"
)

// cmdEval runs the labelled eval set through the full pipeline. Metrics are
// informational: it exits 0 when it ran, 1 on setup errors.
func cmdEval(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("eval", flag.ContinueOnError)
	fs.SetOutput(stderr)
	casesPath := fs.String("cases", "", "cases JSONL file (default: the embedded set)")
	policyPath := fs.String("policy", "", "system policy file")
	backendName := fs.String("backend", "", "backend name from the policy's backends, or fake / fake:<mode> / anthropic / anthropic:<model>")
	bucket := fs.String("bucket", "", "run only this bucket")
	concurrency := fs.Int("concurrency", 4, "parallel decisions")
	asJSON := fs.Bool("json", false, "print the report as JSON")
	facts := fs.String("facts", "on", "show the judge nah facts: on, off or both (runs the set twice and compares)")
	maxUSD := fs.Float64("max-usd", 1.0, "stop at 90% of this estimated spend in USD (0 = no cap)")
	llmTimeout := fs.Int("llm-timeout-ms", 0, "override the policy's llm.timeout_ms (the eval measures judgement, not latency)")
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
	if *facts != "on" && *facts != "off" && *facts != "both" {
		fmt.Fprintf(stderr, "callguard eval: --facts must be on, off or both, not %q\n", *facts)
		return 64
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
		// The eval never probes git or gh: cases carry the meta they need.
		Options: callguard.Options{LogPath: "-", NoHostMeta: true, LLMTimeoutMS: *llmTimeout},
	}
	b, keyEnv, err := chooseBackend(*backendName, opts)
	if err != nil {
		return fail("%v", err)
	}
	if keyEnv != "" && os.Getenv(keyEnv) == "" {
		return fail("%s is not set; the eval needs it for the anthropic backend", keyEnv)
	}

	// run decides the set once. A fresh meter per run keeps the usage apart;
	// the cap is what is left of --max-usd.
	run := func(withFacts bool, capUSD float64) (evalrun.Report, error) {
		o := opts
		o.OmitFacts = !withFacts
		var meter *evalrun.Meter
		var stop func() bool
		if b != nil {
			meter = evalrun.NewMeter(b, capUSD)
			o.Backend, stop = meter, meter.Stop
		}
		eng, err := callguard.Load(o)
		if err != nil {
			return evalrun.Report{}, fmt.Errorf("loading policy: %w", err)
		}
		rep := evalrun.Run(context.Background(), cases, func(ctx context.Context, r *callguard.Request) callguard.Verdict {
			return eng.Decide(ctx, r)
		}, *concurrency, stop)
		if meter != nil {
			u := meter.Usage(rep.LLMCases)
			rep.Usage = &u
		}
		return rep, nil
	}

	first, err := run(*facts != "off", *maxUSD)
	if err != nil {
		return fail("%v", err)
	}
	var second evalrun.Report
	if *facts == "both" {
		remaining := *maxUSD
		if remaining > 0 && first.Usage != nil {
			remaining = max(remaining-first.Usage.EstUSD, 1e-9) // never "no cap" by accident
		}
		if second, err = run(false, remaining); err != nil {
			return fail("%v", err)
		}
	}

	if *asJSON {
		var v any = first
		if *facts == "both" {
			v = map[string]evalrun.Report{"facts_on": first, "facts_off": second}
		}
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(v); err != nil {
			return fail("%v", err)
		}
		return 0
	}
	if b != nil {
		fmt.Fprintf(stdout, "backend: %s\n", b.Name())
	}
	if *facts == "both" {
		fmt.Fprint(stdout, "\n== facts on ==\n")
		first.WriteText(stdout)
		fmt.Fprint(stdout, "\n== facts off ==\n")
		second.WriteText(stdout)
		fmt.Fprint(stdout, "\n== comparison ==\n")
		evalrun.WriteComparison(stdout, "facts on", first, "facts off", second)
		return 0
	}
	fmt.Fprintln(stdout)
	first.WriteText(stdout)
	return 0
}

// chooseBackend resolves --backend: fake / fake:<mode> and anthropic /
// anthropic:<model> need no policy entry, any other name is looked up in the
// policy's backends. With no --backend it is the policy's llm backend, if that
// can be built (otherwise the engine reports the problem per case, as before).
// keyEnv is the API key variable an anthropic backend needs, "" otherwise.
func chooseBackend(name string, opts callguard.LoadOptions) (b backend.Backend, keyEnv string, err error) {
	if name == "fake" || strings.HasPrefix(name, "fake:") {
		b, err = backend.NewFake(strings.TrimPrefix(strings.TrimPrefix(name, "fake"), ":"))
		return b, "", err
	}
	probe, err := callguard.Load(opts) // no backend override: only to read the policy
	if err != nil {
		return nil, "", fmt.Errorf("loading policy: %w", err)
	}
	pol := probe.Policy()
	explicit := name != ""
	if !explicit {
		name = pol.LLM.Backend
	}
	var cfg policy.Backend
	model, isAnthropic := strings.CutPrefix(name, "anthropic:")
	switch c, found := pol.Backends[name]; {
	case isAnthropic || name == "anthropic":
		cfg = pol.Backends["anthropic"]
		cfg.Type = "anthropic"
		if model != "" {
			cfg.Model = model
		}
	case found:
		cfg = c
	case explicit:
		return nil, "", fmt.Errorf("backend %q is not defined in the policy's backends", name)
	default:
		return nil, "", nil
	}
	if b, err = backend.FromConfig(cfg); err != nil {
		if explicit {
			return nil, "", err
		}
		return nil, "", nil
	}
	if cfg.Type == "anthropic" {
		keyEnv = cfg.APIKeyEnv
		if keyEnv == "" {
			keyEnv = "ANTHROPIC_API_KEY"
		}
	}
	return b, keyEnv, nil
}
