package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"

	"github.com/lhns/callguard"
	"github.com/lhns/callguard/internal/hook"
)

const hookUsage = `usage: callguard hook claude|hermes|generic [flags]

Flags:
  --policy PATH         system policy file (default: the platform default)
  --no-user-policy      do not read the user policy layer
  --log PATH            decision log path ("-" disables logging)
  --unattended          nobody can answer a prompt: ask becomes deny
  --context KEY=VALUE   request context entry (repeatable)
  --context-file PATH   JSON object of strings merged into the context;
                        must be root-owned, the agent must not be able to write it
  --allow-in-auto       claude only: also emit allow in permission_mode auto
`

type kvFlags map[string]string

func (k kvFlags) String() string { return fmt.Sprint(map[string]string(k)) }
func (k kvFlags) Set(s string) error {
	key, val, ok := strings.Cut(s, "=")
	if !ok || key == "" {
		return errors.New("want KEY=VALUE")
	}
	k[key] = val
	return nil
}

// cmdHook runs a hook adapter. A misconfigured hook must still block, so
// every usage error exits 2: Claude and Hermes treat exit 2 as a block and
// any other non-zero exit as "run the tool"; the plugins block on any
// non-zero exit.
func cmdHook(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, hookUsage)
		return 2
	}
	name := args[0]
	if name != "claude" && name != "hermes" && name != "generic" {
		fmt.Fprintf(stderr, "callguard hook: unknown harness %q; blocking the call\n\n%s", name, hookUsage)
		return 2
	}

	fs := flag.NewFlagSet("hook "+name, flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() { fmt.Fprint(stderr, hookUsage) }
	policyPath := fs.String("policy", "", "")
	noUser := fs.Bool("no-user-policy", false, "")
	logPath := fs.String("log", "", "")
	unattended := fs.Bool("unattended", false, "")
	ctxFlags := kvFlags{}
	fs.Var(ctxFlags, "context", "")
	ctxFile := fs.String("context-file", "", "")
	allowInAuto := fs.Bool("allow-in-auto", false, "")
	if err := fs.Parse(args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		fmt.Fprintln(stderr, "callguard hook: bad flags; blocking the call")
		return 2
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(stderr, "callguard hook: unexpected argument %q; blocking the call\n", fs.Arg(0))
		return 2
	}
	if *allowInAuto && name != "claude" {
		fmt.Fprintln(stderr, "callguard hook: --allow-in-auto applies to claude only; blocking the call")
		return 2
	}

	opt := hook.Options{
		Unattended:  *unattended,
		Context:     ctxFlags,
		ContextFile: *ctxFile,
		AllowInAuto: *allowInAuto,
	}
	d := engineDecider(*policyPath, *noUser, *logPath)
	switch name {
	case "claude":
		return hook.Claude(stdin, stdout, stderr, opt, d)
	case "hermes":
		return hook.Hermes(stdin, stdout, stderr, opt, d)
	default:
		return hook.Generic(stdin, stdout, stderr, opt, d)
	}
}

// engineDecider builds the engine per request, because the project policy
// layer depends on the request's project directory.
func engineDecider(policyPath string, noUser bool, logPath string) hook.Decider {
	return func(ctx context.Context, req *callguard.Request) callguard.Verdict {
		lo := callguard.LoadOptions{
			SystemPolicy: policyPath,
			ProjectDir:   callguard.ResolveProjectDir(req),
			Options:      callguard.Options{LogPath: logPath},
		}
		if noUser {
			lo.UserConfigDir = "-"
		}
		eng, err := callguard.Load(lo)
		if err != nil {
			return callguard.FallbackVerdict(req, "policy: "+err.Error())
		}
		return eng.Decide(ctx, req)
	}
}
