// Command callguard decides coding-agent tool calls. See README.md.
package main

import (
	"fmt"
	"io"
	"os"
)

// version is set with -ldflags "-X main.version=...".
var version = "dev"

const usage = `callguard - allow, ask or deny a coding-agent tool call

Usage:
  callguard decide [flags]          request JSON on stdin, verdict JSON on stdout
  callguard hook <harness> [flags]  harness hook: claude, hermes, generic (opencode, pi plugins)
  callguard plugin <harness>        print the opencode or pi plugin source
  callguard policy check [flags]    load, merge and lint the policy layers
  callguard eval [flags]            run the labelled eval set
  callguard version

Run "callguard <command> -h" for flags.
`

func main() {
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return 64
	}
	switch args[0] {
	case "decide":
		return cmdDecide(args[1:], stdin, stdout, stderr)
	case "hook":
		return cmdHook(args[1:], stdin, stdout, stderr)
	case "plugin":
		return cmdPlugin(args[1:], stdout, stderr)
	case "policy":
		return cmdPolicy(args[1:], stdout, stderr)
	case "eval":
		return cmdEval(args[1:], stdout, stderr)
	case "version", "--version":
		fmt.Fprintln(stdout, "callguard", version)
		return 0
	case "help", "-h", "--help":
		fmt.Fprint(stdout, usage)
		return 0
	default:
		fmt.Fprintf(stderr, "callguard: unknown command %q\n\n%s", args[0], usage)
		return 64
	}
}
