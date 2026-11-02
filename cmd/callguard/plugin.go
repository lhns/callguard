package main

import (
	"fmt"
	"io"

	"github.com/lhns/callguard/adapters"
)

const pluginUsage = `usage: callguard plugin opencode|pi

Prints the plugin source. Install with:
  callguard plugin opencode > ~/.config/opencode/plugins/callguard.js
  callguard plugin pi > ~/.pi/agent/extensions/callguard/index.js
`

func cmdPlugin(args []string, stdout, stderr io.Writer) int {
	if len(args) != 1 {
		fmt.Fprint(stderr, pluginUsage)
		return 64
	}
	switch args[0] {
	case "opencode":
		fmt.Fprint(stdout, adapters.OpenCode())
	case "pi":
		fmt.Fprint(stdout, adapters.Pi())
	default:
		fmt.Fprintf(stderr, "callguard plugin: unknown harness %q\n\n%s", args[0], pluginUsage)
		return 64
	}
	return 0
}
