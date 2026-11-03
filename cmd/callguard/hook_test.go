package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestPluginPrintsEmbeddedSource(t *testing.T) {
	for _, h := range []string{"opencode", "pi"} {
		var out, errOut bytes.Buffer
		if code := cmdPlugin([]string{h}, &out, &errOut); code != 0 || !strings.Contains(out.String(), "hook") {
			t.Fatalf("%s: code=%d out=%q", h, code, out.String())
		}
	}
	var out, errOut bytes.Buffer
	if code := cmdPlugin([]string{"vim"}, &out, &errOut); code != 64 || out.Len() != 0 {
		t.Fatalf("code=%d", code)
	}
	if code := cmdPlugin(nil, &out, &errOut); code != 64 {
		t.Fatalf("code=%d", code)
	}
}

func TestHookUsageErrors(t *testing.T) {
	run := func(args ...string) int {
		var out, errOut bytes.Buffer
		return cmdHook(args, strings.NewReader(""), &out, &errOut)
	}
	// Every usage error must block (exit 2), never exit 1 or 64, which Claude
	// and Hermes treat as "run the tool".
	if c := run(); c != 2 {
		t.Errorf("no harness: %d", c)
	}
	if c := run("claud"); c != 2 {
		t.Errorf("unknown harness: %d", c)
	}
	for _, h := range []string{"claude", "hermes", "generic"} {
		if c := run(h, "--bogus"); c != 2 {
			t.Errorf("%s bad flag: %d", h, c)
		}
		if c := run(h, "--context", "novalue"); c != 2 {
			t.Errorf("%s bad context: %d", h, c)
		}
		if c := run(h, "extra"); c != 2 {
			t.Errorf("%s extra argument: %d", h, c)
		}
	}
	if c := run("hermes", "--allow-in-auto"); c != 2 {
		t.Errorf("hermes --allow-in-auto: %d", c)
	}
}
