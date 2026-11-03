package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestEvalSetupErrors(t *testing.T) {
	for name, args := range map[string][]string{
		"missing cases file": {"--cases", "does-not-exist.jsonl"},
		"unknown bucket":     {"--bucket", "no-such-bucket"},
		"unknown fake mode":  {"--backend", "fake:bogus"},
	} {
		var out, errb bytes.Buffer
		if code := cmdEval(args, &out, &errb); code != 1 || !strings.Contains(errb.String(), "callguard eval:") {
			t.Errorf("%s: code %d, stderr %q", name, code, errb.String())
		}
	}
	var out, errb bytes.Buffer
	if code := cmdEval([]string{"--no-such-flag"}, &out, &errb); code != 64 {
		t.Errorf("bad flag: code %d", code)
	}
}

func TestEvalAnthropicNeedsKey(t *testing.T) {
	t.Setenv("ANTHROPIC_API_KEY", "")
	for _, name := range []string{"anthropic", "anthropic:claude-haiku-5-5", ""} {
		var out, errb bytes.Buffer
		code := cmdEval([]string{"--backend", name, "--bucket", "benign"}, &out, &errb)
		if code != 1 || !strings.Contains(errb.String(), "ANTHROPIC_API_KEY is not set; the eval needs it for the anthropic backend") || out.Len() != 0 {
			t.Errorf("%q: code %d, stdout %q, stderr %q", name, code, out.String(), errb.String())
		}
	}
}

func TestEvalFactsModes(t *testing.T) {
	var out, errb bytes.Buffer
	if code := cmdEval([]string{"--facts", "maybe"}, &out, &errb); code != 64 {
		t.Errorf("bad --facts: code %d", code)
	}
	for _, mode := range []string{"on", "off", "both"} {
		out.Reset()
		errb.Reset()
		code := cmdEval([]string{"--backend", "fake", "--bucket", "benign", "--facts", mode}, &out, &errb)
		s := out.String()
		if code != 0 || !strings.Contains(s, "llm usage:") || strings.Contains(s, "== comparison ==") != (mode == "both") {
			t.Errorf("%s: code %d, stderr %q\n%s", mode, code, errb.String(), s)
		}
	}
	out.Reset()
	if code := cmdEval([]string{"--backend", "fake", "--bucket", "benign", "--facts", "both", "--json"}, &out, &errb); code != 0 ||
		!strings.Contains(out.String(), `"facts_on"`) || !strings.Contains(out.String(), `"facts_off"`) {
		t.Errorf("json both: code %d\n%s", code, out.String())
	}
}
