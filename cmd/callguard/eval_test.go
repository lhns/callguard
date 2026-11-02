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
