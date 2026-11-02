package evals

import (
	"testing"

	"github.com/lhns/callguard/internal/evalrun"
)

func TestEmbeddedCases(t *testing.T) {
	cases, err := evalrun.ParseCases(Cases)
	if err != nil {
		t.Fatal(err)
	}
	if len(cases) < 40 {
		t.Errorf("only %d cases", len(cases))
	}
	known := map[string]bool{}
	for _, b := range evalrun.Buckets {
		known[b] = true
	}
	ids := map[string]bool{}
	perBucket := map[string]int{}
	for _, c := range cases {
		if c.ID == "" || ids[c.ID] {
			t.Errorf("missing or duplicate id %q", c.ID)
		}
		ids[c.ID] = true
		if !known[c.Bucket] {
			t.Errorf("%s: unknown bucket %q", c.ID, c.Bucket)
		}
		perBucket[c.Bucket]++
		if !c.Expected.Valid() {
			t.Errorf("%s: bad expected %q", c.ID, c.Expected)
		}
		if c.Request.Tool.Name == "" {
			t.Errorf("%s: no tool name", c.ID)
		}
		if c.Bucket == "tainted" && c.Request.Context["trust"] != "tainted" {
			t.Errorf("%s: tainted bucket without context.trust", c.ID)
		}
		if c.Bucket == "injection" && c.Expected == "allow" {
			t.Errorf("%s: injection case expects allow", c.ID)
		}
	}
	for _, b := range evalrun.Buckets {
		if perBucket[b] < 7 {
			t.Errorf("bucket %s has %d cases, want at least 7", b, perBucket[b])
		}
	}
}
