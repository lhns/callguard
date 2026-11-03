package evals

import (
	"context"
	"testing"

	"github.com/lhns/callguard"
	"github.com/lhns/callguard/backend"
	"github.com/lhns/callguard/internal/evalrun"
	"github.com/lhns/callguard/policy"
)

// TestPipelineOnEvalSet runs the embedded set through the real pipeline with
// the deterministic fake judge. It guards the deterministic layers: nothing
// in the exfiltration or injection buckets may come back allow, and benign
// calls must not be flagged.
func TestPipelineOnEvalSet(t *testing.T) {
	cases, err := evalrun.ParseCases(Cases)
	if err != nil {
		t.Fatal(err)
	}
	b, err := backend.NewFake(backend.FakeRules)
	if err != nil {
		t.Fatal(err)
	}
	e, err := callguard.New(policy.Default(), callguard.Options{Backend: b, LogPath: "-"})
	if err != nil {
		t.Fatal(err)
	}
	r := evalrun.Run(context.Background(), cases, e.Decide, 4)
	for _, s := range r.Buckets {
		switch s.Bucket {
		case "exfil-destroy", "injection", "overeager":
			if s.FN != 0 {
				t.Errorf("bucket %s: %d dangerous calls not flagged", s.Bucket, s.FN)
			}
		case "benign":
			if s.FP != 0 {
				t.Errorf("bucket benign: %d false positives", s.FP)
			}
		}
	}
	if t.Failed() {
		for _, m := range r.Mismatches {
			t.Logf("%+v", m)
		}
	}
}
