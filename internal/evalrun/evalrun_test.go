package evalrun

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lhns/callguard"
)

func mkCase(id, bucket string, exp callguard.Decision) Case {
	return Case{ID: id, Bucket: bucket, Expected: exp, Request: callguard.Request{Tool: callguard.ToolCall{Name: id}}}
}

func TestRunScoresBuckets(t *testing.T) {
	cases := []Case{
		mkCase("b1", "benign", callguard.Allow),
		mkCase("b2", "benign", callguard.Allow),
		mkCase("o1", "overeager", callguard.Ask),
		mkCase("o2", "overeager", callguard.Ask),
		mkCase("e1", "exfil-destroy", callguard.Deny),
	}
	got := map[string]callguard.Verdict{
		"b1": {Decision: callguard.Allow, Layer: callguard.LayerRules},                  // TN, exact
		"b2": {Decision: callguard.Ask, Layer: callguard.LayerLLM, Rule: "x"},           // FP
		"o1": {Decision: callguard.Deny, Layer: callguard.LayerBuiltin, Rule: "r1"},     // TP, not exact
		"o2": {Decision: callguard.Ask, Layer: callguard.LayerNone},                     // layer none: FN
		"e1": {Decision: callguard.Deny, Layer: callguard.LayerBuiltin, Enforced: true}, // TP, exact
	}
	rep := Run(context.Background(), cases, func(_ context.Context, r *callguard.Request) callguard.Verdict {
		time.Sleep(time.Millisecond)
		return got[r.Tool.Name]
	}, 3, nil)

	o := rep.Overall
	if o.N != 5 || o.TP != 2 || o.FP != 1 || o.TN != 1 || o.FN != 1 {
		t.Fatalf("overall %+v", o)
	}
	approx := func(name string, p *float64, want float64) {
		t.Helper()
		if p == nil || *p < want-1e-9 || *p > want+1e-9 {
			t.Errorf("%s = %v, want %v", name, p, want)
		}
	}
	approx("precision", o.Precision, 2.0/3)
	approx("recall", o.Recall, 2.0/3)
	approx("fpr", o.FPR, 0.5)
	approx("accuracy", o.Accuracy, 2.0/5)
	if o.P50MS <= 0 || o.P95MS < o.P50MS {
		t.Errorf("latency %v %v", o.P50MS, o.P95MS)
	}
	if len(rep.Buckets) != 3 || rep.Buckets[0].Bucket != "benign" || rep.Buckets[1].Bucket != "overeager" || rep.Buckets[2].Bucket != "exfil-destroy" {
		t.Fatalf("buckets %+v", rep.Buckets)
	}
	if b := rep.Buckets[0]; b.FP != 1 || b.TN != 1 || b.Recall != nil || b.Precision == nil || *b.Precision != 0 {
		t.Errorf("benign %+v", b)
	}
	if len(rep.Mismatches) != 3 {
		t.Fatalf("mismatches %+v", rep.Mismatches)
	}
	ids := map[string]Mismatch{}
	for _, m := range rep.Mismatches {
		ids[m.ID] = m
	}
	if m := ids["o2"]; m.Got != "allow" || m.Layer != "none" {
		t.Errorf("layer none mismatch %+v", m)
	}
	if m := ids["o1"]; m.Got != "deny" || m.Expected != "ask" || m.Rule != "r1" {
		t.Errorf("o1 %+v", m)
	}

	var txt bytes.Buffer
	rep.WriteText(&txt)
	if !strings.Contains(txt.String(), "mismatches (3)") || !strings.Contains(txt.String(), "overeager") {
		t.Errorf("text:\n%s", txt.String())
	}
	var js bytes.Buffer
	if err := rep.WriteJSON(&js); err != nil {
		t.Fatal(err)
	}
	var back Report
	if err := json.Unmarshal(js.Bytes(), &back); err != nil || back.Overall.N != 5 {
		t.Errorf("json round trip: %v", err)
	}
}

func TestRunEmptyAndParse(t *testing.T) {
	rep := Run(context.Background(), nil, nil, 0, nil)
	if rep.Overall.N != 0 || rep.Overall.Accuracy != nil || len(rep.Mismatches) != 0 {
		t.Errorf("%+v", rep)
	}
	row := `{"id":"a","bucket":"benign","request":{"tool":{"name":"Bash"}},"expected":"allow"}`
	cs, err := ParseCases([]byte("\n// c\n" + row + "\n"))
	if err != nil || len(cs) != 1 || cs[0].Request.Tool.Name != "Bash" {
		t.Errorf("%v %+v", err, cs)
	}
	if _, err := ParseCases([]byte("{bad")); err == nil || !strings.Contains(err.Error(), "line 1") {
		t.Errorf("err = %v", err)
	}
}

func TestRunStopsAndCountsSkipped(t *testing.T) {
	var cases []Case
	for _, id := range []string{"a", "b", "c", "d", "e"} {
		cases = append(cases, mkCase(id, "benign", callguard.Allow))
	}
	var ran atomic.Int32
	var first atomic.Bool
	decide := func(_ context.Context, r *callguard.Request) callguard.Verdict {
		if ran.Add(1) == 1 {
			first.Store(r.Tool.Name == "a") // the first case runs before any other starts
			time.Sleep(20 * time.Millisecond)
		} else if !first.Load() {
			t.Error("a worker started before the first case finished")
		}
		return callguard.Verdict{Decision: callguard.Allow, Layer: callguard.LayerLLM}
	}
	rep := Run(context.Background(), cases, decide, 4, func() bool { return ran.Load() >= 2 })
	if rep.Skipped == 0 || rep.Overall.N+rep.Skipped != 5 || int(ran.Load()) != rep.Overall.N || rep.LLMCases != rep.Overall.N {
		t.Errorf("skipped %d, n %d, ran %d, llm %d", rep.Skipped, rep.Overall.N, ran.Load(), rep.LLMCases)
	}
	var txt bytes.Buffer
	rep.Usage = &Usage{LLMCalls: 2, EstUSD: 0.5}
	rep.WriteText(&txt)
	if !strings.Contains(txt.String(), "stopped at spend cap") || !strings.Contains(txt.String(), "llm usage: 2 calls") {
		t.Errorf("text:\n%s", txt.String())
	}
}
