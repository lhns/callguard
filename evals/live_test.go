package evals

import (
	"bytes"
	"context"
	"os"
	"testing"

	"github.com/lhns/callguard"
	"github.com/lhns/callguard/backend"
	"github.com/lhns/callguard/internal/evalrun"
	"github.com/lhns/callguard/policy"
)

// TestLiveAnthropicEval runs the embedded set against the real Anthropic API,
// with and without nah facts, under a $1 spend cap. It only logs the reports:
// the metrics are informational. It skips without ANTHROPIC_API_KEY.
func TestLiveAnthropicEval(t *testing.T) {
	if os.Getenv("ANTHROPIC_API_KEY") == "" {
		t.Skip("ANTHROPIC_API_KEY is not set")
	}
	cases, err := evalrun.ParseCases(Cases)
	if err != nil {
		t.Fatal(err)
	}
	b, err := backend.FromConfig(policy.Default().Backends["anthropic"])
	if err != nil {
		t.Fatal(err)
	}
	reports := map[bool]evalrun.Report{}
	spent := 0.0
	for _, withFacts := range []bool{true, false} {
		m := evalrun.NewMeter(b, 1.0-spent)
		e, err := callguard.New(policy.Default(), callguard.Options{
			Backend: m, LogPath: "-", NoHostMeta: true, OmitFacts: !withFacts, LLMTimeoutMS: 20000,
		})
		if err != nil {
			t.Fatal(err)
		}
		rep := evalrun.Run(context.Background(), cases, e.Decide, 4, m.Stop)
		u := m.Usage(rep.LLMCases)
		rep.Usage = &u
		spent += u.EstUSD
		reports[withFacts] = rep
		var buf bytes.Buffer
		rep.WriteText(&buf)
		t.Logf("facts=%v\n%s", withFacts, buf.String())
	}
	var buf bytes.Buffer
	evalrun.WriteComparison(&buf, "facts on", reports[true], "facts off", reports[false])
	t.Logf("comparison\n%s", buf.String())
}
