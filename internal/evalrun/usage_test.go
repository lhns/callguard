package evalrun

import (
	"context"
	"math"
	"testing"

	"github.com/lhns/callguard/backend"
)

type priced struct {
	name string
	res  backend.ClassifyResult
}

func (p *priced) Name() string          { return p.name }
func (p *priced) DataClasses() []string { return nil }
func (p *priced) Classify(context.Context, backend.ClassifyRequest) (backend.ClassifyResult, error) {
	return p.res, nil
}

func TestPriceOf(t *testing.T) {
	for name, want := range map[string]price{
		"anthropic:claude-haiku-5-5":  {0.10, 0.50},
		"anthropic:claude-sonnet-5":   {2, 10},
		"anthropic:claude-opus-4-1":   {5, 25},
		"anthropic:claude-fable-5-1":  {10, 50},
		"anthropic:claude-unheard-of": {10, 50},
		"anthropic:claude-sonnet-4-6": {3, 15},
	} {
		if p, ok := priceOf(name); !ok || p != want {
			t.Errorf("%s: %+v %v, want %+v", name, p, ok, want)
		}
	}
	if _, ok := priceOf("fake:rules"); ok {
		t.Error("fake backends are free")
	}
}

func TestMeterSumsAndStopsAtNinetyPercent(t *testing.T) {
	// claude-sonnet-5-5: $2 in, $10 out per MTok. One call: 1M input = $2,
	// 100k output = $1, 1M cache read = $0.2, 100k cache write = $0.25.
	b := &priced{name: "anthropic:claude-sonnet-5-5", res: backend.ClassifyResult{
		InputTokens: 1_000_000, OutputTokens: 100_000, CacheReadTokens: 1_000_000, CacheWriteTokens: 100_000}}
	m := NewMeter(b, 5)
	if _, err := m.Classify(context.Background(), backend.ClassifyRequest{}); err != nil {
		t.Fatal(err)
	}
	u := m.Usage(2)
	if u.LLMCalls != 1 || math.Abs(u.EstUSD-3.45) > 1e-9 || u.TokensPerCase != 1_100_000 || m.Stop() {
		t.Errorf("%+v stop %v", u, m.Stop())
	}
	if _, err := m.Classify(context.Background(), backend.ClassifyRequest{}); err != nil {
		t.Fatal(err)
	}
	if !m.Stop() { // 6.90 >= 4.50
		t.Error("no stop at 90% of the cap")
	}
	if _, err := m.Classify(context.Background(), backend.ClassifyRequest{}); err == nil {
		t.Error("a call after the cap must be refused")
	}
	if m.Usage(0).LLMCalls != 2 {
		t.Error("a refused call must not count")
	}
	free := NewMeter(&priced{name: "fake:rules", res: b.res}, 0.01)
	_, _ = free.Classify(context.Background(), backend.ClassifyRequest{})
	if free.Stop() || free.Usage(1).EstUSD != 0 {
		t.Error("non-anthropic backends cost nothing")
	}
}
