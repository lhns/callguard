package evalrun

import (
	"context"
	"fmt"
	"io"
	"strings"
	"sync"

	"github.com/lhns/callguard/backend"
)

// Usage is what an eval run spent on the LLM backend.
type Usage struct {
	LLMCalls         int     `json:"llm_calls"`
	InputTokens      int     `json:"input_tokens"`
	OutputTokens     int     `json:"output_tokens"`
	CacheReadTokens  int     `json:"cache_read_tokens"`
	CacheWriteTokens int     `json:"cache_write_tokens"`
	TokensPerCase    float64 `json:"tokens_per_case"` // input incl. cache, plus output, per case that reached the llm
	EstUSD           float64 `json:"est_usd"`
}

// SpendStopFraction is the share of the spend cap at which the Meter stops
// taking new calls and the run stops dispatching cases. The rest is headroom
// for calls already in flight.
const SpendStopFraction = 0.9

type price struct{ in, out float64 } // USD per million tokens

var exactPrices = map[string]price{
	"claude-haiku-5-5":  {0.10, 0.50},
	"claude-haiku-4-5":  {1, 5},
	"claude-sonnet-5-5": {2, 10},
	"claude-sonnet-5":   {2, 10},
	"claude-sonnet-4-6": {3, 15},
	"claude-opus-5-5":   {4, 20},
	"claude-opus-5":     {5, 25},
}

var prefixPrices = []struct {
	prefix string
	p      price
}{
	{"claude-opus-4-", price{5, 25}},
	{"claude-fable-5", price{10, 50}},
}

// unknownAnthropic is the price of an anthropic model not in the table: the
// highest, so the cap errs on the safe side.
var unknownAnthropic = price{10, 50}

// priceOf returns the model's price. ok is false for non-anthropic backends,
// which cost nothing here.
func priceOf(backendName string) (p price, ok bool) {
	model, found := strings.CutPrefix(backendName, "anthropic:")
	if !found {
		return price{}, false
	}
	if p, ok := exactPrices[model]; ok {
		return p, true
	}
	for _, pp := range prefixPrices {
		if strings.HasPrefix(model, pp.prefix) {
			return pp.p, true
		}
	}
	return unknownAnthropic, true
}

// Meter wraps a backend, sums its token use and estimates the cost. Once the
// estimate reaches 90% of the cap it refuses new calls (they fail, so the
// engine answers with its fallback) and Stop reports true.
type Meter struct {
	backend.Backend
	capUSD float64

	mu sync.Mutex
	u  Usage
}

// NewMeter wraps b. A cap <= 0 means no cap.
func NewMeter(b backend.Backend, capUSD float64) *Meter { return &Meter{Backend: b, capUSD: capUSD} }

// Stop reports whether the spend cap is reached.
func (m *Meter) Stop() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.stopped()
}

func (m *Meter) stopped() bool {
	return m.capUSD > 0 && m.u.EstUSD >= SpendStopFraction*m.capUSD
}

// Classify forwards to the wrapped backend and records the usage.
func (m *Meter) Classify(ctx context.Context, req backend.ClassifyRequest) (backend.ClassifyResult, error) {
	if m.Stop() {
		return backend.ClassifyResult{}, fmt.Errorf("eval spend cap of $%.2f reached", m.capUSD)
	}
	res, err := m.Backend.Classify(ctx, req)
	m.mu.Lock()
	defer m.mu.Unlock()
	m.u.LLMCalls++
	m.u.InputTokens += res.InputTokens
	m.u.OutputTokens += res.OutputTokens
	m.u.CacheReadTokens += res.CacheReadTokens
	m.u.CacheWriteTokens += res.CacheWriteTokens
	if p, ok := priceOf(m.Name()); ok {
		m.u.EstUSD += (float64(res.InputTokens)*p.in + float64(res.OutputTokens)*p.out +
			float64(res.CacheWriteTokens)*1.25*p.in + float64(res.CacheReadTokens)*0.1*p.in) / 1e6
	}
	return res, err
}

// Usage returns the totals so far. llmCases is the number of cases that
// reached the llm layer, the divisor of TokensPerCase.
func (m *Meter) Usage(llmCases int) Usage {
	m.mu.Lock()
	defer m.mu.Unlock()
	u := m.u
	if llmCases > 0 {
		u.TokensPerCase = float64(u.InputTokens+u.CacheReadTokens+u.CacheWriteTokens+u.OutputTokens) / float64(llmCases)
	}
	return u
}

func (u Usage) write(w io.Writer) {
	fmt.Fprintf(w, "\nllm usage: %d calls, input %d, output %d, cache read %d, cache write %d, %.0f tokens/case, est. $%.4f\n",
		u.LLMCalls, u.InputTokens, u.OutputTokens, u.CacheReadTokens, u.CacheWriteTokens, u.TokensPerCase, u.EstUSD)
}
