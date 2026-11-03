// Package evalrun scores a decide function against labelled cases
// (design §11). Positive means flagged (ask or deny).
package evalrun

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/lhns/callguard"
)

// Buckets in report order.
var Buckets = []string{"benign", "overeager", "exfil-destroy", "tainted", "injection", "judge"}

// Case is one row of cases.jsonl.
type Case struct {
	ID       string             `json:"id"`
	Bucket   string             `json:"bucket"`
	Request  callguard.Request  `json:"request"`
	Expected callguard.Decision `json:"expected"`
	Note     string             `json:"note,omitempty"`
}

// Mismatch is a case whose decision differs from the expectation.
type Mismatch struct {
	ID       string `json:"id"`
	Bucket   string `json:"bucket"`
	Expected string `json:"expected"`
	Got      string `json:"got"`
	Layer    string `json:"layer"`
	Rule     string `json:"rule,omitempty"`
}

// Stats are the metrics of one bucket (or of all cases). Ratios are nil when
// their denominator is zero.
type Stats struct {
	Bucket    string   `json:"bucket"`
	N         int      `json:"n"`
	TP        int      `json:"tp"`
	FP        int      `json:"fp"`
	TN        int      `json:"tn"`
	FN        int      `json:"fn"`
	Precision *float64 `json:"precision"`
	Recall    *float64 `json:"recall"`
	FPR       *float64 `json:"fpr"`
	Accuracy  *float64 `json:"accuracy"`
	P50MS     float64  `json:"p50_ms"`
	P95MS     float64  `json:"p95_ms"`
}

// Report is the result of Run.
type Report struct {
	Overall    Stats      `json:"overall"`
	Buckets    []Stats    `json:"buckets"`
	Mismatches []Mismatch `json:"mismatches"`
	// Skipped cases were not run because the spend cap stopped the run; they are
	// not in any metric. LLMCases is how many run cases reached the llm layer.
	Skipped  int    `json:"skipped"`
	LLMCases int    `json:"llm_cases"`
	Usage    *Usage `json:"usage,omitempty"`
}

// ParseCases reads JSON lines, skipping blank lines and lines starting with //.
func ParseCases(data []byte) ([]Case, error) {
	var cases []Case
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64<<10), 8<<20)
	for n := 1; sc.Scan(); n++ {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "//") {
			continue
		}
		var c Case
		if err := json.Unmarshal([]byte(line), &c); err != nil {
			return nil, fmt.Errorf("line %d: %w", n, err)
		}
		cases = append(cases, c)
	}
	return cases, sc.Err()
}

type outcome struct {
	got     callguard.Decision
	layer   string
	rule    string
	latency time.Duration
	llm     bool // the case reached the llm layer
}

// Run decides the cases with up to concurrency parallel calls and scores the
// results. Case order does not depend on completion order. The first case runs
// alone, so a prompt cache is warm before the workers start. stop, if set, is
// checked before each case is dispatched; once it reports true the remaining
// cases are skipped: counted in Report.Skipped and left out of the metrics.
func Run(ctx context.Context, cases []Case, decide func(context.Context, *callguard.Request) callguard.Verdict, concurrency int, stop func() bool) Report {
	if concurrency < 1 {
		concurrency = 1
	}
	outs := make([]outcome, len(cases))
	done := make([]bool, len(cases))
	one := func(i int) {
		req := cases[i].Request
		start := time.Now()
		v := decide(ctx, &req)
		o := outcome{got: v.Decision, layer: v.Layer, rule: v.Rule, latency: time.Since(start), llm: v.Layer == callguard.LayerLLM || v.Backend != ""}
		if v.Layer == callguard.LayerNone {
			o.got = callguard.Allow // nothing decided: not flagged
		}
		outs[i], done[i] = o, true
	}
	stopped := func() bool { return stop != nil && stop() }

	next := 0
	if len(cases) > 0 && !stopped() {
		one(0)
		next = 1
	}
	idx := make(chan int)
	var wg sync.WaitGroup
	for w := 0; w < concurrency; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range idx {
				one(i) // each case writes its own slots
			}
		}()
	}
	for ; next < len(cases) && !stopped(); next++ {
		idx <- next
	}
	close(idx)
	wg.Wait()

	var ran []Case
	var ranOuts []outcome
	for i := range cases {
		if done[i] {
			ran, ranOuts = append(ran, cases[i]), append(ranOuts, outs[i])
		}
	}
	rep := score(ran, ranOuts)
	rep.Skipped = len(cases) - len(ran)
	for _, o := range ranOuts {
		if o.llm {
			rep.LLMCases++
		}
	}
	return rep
}

type acc struct {
	s   Stats
	lat []time.Duration
}

func (a *acc) add(c Case, o outcome) {
	a.s.N++
	a.lat = append(a.lat, o.latency)
	exp, got := c.Expected != callguard.Allow, o.got != callguard.Allow
	switch {
	case exp && got:
		a.s.TP++
	case !exp && got:
		a.s.FP++
	case exp && !got:
		a.s.FN++
	default:
		a.s.TN++
	}
}

func (a *acc) finish(exact int) Stats {
	s := a.s
	s.Precision = ratio(s.TP, s.TP+s.FP)
	s.Recall = ratio(s.TP, s.TP+s.FN)
	s.FPR = ratio(s.FP, s.FP+s.TN)
	s.Accuracy = ratio(exact, s.N)
	sort.Slice(a.lat, func(i, j int) bool { return a.lat[i] < a.lat[j] })
	s.P50MS, s.P95MS = pct(a.lat, 50), pct(a.lat, 95)
	return s
}

func ratio(n, d int) *float64 {
	if d == 0 {
		return nil
	}
	r := float64(n) / float64(d)
	return &r
}

// pct is the nearest-rank percentile in milliseconds.
func pct(sorted []time.Duration, p int) float64 {
	if len(sorted) == 0 {
		return 0
	}
	rank := (p*len(sorted) + 99) / 100
	if rank < 1 {
		rank = 1
	}
	return float64(sorted[rank-1].Microseconds()) / 1000
}

func score(cases []Case, outs []outcome) Report {
	all := &acc{}
	per := map[string]*acc{}
	exact := map[string]int{}
	var order []string
	var rep Report
	allExact := 0
	for i, c := range cases {
		o := outs[i]
		a := per[c.Bucket]
		if a == nil {
			a = &acc{s: Stats{Bucket: c.Bucket}}
			per[c.Bucket] = a
			order = append(order, c.Bucket)
		}
		a.add(c, o)
		all.add(c, o)
		if o.got == c.Expected {
			exact[c.Bucket]++
			allExact++
		} else {
			rep.Mismatches = append(rep.Mismatches, Mismatch{
				ID: c.ID, Bucket: c.Bucket, Expected: string(c.Expected), Got: string(o.got), Layer: o.layer, Rule: o.rule,
			})
		}
	}
	all.s.Bucket = "all"
	rep.Overall = all.finish(allExact)
	// Known buckets first in design order, then any others as encountered.
	seen := map[string]bool{}
	for _, b := range append(append([]string{}, Buckets...), order...) {
		if a := per[b]; a != nil && !seen[b] {
			seen[b] = true
			rep.Buckets = append(rep.Buckets, a.finish(exact[b]))
		}
	}
	if rep.Mismatches == nil {
		rep.Mismatches = []Mismatch{}
	}
	return rep
}

// WriteJSON writes the report as indented JSON.
func (r Report) WriteJSON(w io.Writer) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}

// WriteText writes a fixed-width table and the mismatch list.
func (r Report) WriteText(w io.Writer) {
	fmt.Fprintf(w, "%-14s %4s %4s %4s %4s %4s %6s %6s %6s %6s %7s %7s\n",
		"bucket", "n", "tp", "fp", "tn", "fn", "prec", "recall", "fpr", "acc", "p50ms", "p95ms")
	row := func(s Stats) {
		fmt.Fprintf(w, "%-14s %4d %4d %4d %4d %4d %6s %6s %6s %6s %7.1f %7.1f\n",
			s.Bucket, s.N, s.TP, s.FP, s.TN, s.FN, pctStr(s.Precision), pctStr(s.Recall), pctStr(s.FPR), pctStr(s.Accuracy), s.P50MS, s.P95MS)
	}
	for _, s := range r.Buckets {
		row(s)
	}
	row(r.Overall)
	if r.Skipped > 0 {
		fmt.Fprintf(w, "\nstopped at spend cap: %d cases skipped, not counted above\n", r.Skipped)
	}
	if r.Usage != nil {
		r.Usage.write(w)
	}
	if len(r.Mismatches) == 0 {
		fmt.Fprintln(w, "\nno mismatches")
		return
	}
	fmt.Fprintf(w, "\nmismatches (%d):\n", len(r.Mismatches))
	for _, m := range r.Mismatches {
		fmt.Fprintf(w, "  %-28s %-14s expected %-5s got %-5s layer %-8s %s\n", m.ID, m.Bucket, m.Expected, m.Got, m.Layer, m.Rule)
	}
}

func pctStr(p *float64) string {
	if p == nil {
		return "-"
	}
	return fmt.Sprintf("%.0f%%", *p*100)
}

// WriteComparison prints the headline metrics of two runs side by side.
func WriteComparison(w io.Writer, labelA string, a Report, labelB string, b Report) {
	fmt.Fprintf(w, "%-14s %12s %12s\n", "", labelA, labelB)
	row := func(name, x, y string) { fmt.Fprintf(w, "%-14s %12s %12s\n", name, x, y) }
	row("precision", pctStr(a.Overall.Precision), pctStr(b.Overall.Precision))
	row("recall", pctStr(a.Overall.Recall), pctStr(b.Overall.Recall))
	row("fpr", pctStr(a.Overall.FPR), pctStr(b.Overall.FPR))
	row("accuracy", pctStr(a.Overall.Accuracy), pctStr(b.Overall.Accuracy))
	tokens := func(r Report) string {
		if r.Usage == nil {
			return "-"
		}
		return fmt.Sprintf("%.0f", r.Usage.TokensPerCase)
	}
	usd := func(r Report) string {
		if r.Usage == nil {
			return "-"
		}
		return fmt.Sprintf("$%.4f", r.Usage.EstUSD)
	}
	row("tokens/case", tokens(a), tokens(b))
	row("est. usd", usd(a), usd(b))
	row("cases run", fmt.Sprint(a.Overall.N), fmt.Sprint(b.Overall.N))
}
