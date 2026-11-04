//! Scores a decide function against labelled cases (design section 11).
//! Positive means flagged (ask or deny).

use std::io::{self, Write};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize, Serializer};

use crate::backend::{Backend, BackendError, ClassifyRequest, ClassifyResult};
use crate::policy::go_float_raw;
use crate::schema::{Decision, LAYER_LLM, LAYER_NONE, Request, Verdict};
use crate::serde_util::nullable;

/// Buckets in report order.
pub const BUCKETS: [&str; 6] = [
    "benign",
    "overeager",
    "exfil-destroy",
    "tainted",
    "injection",
    "judge",
];

/// One row of cases.jsonl.
#[derive(Debug, Clone, Deserialize)]
pub struct Case {
    #[serde(default, deserialize_with = "nullable")]
    pub id: String,
    #[serde(default, deserialize_with = "nullable")]
    pub bucket: String,
    #[serde(default, deserialize_with = "nullable")]
    pub request: Request,
    pub expected: Decision,
    #[serde(default, deserialize_with = "nullable")]
    pub note: String,
}

/// A case whose decision differs from the expectation.
#[derive(Debug, Clone, Serialize)]
pub struct Mismatch {
    pub id: String,
    pub bucket: String,
    pub expected: String,
    pub got: String,
    pub layer: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub rule: String,
}

fn num<S: Serializer>(v: &f64, s: S) -> Result<S::Ok, S::Error> {
    go_float_raw(*v, s)
}

fn opt_num<S: Serializer>(v: &Option<f64>, s: S) -> Result<S::Ok, S::Error> {
    match v {
        Some(f) => go_float_raw(*f, s),
        None => s.serialize_none(),
    }
}

/// The metrics of one bucket (or of all cases). Ratios are `None` (JSON null)
/// when their denominator is zero.
#[derive(Debug, Clone, Default, Serialize)]
pub struct Stats {
    pub bucket: String,
    pub n: i64,
    pub tp: i64,
    pub fp: i64,
    pub tn: i64,
    #[serde(rename = "fn")]
    pub fn_: i64,
    #[serde(serialize_with = "opt_num")]
    pub precision: Option<f64>,
    #[serde(serialize_with = "opt_num")]
    pub recall: Option<f64>,
    #[serde(serialize_with = "opt_num")]
    pub fpr: Option<f64>,
    #[serde(serialize_with = "opt_num")]
    pub accuracy: Option<f64>,
    #[serde(serialize_with = "num")]
    pub p50_ms: f64,
    #[serde(serialize_with = "num")]
    pub p95_ms: f64,
}

/// The result of [`run`]. `skipped` cases were not run because the spend cap
/// stopped the run; they are in no metric. `llm_cases` is how many run cases
/// reached the llm layer.
#[derive(Debug, Clone, Default, Serialize)]
pub struct Report {
    pub overall: Stats,
    pub buckets: Vec<Stats>,
    pub mismatches: Vec<Mismatch>,
    pub skipped: i64,
    pub llm_cases: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub usage: Option<Usage>,
}

/// What an eval run spent on the LLM backend.
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct Usage {
    pub llm_calls: i64,
    pub input_tokens: i64,
    pub output_tokens: i64,
    pub cache_read_tokens: i64,
    pub cache_write_tokens: i64,
    /// Input incl. cache, plus output, per case that reached the llm.
    #[serde(serialize_with = "num")]
    pub tokens_per_case: f64,
    #[serde(serialize_with = "num")]
    pub est_usd: f64,
}

/// A bad cases file.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct EvalError(pub String);

/// The share of the spend cap at which the [`Meter`] stops taking new calls
/// and the run stops dispatching cases. The rest is headroom for calls
/// already in flight.
pub const SPEND_STOP_FRACTION: f64 = 0.9;

/// Reads JSON lines, skipping blank lines and lines starting with `//`. The
/// error names the line.
pub fn parse_cases(data: &[u8]) -> Result<Vec<Case>, EvalError> {
    let mut cases = Vec::new();
    for (i, line) in data.split(|&b| b == b'\n').enumerate() {
        let line = String::from_utf8_lossy(line);
        let line = line.trim();
        if line.is_empty() || line.starts_with("//") {
            continue;
        }
        let case: Case =
            serde_json::from_str(line).map_err(|e| EvalError(format!("line {}: {e}", i + 1)))?;
        cases.push(case);
    }
    Ok(cases)
}

struct Outcome {
    got: Decision,
    layer: String,
    rule: String,
    latency: Duration,
    /// The case reached the llm layer.
    llm: bool,
}

/// Decides the cases with up to `concurrency` parallel calls (scoped threads)
/// and scores the results. Case order does not depend on completion order. The
/// first case runs alone, so a prompt cache is warm before the workers start.
/// `stop`, checked before each case is dispatched, skips the remaining cases
/// once it reports true.
pub fn run(
    cases: &[Case],
    decide: &(dyn Fn(&Request) -> Verdict + Sync),
    concurrency: usize,
    stop: Option<&(dyn Fn() -> bool + Sync)>,
) -> Report {
    let concurrency = concurrency.max(1);
    let slots: Vec<Mutex<Option<Outcome>>> = cases.iter().map(|_| Mutex::new(None)).collect();
    let one = |i: usize| {
        let req = cases[i].request.clone();
        let start = Instant::now();
        let v = decide(&req);
        let latency = start.elapsed();
        let llm = v.layer == LAYER_LLM || !v.backend.is_empty();
        let got = if v.layer == LAYER_NONE {
            Decision::Allow // nothing decided: not flagged
        } else {
            v.decision
        };
        let out = Outcome {
            got,
            layer: v.layer,
            rule: v.rule,
            latency,
            llm,
        };
        *slots[i].lock().unwrap_or_else(|p| p.into_inner()) = Some(out);
    };
    let stopped = || stop.is_some_and(|s| s());

    let mut next = 0;
    if !cases.is_empty() && !stopped() {
        one(0);
        next = 1;
    }
    // The dispatcher hands one case at a time to whichever worker is free.
    let (tx, rx) = mpsc::sync_channel::<usize>(0);
    let rx = Arc::new(Mutex::new(rx));
    let one = &one;
    std::thread::scope(|s| {
        for _ in 0..concurrency {
            let rx = Arc::clone(&rx);
            s.spawn(move || {
                loop {
                    let next = rx.lock().unwrap_or_else(|p| p.into_inner()).recv();
                    match next {
                        Ok(i) => one(i), // each case writes its own slot
                        Err(_) => break,
                    }
                }
            });
        }
        // If every worker died the receiver is gone and the send fails.
        drop(rx);
        while next < cases.len() && !stopped() {
            if tx.send(next).is_err() {
                break;
            }
            next += 1;
        }
        drop(tx);
    });

    let mut ran: Vec<&Case> = Vec::new();
    let mut ran_outs: Vec<Outcome> = Vec::new();
    for (case, slot) in cases.iter().zip(slots) {
        if let Some(o) = slot.into_inner().unwrap_or_else(|p| p.into_inner()) {
            ran.push(case);
            ran_outs.push(o);
        }
    }
    let mut rep = score(&ran, &ran_outs);
    rep.skipped = (cases.len() - ran.len()) as i64;
    rep.llm_cases = ran_outs.iter().filter(|o| o.llm).count() as i64;
    rep
}

#[derive(Default)]
struct Acc {
    s: Stats,
    lat: Vec<Duration>,
}

impl Acc {
    fn add(&mut self, c: &Case, o: &Outcome) {
        self.s.n += 1;
        self.lat.push(o.latency);
        let (exp, got) = (c.expected != Decision::Allow, o.got != Decision::Allow);
        match (exp, got) {
            (true, true) => self.s.tp += 1,
            (false, true) => self.s.fp += 1,
            (true, false) => self.s.fn_ += 1,
            (false, false) => self.s.tn += 1,
        }
    }

    fn finish(&mut self, exact: i64) -> Stats {
        let mut s = self.s.clone();
        s.precision = ratio(s.tp, s.tp + s.fp);
        s.recall = ratio(s.tp, s.tp + s.fn_);
        s.fpr = ratio(s.fp, s.fp + s.tn);
        s.accuracy = ratio(exact, s.n);
        self.lat.sort();
        s.p50_ms = pct(&self.lat, 50);
        s.p95_ms = pct(&self.lat, 95);
        s
    }
}

fn ratio(n: i64, d: i64) -> Option<f64> {
    (d != 0).then(|| n as f64 / d as f64)
}

/// The nearest-rank percentile in milliseconds.
fn pct(sorted: &[Duration], p: usize) -> f64 {
    if sorted.is_empty() {
        return 0.0;
    }
    let rank = (p * sorted.len()).div_ceil(100).max(1);
    sorted[rank - 1].as_micros() as f64 / 1000.0
}

fn score(cases: &[&Case], outs: &[Outcome]) -> Report {
    let mut all = Acc::default();
    let mut per: Vec<(String, Acc)> = Vec::new(); // in order of first appearance
    let mut exact: Vec<(String, i64)> = Vec::new();
    let mut rep = Report::default();
    let mut all_exact = 0;
    for (c, o) in cases.iter().zip(outs) {
        let idx = match per.iter().position(|(b, _)| *b == c.bucket) {
            Some(i) => i,
            None => {
                per.push((
                    c.bucket.clone(),
                    Acc {
                        s: Stats {
                            bucket: c.bucket.clone(),
                            ..Default::default()
                        },
                        lat: Vec::new(),
                    },
                ));
                exact.push((c.bucket.clone(), 0));
                per.len() - 1
            }
        };
        per[idx].1.add(c, o);
        all.add(c, o);
        if o.got == c.expected {
            exact[idx].1 += 1;
            all_exact += 1;
        } else {
            rep.mismatches.push(Mismatch {
                id: c.id.clone(),
                bucket: c.bucket.clone(),
                expected: c.expected.as_str().into(),
                got: o.got.as_str().into(),
                layer: o.layer.clone(),
                rule: o.rule.clone(),
            });
        }
    }
    all.s.bucket = "all".into();
    rep.overall = all.finish(all_exact);
    // Known buckets first in design order, then any others as encountered.
    let order: Vec<String> = BUCKETS
        .iter()
        .map(|b| (*b).to_owned())
        .chain(per.iter().map(|(b, _)| b.clone()))
        .collect();
    let mut seen: Vec<&str> = Vec::new();
    for b in &order {
        if seen.contains(&b.as_str()) {
            continue;
        }
        if let Some(i) = per.iter().position(|(name, _)| name == b) {
            seen.push(b);
            let ex = exact[i].1;
            rep.buckets.push(per[i].1.finish(ex));
        }
    }
    rep
}

fn pct_str(p: Option<f64>) -> String {
    p.map_or_else(|| "-".to_owned(), |p| format!("{:.0}%", p * 100.0))
}

impl Report {
    /// Writes the report as indented JSON, with a two-space indent, a trailing
    /// newline and `<`, `>`, `&` escaped.
    pub fn write_json(&self, w: &mut dyn Write) -> io::Result<()> {
        let json = crate::gojson::to_string_indent(self).map_err(io::Error::other)?;
        w.write_all(json.as_bytes())?;
        w.write_all(b"\n")
    }

    /// Writes a fixed-width table and the mismatch list.
    pub fn write_text(&self, w: &mut dyn Write) -> io::Result<()> {
        writeln!(
            w,
            "{:<14} {:>4} {:>4} {:>4} {:>4} {:>4} {:>6} {:>6} {:>6} {:>6} {:>7} {:>7}",
            "bucket", "n", "tp", "fp", "tn", "fn", "prec", "recall", "fpr", "acc", "p50ms", "p95ms"
        )?;
        let row = |w: &mut dyn Write, s: &Stats| {
            writeln!(
                w,
                "{:<14} {:>4} {:>4} {:>4} {:>4} {:>4} {:>6} {:>6} {:>6} {:>6} {:>7.1} {:>7.1}",
                s.bucket,
                s.n,
                s.tp,
                s.fp,
                s.tn,
                s.fn_,
                pct_str(s.precision),
                pct_str(s.recall),
                pct_str(s.fpr),
                pct_str(s.accuracy),
                s.p50_ms,
                s.p95_ms
            )
        };
        for s in &self.buckets {
            row(w, s)?;
        }
        row(w, &self.overall)?;
        if self.skipped > 0 {
            writeln!(
                w,
                "\nstopped at spend cap: {} cases skipped, not counted above",
                self.skipped
            )?;
        }
        if let Some(u) = &self.usage {
            u.write(w)?;
        }
        if self.mismatches.is_empty() {
            return writeln!(w, "\nno mismatches");
        }
        writeln!(w, "\nmismatches ({}):", self.mismatches.len())?;
        for m in &self.mismatches {
            writeln!(
                w,
                "  {:<28} {:<14} expected {:<5} got {:<5} layer {:<8} {}",
                m.id, m.bucket, m.expected, m.got, m.layer, m.rule
            )?;
        }
        Ok(())
    }
}

impl Usage {
    fn write(&self, w: &mut dyn Write) -> io::Result<()> {
        writeln!(
            w,
            "\nllm usage: {} calls, input {}, output {}, cache read {}, cache write {}, {:.0} tokens/case, est. ${:.4}",
            self.llm_calls,
            self.input_tokens,
            self.output_tokens,
            self.cache_read_tokens,
            self.cache_write_tokens,
            self.tokens_per_case,
            self.est_usd
        )
    }
}

/// Prints the headline metrics of two runs side by side.
pub fn write_comparison(
    w: &mut dyn Write,
    label_a: &str,
    a: &Report,
    label_b: &str,
    b: &Report,
) -> io::Result<()> {
    writeln!(w, "{:<14} {:>12} {:>12}", "", label_a, label_b)?;
    let mut row = |name: &str, x: String, y: String| writeln!(w, "{name:<14} {x:>12} {y:>12}");
    row(
        "precision",
        pct_str(a.overall.precision),
        pct_str(b.overall.precision),
    )?;
    row(
        "recall",
        pct_str(a.overall.recall),
        pct_str(b.overall.recall),
    )?;
    row("fpr", pct_str(a.overall.fpr), pct_str(b.overall.fpr))?;
    row(
        "accuracy",
        pct_str(a.overall.accuracy),
        pct_str(b.overall.accuracy),
    )?;
    let tokens = |r: &Report| {
        r.usage
            .as_ref()
            .map_or_else(|| "-".to_owned(), |u| format!("{:.0}", u.tokens_per_case))
    };
    let usd = |r: &Report| {
        r.usage
            .as_ref()
            .map_or_else(|| "-".to_owned(), |u| format!("${:.4}", u.est_usd))
    };
    row("tokens/case", tokens(a), tokens(b))?;
    row("est. usd", usd(a), usd(b))?;
    row(
        "cases run",
        a.overall.n.to_string(),
        b.overall.n.to_string(),
    )
}

/// USD per million tokens.
#[derive(Debug, Clone, Copy, PartialEq)]
struct Price {
    input: f64,
    output: f64,
}

const fn price(input: f64, output: f64) -> Price {
    Price { input, output }
}

const EXACT_PRICES: [(&str, Price); 7] = [
    ("claude-haiku-5-5", price(0.10, 0.50)),
    ("claude-haiku-4-5", price(1.0, 5.0)),
    ("claude-sonnet-5-5", price(2.0, 10.0)),
    ("claude-sonnet-5", price(2.0, 10.0)),
    ("claude-sonnet-4-6", price(3.0, 15.0)),
    ("claude-opus-5-5", price(4.0, 20.0)),
    ("claude-opus-5", price(5.0, 25.0)),
];

const PREFIX_PRICES: [(&str, Price); 2] = [
    ("claude-opus-4-", price(5.0, 25.0)),
    ("claude-fable-5", price(10.0, 50.0)),
];

/// The price of an anthropic model not in the table: the highest, so the cap
/// errs on the safe side.
const UNKNOWN_ANTHROPIC: Price = price(10.0, 50.0);

/// The model's price; None for non-anthropic backends, which cost nothing here.
fn price_of(backend_name: &str) -> Option<Price> {
    let model = backend_name.strip_prefix("anthropic:")?;
    if let Some((_, p)) = EXACT_PRICES.iter().find(|(m, _)| *m == model) {
        return Some(*p);
    }
    if let Some((_, p)) = PREFIX_PRICES.iter().find(|(pre, _)| model.starts_with(pre)) {
        return Some(*p);
    }
    Some(UNKNOWN_ANTHROPIC)
}

/// Wraps a backend, sums its token use and estimates the cost. Once the
/// estimate reaches 90% of the cap it refuses new calls (they fail, so the
/// engine answers with its fallback) and [`Meter::stop`] reports true.
pub struct Meter {
    inner: Arc<dyn Backend>,
    cap_usd: f64,
    usage: Mutex<Usage>,
}

impl Meter {
    /// A `cap_usd` of 0 (or less) means no cap.
    pub fn new(inner: Arc<dyn Backend>, cap_usd: f64) -> Meter {
        Meter {
            inner,
            cap_usd,
            usage: Mutex::new(Usage::default()),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Usage> {
        self.usage.lock().unwrap_or_else(|p| p.into_inner())
    }

    fn stopped(&self, u: &Usage) -> bool {
        self.cap_usd > 0.0 && u.est_usd >= SPEND_STOP_FRACTION * self.cap_usd
    }

    /// Whether the spend cap has been reached.
    pub fn stop(&self) -> bool {
        self.stopped(&self.lock())
    }

    /// The usage so far; `llm_cases` is [`Report::llm_cases`].
    pub fn usage(&self, llm_cases: i64) -> Usage {
        let mut u = self.lock().clone();
        if llm_cases > 0 {
            u.tokens_per_case =
                (u.input_tokens + u.cache_read_tokens + u.cache_write_tokens + u.output_tokens)
                    as f64
                    / llm_cases as f64;
        }
        u
    }
}

impl Backend for Meter {
    fn name(&self) -> String {
        self.inner.name()
    }

    fn data_classes(&self) -> &[String] {
        self.inner.data_classes()
    }

    /// Forwards to the wrapped backend and records the usage.
    fn classify(
        &self,
        req: &ClassifyRequest,
        deadline: Instant,
    ) -> Result<ClassifyResult, BackendError> {
        if self.stop() {
            return Err(BackendError::Other(format!(
                "eval spend cap of ${:.2} reached",
                self.cap_usd
            )));
        }
        let res = self.inner.classify(req, deadline);
        let r = res.clone().unwrap_or_default();
        let mut u = self.lock();
        u.llm_calls += 1;
        u.input_tokens += r.input_tokens;
        u.output_tokens += r.output_tokens;
        u.cache_read_tokens += r.cache_read_tokens;
        u.cache_write_tokens += r.cache_write_tokens;
        if let Some(p) = price_of(&self.inner.name()) {
            u.est_usd += (r.input_tokens as f64 * p.input
                + r.output_tokens as f64 * p.output
                + r.cache_write_tokens as f64 * 1.25 * p.input
                + r.cache_read_tokens as f64 * 0.1 * p.input)
                / 1e6;
        }
        drop(u);
        res
    }
}

#[cfg(test)]
mod tests;
