//! Scores a decide function against labelled cases (design section 11).
//! Positive means flagged (ask or deny). Stub (worker D).
#![allow(unused_variables, dead_code)]

use std::io::{self, Write};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use serde::{Deserialize, Serialize};

use crate::backend::{Backend, BackendError, ClassifyRequest, ClassifyResult};
use crate::schema::{Decision, Request, Verdict};

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
    pub id: String,
    pub bucket: String,
    pub request: Request,
    pub expected: Decision,
    #[serde(default)]
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
    pub precision: Option<f64>,
    pub recall: Option<f64>,
    pub fpr: Option<f64>,
    pub accuracy: Option<f64>,
    pub p50_ms: f64,
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
    pub tokens_per_case: f64,
    pub est_usd: f64,
}

/// A bad cases file.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct EvalError(pub String);

/// The share of the spend cap at which the [`Meter`] stops taking new calls
/// and the run stops dispatching cases.
pub const SPEND_STOP_FRACTION: f64 = 0.9;

/// Reads JSON lines, skipping blank lines and lines starting with `//`. The
/// error names the line.
pub fn parse_cases(data: &[u8]) -> Result<Vec<Case>, EvalError> {
    todo!("port evalrun.ParseCases")
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
    todo!("port evalrun.Run")
}

impl Report {
    pub fn write_json(&self, w: &mut dyn Write) -> io::Result<()> {
        todo!("port Report.WriteJSON")
    }

    pub fn write_text(&self, w: &mut dyn Write) -> io::Result<()> {
        todo!("port Report.WriteText")
    }
}

/// Prints the two reports side by side.
pub fn write_comparison(
    w: &mut dyn Write,
    label_a: &str,
    a: &Report,
    label_b: &str,
    b: &Report,
) -> io::Result<()> {
    todo!("port evalrun.WriteComparison")
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
    /// A `cap_usd` of 0 means no cap.
    pub fn new(inner: Arc<dyn Backend>, cap_usd: f64) -> Meter {
        Meter {
            inner,
            cap_usd,
            usage: Mutex::new(Usage::default()),
        }
    }

    /// Whether the spend cap has been reached.
    pub fn stop(&self) -> bool {
        todo!("port Meter.Stop")
    }

    /// The usage so far; `llm_cases` is [`Report::llm_cases`].
    pub fn usage(&self, llm_cases: i64) -> Usage {
        todo!("port Meter.Usage")
    }
}

impl Backend for Meter {
    fn name(&self) -> String {
        self.inner.name()
    }

    fn data_classes(&self) -> &[String] {
        self.inner.data_classes()
    }

    fn classify(
        &self,
        req: &ClassifyRequest,
        deadline: Instant,
    ) -> Result<ClassifyResult, BackendError> {
        todo!("port Meter.Classify")
    }
}
