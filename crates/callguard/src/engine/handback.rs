//! Review of a sub-agent's report with the engine's backend, deadline,
//! token counts and decision log. The review is advisory: its log entry has
//! layer `handback` and decision `ask`, so it feeds neither the deny streak
//! (`declog::llm_denies` counts layer `llm`) nor the judge's
//! "blocked by callguard" marks (those need a `deny`).

use super::*;
use crate::handback::{self, Review, SubagentReport};
use crate::schema::ToolCall;

/// What one review used and learned.
struct Ran {
    review: Review,
    backend: String,
    confidence: f64,
    in_tok: i64,
    out_tok: i64,
}

impl Ran {
    fn new(review: Review) -> Ran {
        Ran {
            review,
            backend: String::new(),
            confidence: 0.0,
            in_tok: 0,
            out_tok: 0,
        }
    }

    fn failed(cause: String, backend: &str) -> Ran {
        Ran {
            backend: backend.into(),
            ..Ran::new(Review::Failed(cause))
        }
    }
}

impl Engine {
    /// Reviews a sub-agent's report. `Skipped` when the judge is off or has no
    /// backend; otherwise the verdict is logged. In shadow mode (the llm layer
    /// or the policy) the result is logged but a flag or failure is not
    /// reported, as for the judge's own verdicts. A panic is a failed review.
    pub fn review_handback(&self, r: &SubagentReport) -> Review {
        let start = self.inner.now();
        let t0 = Instant::now();
        let ran = panic::catch_unwind(AssertUnwindSafe(|| self.inner.review(r, t0)))
            .unwrap_or_else(|p| {
                Ran::failed(format!("internal error: {}", panic_message(p.as_ref())), "")
            });
        if ran.review == Review::Skipped {
            return Review::Skipped;
        }
        let llm = self.inner.pol.llm.clone().unwrap_or_default();
        let enforced =
            llm.mode != policy::MODE_SHADOW && self.inner.pol.mode != policy::MODE_SHADOW;
        let latency = self
            .inner
            .now()
            .duration_since(start)
            .map_or(0, |d| d.as_millis() as i64);
        self.inner.log_review(r, &ran, enforced, latency);
        if enforced { ran.review } else { Review::Clean }
    }
}

impl Inner {
    fn review(&self, r: &SubagentReport, t0: Instant) -> Ran {
        let llm = self.pol.llm.clone().unwrap_or_default();
        if !self.pol.llm_enabled() {
            return Ran::new(Review::Skipped);
        }
        let b = match self.backend(&llm.backend) {
            Ok(b) => b,
            Err(NoBackend::Missing) => return Ran::new(Review::Skipped),
            Err(NoBackend::Unavailable(e)) => {
                return Ran::failed(format!("backend unavailable: {e}"), "");
            }
        };
        let name = b.name();
        if let Some(dc) = r.context.get("data_class").filter(|d| !d.is_empty())
            && !b.data_classes().contains(dc)
        {
            return Ran::failed(
                format!("data class {dc:?} may not be sent to {name}"),
                &name,
            );
        }
        // What the user asked for, from the parent's transcript.
        let req = Request {
            harness: r.harness.clone(),
            session_id: r.session_id.clone(),
            cwd: r.cwd.clone(),
            tool: ToolCall {
                name: r.tool_name.clone(),
                input: r.tool_input.clone(),
            },
            transcript: r.transcript.clone(),
            ..Default::default()
        };
        let (history, _) = self.transcript(&req);
        let cr = handback::classify_request(r, history);
        let limit = Duration::from_millis(llm.timeout_ms.max(0) as u64)
            .min(Duration::from_millis(self.pol.deadline_ms.max(0) as u64));
        let res = match b.classify(&cr, t0 + limit) {
            Ok(res) => res,
            Err(e) => return Ran::failed(e.to_string(), &name),
        };
        let review = match handback::interpret(&res.label, res.confidence, &res.reason) {
            Ok(review) => review,
            Err(e) => return Ran::failed(e, &name),
        };
        Ran {
            review,
            backend: name,
            confidence: res.confidence,
            in_tok: res.input_tokens,
            out_tok: res.output_tokens,
        }
    }

    fn log_review(&self, r: &SubagentReport, ran: &Ran, enforced: bool, latency_ms: i64) {
        let Some(logger) = &self.logger else { return };
        let include_input = self.pol.log.as_ref().is_some_and(|l| l.include_input);
        let (rule, reason) = match &ran.review {
            Review::Flagged(why) => ("handback-flag", why.as_str()),
            Review::Failed(why) => ("handback-failed", why.as_str()),
            _ => ("handback-clean", ""),
        };
        let ent = declog::Entry {
            ts: rfc3339_nano(self.now()),
            id: new_id(),
            session_id: r.session_id.clone(),
            tool_use_id: r.tool_use_id.clone(),
            harness: r.harness.clone(),
            tool: r.tool_name.clone(),
            kind: "agent".into(),
            input_sha256: hex::encode(Sha256::digest(r.report.as_bytes())),
            decision: if rule == "handback-clean" {
                "allow"
            } else {
                "ask"
            }
            .into(),
            enforced,
            layer: LAYER_HANDBACK.into(),
            rule: rule.into(),
            confidence: ran.confidence,
            backend: ran.backend.clone(),
            policy_rev: self.rev.clone(),
            latency_ms,
            unattended: r.unattended,
            input_tokens: ran.in_tok,
            output_tokens: ran.out_tok,
            // Model text about the report: kept out of the log like an llm reason.
            reason: if include_input {
                reason.to_owned()
            } else {
                String::new()
            },
            ..Default::default()
        };
        let _ = logger.append(&ent);
    }
}

/// The log layer of report reviews.
pub(crate) const LAYER_HANDBACK: &str = "handback";
