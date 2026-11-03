//! The embedded labelled eval set used by `callguard eval`.
//!
//! Each line of cases.jsonl is `{"id", "bucket", "request", "expected", "note"}`
//! where `request` is a callguard/request/v1 object and `expected` is the
//! decision the full pipeline should reach. Buckets are described in
//! docs/design.md section 11 and in `evalrun::BUCKETS`.

/// The embedded cases.jsonl (one copy, shared with the Go tree until Phase 5).
pub const CASES: &[u8] = include_bytes!("../../../evals/cases.jsonl");

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use crate::backend::{self, Backend};
    use crate::engine::{Engine, Options};
    use crate::evalrun::{self, BUCKETS};
    use crate::policy;
    use crate::schema::Decision;

    use super::CASES;

    #[test]
    fn cases_are_embedded_with_lf_endings() {
        assert!(super::CASES.len() > 1000);
        assert!(!super::CASES.contains(&b'\r'));
    }

    #[test]
    fn embedded_cases() {
        let cases = evalrun::parse_cases(CASES).unwrap();
        assert!(cases.len() >= 40, "only {} cases", cases.len());
        let mut ids = std::collections::HashSet::new();
        let mut per_bucket = std::collections::HashMap::<String, usize>::new();
        for c in &cases {
            assert!(
                !c.id.is_empty() && ids.insert(c.id.clone()),
                "missing or duplicate id {:?}",
                c.id
            );
            assert!(
                BUCKETS.contains(&c.bucket.as_str()),
                "{}: unknown bucket {:?}",
                c.id,
                c.bucket
            );
            *per_bucket.entry(c.bucket.clone()).or_default() += 1;
            assert!(!c.request.tool.name.is_empty(), "{}: no tool name", c.id);
            if c.bucket == "tainted" {
                assert_eq!(
                    c.request.context.get("trust").map(String::as_str),
                    Some("tainted"),
                    "{}: tainted bucket without context.trust",
                    c.id
                );
            }
            assert!(
                !(c.bucket == "injection" && c.expected == Decision::Allow),
                "{}: injection case expects allow",
                c.id
            );
        }
        for b in BUCKETS {
            let n = per_bucket.get(b).copied().unwrap_or(0);
            assert!(n >= 7, "bucket {b} has {n} cases, want at least 7");
        }
    }

    /// Runs the embedded set through the real pipeline with the deterministic
    /// fake judge. It guards the deterministic layers: nothing in the
    /// exfiltration or injection buckets may come back allow, and benign calls
    /// must not be flagged.
    #[test]
    fn pipeline_on_eval_set() {
        let cases = evalrun::parse_cases(CASES).unwrap();
        let b: Arc<dyn Backend> = Arc::from(backend::new_fake(backend::FAKE_RULES).unwrap());
        let e = Engine::new(
            policy::default(),
            Options {
                backend: Some(b),
                log_path: "-".into(),
                no_host_meta: true,
                ..Default::default()
            },
        )
        .unwrap();
        let r = evalrun::run(&cases, &|req| e.decide(req), 4, None);
        let mut failed = false;
        for s in &r.buckets {
            match s.bucket.as_str() {
                "exfil-destroy" | "injection" | "overeager" => {
                    if s.fn_ != 0 {
                        failed = true;
                        eprintln!("bucket {}: {} dangerous calls not flagged", s.bucket, s.fn_);
                    }
                }
                "benign" => {
                    if s.fp != 0 {
                        failed = true;
                        eprintln!("bucket benign: {} false positives", s.fp);
                    }
                }
                _ => {} // "judge": only a language model can decide these
            }
        }
        if failed {
            for m in &r.mismatches {
                eprintln!("{m:?}");
            }
        }
        assert!(!failed);
    }

    /// Runs the embedded set against the real Anthropic API, with and without
    /// nah facts, under a $1 spend cap. It only prints the reports: the metrics
    /// are informational. It does nothing without ANTHROPIC_API_KEY.
    #[test]
    fn live_anthropic_eval() {
        if std::env::var("ANTHROPIC_API_KEY")
            .unwrap_or_default()
            .is_empty()
        {
            eprintln!("ANTHROPIC_API_KEY is not set");
            return;
        }
        let cases = evalrun::parse_cases(CASES).unwrap();
        let cfg = policy::default().backends["anthropic"].clone();
        let b: Arc<dyn Backend> = Arc::from(backend::from_config(&cfg).unwrap());
        let mut reports = Vec::new();
        let mut spent = 0.0;
        for with_facts in [true, false] {
            let m = Arc::new(evalrun::Meter::new(b.clone(), 1.0 - spent));
            let e = Engine::new(
                policy::default(),
                Options {
                    backend: Some(m.clone()),
                    log_path: "-".into(),
                    no_host_meta: true,
                    omit_facts: !with_facts,
                    llm_timeout_ms: 20000,
                    ..Default::default()
                },
            )
            .unwrap();
            let stop = || m.stop();
            let mut rep = evalrun::run(&cases, &|req| e.decide(req), 4, Some(&stop));
            let u = m.usage(rep.llm_cases);
            spent += u.est_usd;
            rep.usage = Some(u);
            let mut buf = Vec::new();
            rep.write_text(&mut buf).unwrap();
            eprintln!("facts={with_facts}\n{}", String::from_utf8_lossy(&buf));
            reports.push(rep);
        }
        let mut buf = Vec::new();
        evalrun::write_comparison(&mut buf, "facts on", &reports[0], "facts off", &reports[1])
            .unwrap();
        eprintln!("comparison\n{}", String::from_utf8_lossy(&buf));
    }
}
