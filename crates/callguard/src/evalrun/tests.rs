//! Ports of internal/evalrun/evalrun_test.go and usage_test.go.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use super::*;
use crate::schema::{LAYER_BUILTIN, LAYER_RULES, ToolCall};

fn mk_case(id: &str, bucket: &str, expected: Decision) -> Case {
    Case {
        id: id.into(),
        bucket: bucket.into(),
        expected,
        note: String::new(),
        request: Request {
            tool: ToolCall {
                name: id.into(),
                input: None,
            },
            ..Default::default()
        },
    }
}

fn verdict(decision: Decision, layer: &str, rule: &str) -> Verdict {
    Verdict {
        schema: String::new(),
        v: 0,
        id: String::new(),
        decision,
        enforced: false,
        reason: String::new(),
        layer: layer.into(),
        rule: rule.into(),
        confidence: 0.0,
        policy_rev: String::new(),
        backend: String::new(),
        latency_ms: 0,
        warnings: Vec::new(),
    }
}

#[test]
fn run_scores_buckets() {
    let cases = vec![
        mk_case("b1", "benign", Decision::Allow),
        mk_case("b2", "benign", Decision::Allow),
        mk_case("o1", "overeager", Decision::Ask),
        mk_case("o2", "overeager", Decision::Ask),
        mk_case("e1", "exfil-destroy", Decision::Deny),
    ];
    let got: HashMap<&str, Verdict> = HashMap::from([
        ("b1", verdict(Decision::Allow, LAYER_RULES, "")), // TN, exact
        ("b2", verdict(Decision::Ask, LAYER_LLM, "x")),    // FP
        ("o1", verdict(Decision::Deny, LAYER_BUILTIN, "r1")), // TP, not exact
        ("o2", verdict(Decision::Ask, LAYER_NONE, "")),    // layer none: FN
        ("e1", verdict(Decision::Deny, LAYER_BUILTIN, "")), // TP, exact
    ]);
    let rep = run(
        &cases,
        &|r: &Request| {
            std::thread::sleep(Duration::from_millis(1));
            got[r.tool.name.as_str()].clone()
        },
        3,
        None,
    );

    let o = &rep.overall;
    assert!(
        o.n == 5 && o.tp == 2 && o.fp == 1 && o.tn == 1 && o.fn_ == 1,
        "overall {o:?}"
    );
    let approx = |name: &str, p: Option<f64>, want: f64| {
        assert!(
            p.is_some_and(|p| (p - want).abs() < 1e-9),
            "{name} = {p:?}, want {want}"
        );
    };
    approx("precision", o.precision, 2.0 / 3.0);
    approx("recall", o.recall, 2.0 / 3.0);
    approx("fpr", o.fpr, 0.5);
    approx("accuracy", o.accuracy, 2.0 / 5.0);
    assert!(
        o.p50_ms > 0.0 && o.p95_ms >= o.p50_ms,
        "latency {} {}",
        o.p50_ms,
        o.p95_ms
    );
    let names: Vec<&str> = rep.buckets.iter().map(|b| b.bucket.as_str()).collect();
    assert_eq!(names, ["benign", "overeager", "exfil-destroy"]);
    let b = &rep.buckets[0];
    assert!(
        b.fp == 1 && b.tn == 1 && b.recall.is_none() && b.precision == Some(0.0),
        "benign {b:?}"
    );
    assert_eq!(rep.mismatches.len(), 3, "mismatches {:?}", rep.mismatches);
    let ids: HashMap<&str, &Mismatch> = rep.mismatches.iter().map(|m| (m.id.as_str(), m)).collect();
    let m = ids["o2"];
    assert!(
        m.got == "allow" && m.layer == "none",
        "layer none mismatch {m:?}"
    );
    let m = ids["o1"];
    assert!(
        m.got == "deny" && m.expected == "ask" && m.rule == "r1",
        "o1 {m:?}"
    );

    let mut txt = Vec::new();
    rep.write_text(&mut txt).unwrap();
    let txt = String::from_utf8(txt).unwrap();
    assert!(
        txt.contains("mismatches (3)") && txt.contains("overeager"),
        "text:\n{txt}"
    );
    let mut js = Vec::new();
    rep.write_json(&mut js).unwrap();
    let back: serde_json::Value = serde_json::from_slice(&js).unwrap();
    assert_eq!(back["overall"]["n"], 5);
    assert_eq!(back["buckets"][0]["recall"], serde_json::Value::Null);
}

#[test]
fn run_empty_and_parse() {
    let rep = run(&[], &|_| unreachable!("no cases"), 0, None);
    assert!(
        rep.overall.n == 0 && rep.overall.accuracy.is_none() && rep.mismatches.is_empty(),
        "{rep:?}"
    );
    let row =
        r#"{"id":"a","bucket":"benign","request":{"tool":{"name":"Bash"}},"expected":"allow"}"#;
    let cs = parse_cases(format!("\n// c\n{row}\n").as_bytes()).unwrap();
    assert!(cs.len() == 1 && cs[0].request.tool.name == "Bash", "{cs:?}");
    let e = parse_cases(b"{bad").unwrap_err();
    assert!(e.0.contains("line 1"), "err = {e}");
    // CRLF line ends and a line number that counts blank lines.
    let e = parse_cases(format!("{row}\r\n\r\n{{bad\r\n").as_bytes()).unwrap_err();
    assert!(e.0.starts_with("line 3:"), "{e}");
    assert_eq!(
        parse_cases(format!("{row}\r\n").as_bytes()).unwrap().len(),
        1
    );
}

#[test]
fn run_stops_and_counts_skipped() {
    let cases: Vec<Case> = ["a", "b", "c", "d", "e"]
        .iter()
        .map(|id| mk_case(id, "benign", Decision::Allow))
        .collect();
    let ran = AtomicUsize::new(0);
    let first = AtomicBool::new(false);
    let decide = |r: &Request| {
        if ran.fetch_add(1, Ordering::SeqCst) + 1 == 1 {
            first.store(r.tool.name == "a", Ordering::SeqCst); // the first case runs before any other starts
            std::thread::sleep(Duration::from_millis(20));
        } else {
            assert!(
                first.load(Ordering::SeqCst),
                "a worker started before the first case finished"
            );
        }
        verdict(Decision::Allow, LAYER_LLM, "")
    };
    let stop = || ran.load(Ordering::SeqCst) >= 2;
    let mut rep = run(&cases, &decide, 4, Some(&stop));
    // Go's test also asserts Skipped > 0, but whether the dispatcher sees the
    // stop before it has handed out the rest depends on thread timing in both
    // languages; the exact count is tested in run_stops_after_the_first_case.
    let n = ran.load(Ordering::SeqCst);
    assert!(
        rep.overall.n + rep.skipped == 5
            && n as i64 == rep.overall.n
            && rep.llm_cases == rep.overall.n,
        "skipped {}, n {}, ran {n}, llm {}",
        rep.skipped,
        rep.overall.n,
        rep.llm_cases
    );
    rep.skipped = 2;
    rep.usage = Some(Usage {
        llm_calls: 2,
        est_usd: 0.5,
        ..Default::default()
    });
    let mut txt = Vec::new();
    rep.write_text(&mut txt).unwrap();
    let txt = String::from_utf8(txt).unwrap();
    assert!(
        txt.contains("stopped at spend cap") && txt.contains("llm usage: 2 calls"),
        "text:\n{txt}"
    );
}

#[test]
fn run_stops_after_the_first_case() {
    let cases: Vec<Case> = ["a", "b", "c", "d", "e"]
        .iter()
        .map(|id| mk_case(id, "benign", Decision::Allow))
        .collect();
    let done = AtomicBool::new(false);
    let rep = run(
        &cases,
        &|_| {
            done.store(true, Ordering::SeqCst);
            verdict(Decision::Allow, LAYER_RULES, "")
        },
        4,
        Some(&|| done.load(Ordering::SeqCst)),
    );
    assert!(rep.overall.n == 1 && rep.skipped == 4, "{rep:?}");
    // A stop that is already true runs nothing.
    let rep = run(&cases, &|_| unreachable!("stopped"), 4, Some(&|| true));
    assert!(rep.overall.n == 0 && rep.skipped == 5);
}

#[test]
fn case_order_does_not_depend_on_completion_order() {
    let cases: Vec<Case> = (0..20)
        .map(|i| mk_case(&format!("c{i}"), "benign", Decision::Ask))
        .collect();
    let rep = run(
        &cases,
        &|r: &Request| {
            // Later cases finish first.
            let n: u64 = r.tool.name[1..].parse().unwrap();
            std::thread::sleep(Duration::from_millis(20 - n));
            verdict(Decision::Allow, LAYER_RULES, "")
        },
        8,
        None,
    );
    let ids: Vec<String> = rep.mismatches.iter().map(|m| m.id.clone()).collect();
    let want: Vec<String> = (0..20).map(|i| format!("c{i}")).collect();
    assert_eq!(ids, want);
}

#[test]
fn json_report_bytes_follow_go() {
    let rep = Report {
        overall: Stats {
            bucket: "all".into(),
            n: 2,
            tp: 1,
            tn: 1,
            precision: Some(1.0),
            recall: Some(0.8333333333333334),
            fpr: None,
            accuracy: Some(0.5),
            p50_ms: 0.0,
            p95_ms: 12.5,
            ..Default::default()
        },
        buckets: vec![],
        mismatches: vec![Mismatch {
            id: "a<b>&c".into(),
            bucket: "x".into(),
            expected: "ask".into(),
            got: "allow".into(),
            layer: "rules".into(),
            rule: String::new(),
        }],
        skipped: 0,
        llm_cases: 0,
        usage: Some(Usage {
            llm_calls: 1,
            tokens_per_case: 1100000.0,
            est_usd: 5e-7,
            ..Default::default()
        }),
    };
    let mut out = Vec::new();
    rep.write_json(&mut out).unwrap();
    let want = r#"{
  "overall": {
    "bucket": "all",
    "n": 2,
    "tp": 1,
    "fp": 0,
    "tn": 1,
    "fn": 0,
    "precision": 1,
    "recall": 0.8333333333333334,
    "fpr": null,
    "accuracy": 0.5,
    "p50_ms": 0,
    "p95_ms": 12.5
  },
  "buckets": [],
  "mismatches": [
    {
      "id": "a@LT@b@GT@@AMP@c",
      "bucket": "x",
      "expected": "ask",
      "got": "allow",
      "layer": "rules"
    }
  ],
  "skipped": 0,
  "llm_cases": 0,
  "usage": {
    "llm_calls": 1,
    "input_tokens": 0,
    "output_tokens": 0,
    "cache_read_tokens": 0,
    "cache_write_tokens": 0,
    "tokens_per_case": 1100000,
    "est_usd": 5e-7
  }
}
"#;
    let want = want
        .replace("@LT@", "\\u003c")
        .replace("@GT@", "\\u003e")
        .replace("@AMP@", "\\u0026");
    assert_eq!(String::from_utf8(out).unwrap(), want);
}

#[test]
fn text_report_and_comparison() {
    let mut rep = Report::default();
    rep.overall.bucket = "all".into();
    rep.overall.precision = Some(2.0 / 3.0);
    let mut txt = Vec::new();
    rep.write_text(&mut txt).unwrap();
    let txt = String::from_utf8(txt).unwrap();
    let lines: Vec<&str> = txt.lines().collect();
    assert_eq!(
        lines[0],
        "bucket            n   tp   fp   tn   fn   prec recall    fpr    acc   p50ms   p95ms"
    );
    assert_eq!(
        lines[1],
        "all               0    0    0    0    0    67%      -      -      -     0.0     0.0"
    );
    assert!(txt.ends_with("\nno mismatches\n"), "{txt}");

    let mut b = rep.clone();
    b.usage = Some(Usage {
        tokens_per_case: 1234.4,
        est_usd: 0.12345,
        ..Default::default()
    });
    let mut out = Vec::new();
    write_comparison(&mut out, "facts on", &rep, "facts off", &b).unwrap();
    let out = String::from_utf8(out).unwrap();
    let header = format!("{}facts on{}facts off", " ".repeat(19), " ".repeat(4));
    assert!(out.starts_with(&header), "{out}");
    let row = |name: &str, x: &str, y: &str| format!("{name:<14} {x:>12} {y:>12}\n");
    assert!(out.contains(&row("tokens/case", "-", "1234")), "{out}");
    assert!(out.contains(&row("est. usd", "-", "$0.1235")), "{out}");
    assert!(out.ends_with(&row("cases run", "0", "0")), "{out}");
}

// --- usage_test.go ----------------------------------------------------------------

struct Priced {
    name: String,
    res: ClassifyResult,
}

impl Backend for Priced {
    fn name(&self) -> String {
        self.name.clone()
    }
    fn data_classes(&self) -> &[String] {
        &[]
    }
    fn classify(&self, _: &ClassifyRequest, _: Instant) -> Result<ClassifyResult, BackendError> {
        Ok(self.res.clone())
    }
}

#[test]
fn price_table() {
    for (name, want) in [
        ("anthropic:claude-haiku-5-5", price(0.10, 0.50)),
        ("anthropic:claude-sonnet-5", price(2.0, 10.0)),
        ("anthropic:claude-opus-4-1", price(5.0, 25.0)),
        ("anthropic:claude-fable-5-1", price(10.0, 50.0)),
        ("anthropic:claude-unheard-of", price(10.0, 50.0)),
        ("anthropic:claude-sonnet-4-6", price(3.0, 15.0)),
    ] {
        assert_eq!(price_of(name), Some(want), "{name}");
    }
    assert_eq!(price_of("fake:rules"), None, "fake backends are free");
}

#[test]
fn meter_sums_and_stops_at_ninety_percent() {
    // claude-sonnet-5-5: $2 in, $10 out per MTok. One call: 1M input = $2,
    // 100k output = $1, 1M cache read = $0.2, 100k cache write = $0.25.
    let res = ClassifyResult {
        input_tokens: 1_000_000,
        output_tokens: 100_000,
        cache_read_tokens: 1_000_000,
        cache_write_tokens: 100_000,
        ..Default::default()
    };
    let b = Arc::new(Priced {
        name: "anthropic:claude-sonnet-5-5".into(),
        res: res.clone(),
    });
    let m = Meter::new(b, 5.0);
    let deadline = Instant::now() + Duration::from_secs(1);
    let req = ClassifyRequest::default();
    m.classify(&req, deadline).unwrap();
    let u = m.usage(2);
    assert!(
        u.llm_calls == 1
            && (u.est_usd - 3.45).abs() < 1e-9
            && u.tokens_per_case == 1_100_000.0
            && !m.stop(),
        "{u:?} stop {}",
        m.stop()
    );
    m.classify(&req, deadline).unwrap();
    assert!(m.stop(), "no stop at 90% of the cap"); // 6.90 >= 4.50
    assert!(
        m.classify(&req, deadline).is_err(),
        "a call after the cap must be refused"
    );
    assert_eq!(m.usage(0).llm_calls, 2, "a refused call must not count");

    let free = Meter::new(
        Arc::new(Priced {
            name: "fake:rules".into(),
            res,
        }),
        0.01,
    );
    let _ = free.classify(&req, deadline);
    assert!(
        !free.stop() && free.usage(1).est_usd == 0.0,
        "non-anthropic backends cost nothing"
    );
}

#[test]
fn meter_counts_a_failed_call_like_go() {
    struct Failing;
    impl Backend for Failing {
        fn name(&self) -> String {
            "anthropic:claude-haiku-5-5".into()
        }
        fn data_classes(&self) -> &[String] {
            &[]
        }
        fn classify(
            &self,
            _: &ClassifyRequest,
            _: Instant,
        ) -> Result<ClassifyResult, BackendError> {
            Err(BackendError::Timeout)
        }
    }
    let m = Meter::new(Arc::new(Failing), 0.0);
    assert!(
        m.classify(&ClassifyRequest::default(), Instant::now())
            .is_err()
    );
    assert_eq!(m.usage(0).llm_calls, 1);
    assert!(!m.stop(), "no cap");
}
