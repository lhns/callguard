//! `callguard eval`: runs the labelled eval set through the full pipeline.
//! Metrics are informational: it exits 0 when it ran, 1 on setup errors.

use std::io::Write;
use std::sync::Arc;

use callguard::backend::{self, Backend};
use callguard::engine::{self, Engine};
use callguard::evalrun::{self, Meter, Report};
use callguard::evals;
use callguard::gojson;
use callguard::policy;
use callguard::schema::Request;

use crate::flags::{self, FlagError, Kind, spec};

const USAGE: &str = "usage: callguard eval [flags]

Flags:
  --cases FILE         cases JSONL file (default: the embedded set)
  --policy FILE        system policy file
  --backend NAME       backend name from the policy's backends, or fake / fake:<mode> / anthropic / anthropic:<model>
  --bucket NAME        run only this bucket
  --concurrency N      parallel decisions (default 4)
  --json               print the report as JSON
  --facts on|off|both  show the judge nah facts; both runs the set twice and compares (default on)
  --max-usd N          stop at 90% of this estimated spend in USD, 0 = no cap (default 1)
  --llm-timeout-ms N   override the policy's llm.timeout_ms (the eval measures judgement, not latency)
";

pub fn run(args: &[String], stdout: &mut dyn Write, stderr: &mut dyn Write) -> i32 {
    let f = match flags::parse(
        &[
            spec("cases", Kind::Str),
            spec("policy", Kind::Str),
            spec("backend", Kind::Str),
            spec("bucket", Kind::Str),
            spec("concurrency", Kind::Int),
            spec("json", Kind::Bool),
            spec("facts", Kind::Str),
            spec("max-usd", Kind::Float),
            spec("llm-timeout-ms", Kind::Int),
        ],
        args,
    ) {
        Ok(f) => f,
        Err(FlagError::Help) => {
            let _ = stderr.write_all(USAGE.as_bytes());
            return 0;
        }
        Err(FlagError::Bad(m)) => {
            let _ = writeln!(stderr, "{m}");
            let _ = stderr.write_all(USAGE.as_bytes());
            return 64;
        }
    };
    let facts = if !f.is_set("facts") {
        "on".to_owned()
    } else {
        f.str("facts")
    };
    if !matches!(facts.as_str(), "on" | "off" | "both") {
        let _ = writeln!(
            stderr,
            "callguard eval: --facts must be on, off or both, not {facts:?}"
        );
        return 64;
    }
    let fail = |stderr: &mut dyn Write, msg: String| {
        let _ = writeln!(stderr, "callguard eval: {msg}");
        1
    };

    let data = match f.str("cases").as_str() {
        "" => evals::CASES.to_vec(),
        path => match std::fs::read(path) {
            Ok(d) => d,
            Err(e) => return fail(stderr, e.to_string()),
        },
    };
    let mut cases = match evalrun::parse_cases(&data) {
        Ok(c) => c,
        Err(e) => return fail(stderr, format!("cases: {e}")),
    };
    let bucket = f.str("bucket");
    if !bucket.is_empty() {
        cases.retain(|c| c.bucket == bucket);
        if cases.is_empty() {
            return fail(stderr, format!("no cases in bucket {bucket:?}"));
        }
    }

    let policy_path = f.str("policy");
    let llm_timeout = f.int("llm-timeout-ms", 0);
    // The eval never probes git or gh: cases carry the meta they need.
    let load_opts = |omit_facts: bool, backend: Option<Arc<dyn Backend>>| engine::LoadOptions {
        system_policy: policy_path.clone(),
        user_config_dir: "-".into(),
        options: engine::Options {
            log_path: "-".into(),
            no_host_meta: true,
            llm_timeout_ms: llm_timeout,
            omit_facts,
            backend,
            ..Default::default()
        },
        ..Default::default()
    };
    let (b, key_env) = match choose_backend(&f.str("backend"), &load_opts) {
        Ok(x) => x,
        Err(e) => return fail(stderr, e),
    };
    if !key_env.is_empty() && std::env::var(&key_env).unwrap_or_default().is_empty() {
        return fail(
            stderr,
            format!("{key_env} is not set; the eval needs it for the anthropic backend"),
        );
    }

    // Decides the set once. A fresh meter per run keeps the usage apart; the
    // cap is what is left of --max-usd.
    let concurrency = usize::try_from(f.int("concurrency", 4)).unwrap_or(0).max(1);
    let run_once = |with_facts: bool, cap_usd: f64| -> Result<Report, String> {
        let meter = b.as_ref().map(|b| Arc::new(Meter::new(b.clone(), cap_usd)));
        let backend = meter.clone().map(|m| m as Arc<dyn Backend>);
        let eng = Engine::load(load_opts(!with_facts, backend))
            .map_err(|e| format!("loading policy: {e}"))?;
        let decide = |r: &Request| eng.decide(r);
        let stop_meter = meter.clone();
        let stop = move || stop_meter.as_ref().is_some_and(|m| m.stop());
        let stop_fn: Option<&(dyn Fn() -> bool + Sync)> = meter.as_ref().map(|_| &stop as _);
        let mut rep = evalrun::run(&cases, &decide, concurrency, stop_fn);
        if let Some(m) = &meter {
            rep.usage = Some(m.usage(rep.llm_cases));
        }
        Ok(rep)
    };

    let max_usd = f.float("max-usd", 1.0);
    let first = match run_once(facts != "off", max_usd) {
        Ok(r) => r,
        Err(e) => return fail(stderr, e),
    };
    let mut second = None;
    if facts == "both" {
        let mut remaining = max_usd;
        if remaining > 0.0
            && let Some(u) = &first.usage
        {
            // Never "no cap" by accident.
            remaining = (remaining - u.est_usd).max(1e-9);
        }
        second = match run_once(false, remaining) {
            Ok(r) => Some(r),
            Err(e) => return fail(stderr, e),
        };
    }

    if f.bool("json") {
        let text = match &second {
            Some(second) => gojson::to_string_indent(&serde_json::json!({
                "facts_on": first,
                "facts_off": second,
            })),
            None => gojson::to_string_indent(&first),
        };
        return match text {
            Ok(t) => {
                let _ = writeln!(stdout, "{t}");
                0
            }
            Err(e) => fail(stderr, e.to_string()),
        };
    }
    if let Some(b) = &b {
        let _ = writeln!(stdout, "backend: {}", b.name());
    }
    if let Some(second) = &second {
        let _ = write!(stdout, "\n== facts on ==\n");
        let _ = first.write_text(stdout);
        let _ = write!(stdout, "\n== facts off ==\n");
        let _ = second.write_text(stdout);
        let _ = write!(stdout, "\n== comparison ==\n");
        let _ = evalrun::write_comparison(stdout, "facts on", &first, "facts off", second);
        return 0;
    }
    let _ = writeln!(stdout);
    let _ = first.write_text(stdout);
    0
}

/// Resolves --backend: fake / fake:<mode> and anthropic / anthropic:<model>
/// need no policy entry, any other name is looked up in the policy's backends.
/// With no --backend it is the policy's llm backend, if that can be built
/// (otherwise the engine reports the problem per case, as before). The second
/// value is the API key variable an anthropic backend needs, "" otherwise.
fn choose_backend(
    name: &str,
    load_opts: &dyn Fn(bool, Option<Arc<dyn Backend>>) -> engine::LoadOptions,
) -> Result<(Option<Arc<dyn Backend>>, String), String> {
    if name == "fake" || name.starts_with("fake:") {
        let mode = name.strip_prefix("fake").unwrap_or("");
        let mode = mode.strip_prefix(':').unwrap_or(mode);
        let b = backend::new_fake(mode).map_err(|e| e.to_string())?;
        return Ok((Some(Arc::from(b)), String::new()));
    }
    // No backend override: only to read the policy.
    let probe = Engine::load(load_opts(false, None)).map_err(|e| format!("loading policy: {e}"))?;
    let pol = probe.policy();
    let explicit = !name.is_empty();
    let name = if explicit {
        name.to_owned()
    } else {
        pol.llm
            .as_ref()
            .map(|l| l.backend.clone())
            .unwrap_or_default()
    };
    let model = name.strip_prefix("anthropic:");
    let cfg: policy::Backend = if model.is_some() || name == "anthropic" {
        let mut cfg = pol.backends.get("anthropic").cloned().unwrap_or_default();
        cfg.r#type = "anthropic".into();
        if let Some(m) = model.filter(|m| !m.is_empty()) {
            cfg.model = m.to_owned();
        }
        cfg
    } else if let Some(c) = pol.backends.get(&name) {
        c.clone()
    } else if explicit {
        return Err(format!(
            "backend {name:?} is not defined in the policy's backends"
        ));
    } else {
        return Ok((None, String::new()));
    };
    let b = match backend::from_config(&cfg) {
        Ok(b) => b,
        Err(e) if explicit => return Err(e.to_string()),
        Err(_) => return Ok((None, String::new())),
    };
    let key_env = if cfg.r#type == "anthropic" {
        if cfg.api_key_env.is_empty() {
            "ANTHROPIC_API_KEY".to_owned()
        } else {
            cfg.api_key_env.clone()
        }
    } else {
        String::new()
    };
    Ok((Some(Arc::from(b)), key_env))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run_cmd(args: &[&str]) -> (i32, String, String) {
        let args: Vec<String> = args.iter().map(|s| (*s).to_owned()).collect();
        let (mut out, mut err) = (Vec::new(), Vec::new());
        let code = run(&args, &mut out, &mut err);
        (
            code,
            String::from_utf8(out).unwrap(),
            String::from_utf8(err).unwrap(),
        )
    }

    #[test]
    fn missing_cases_file_is_a_setup_error() {
        let (code, _, err) = run_cmd(&["--cases", "does-not-exist.jsonl"]);
        assert!(
            code == 1 && err.contains("callguard eval:"),
            "{code} {err:?}"
        );
    }

    #[test]
    fn bad_flags_exit_64() {
        assert_eq!(run_cmd(&["--no-such-flag"]).0, 64);
        assert_eq!(run_cmd(&["--facts", "maybe"]).0, 64);
        assert_eq!(run_cmd(&["--concurrency", "x"]).0, 64);
    }

    #[test]
    #[ignore = "needs other chunk"]
    fn setup_errors() {
        for (name, args) in [
            ("unknown bucket", vec!["--bucket", "no-such-bucket"]),
            ("unknown fake mode", vec!["--backend", "fake:bogus"]),
        ] {
            let (code, _, err) = run_cmd(&args);
            assert!(
                code == 1 && err.contains("callguard eval:"),
                "{name}: code {code}, stderr {err:?}"
            );
        }
    }

    #[test]
    #[ignore = "needs other chunk"]
    fn anthropic_needs_key() {
        // ANTHROPIC_API_KEY must be unset for this test (it cannot be cleared
        // from safe Rust).
        if std::env::var("ANTHROPIC_API_KEY").is_ok_and(|k| !k.is_empty()) {
            return;
        }
        for name in ["anthropic", "anthropic:claude-haiku-5-5", ""] {
            let (code, out, err) = run_cmd(&["--backend", name, "--bucket", "benign"]);
            assert!(
                code == 1
                    && err.contains(
                        "ANTHROPIC_API_KEY is not set; the eval needs it for the anthropic backend"
                    )
                    && out.is_empty(),
                "{name:?}: code {code}, stdout {out:?}, stderr {err:?}"
            );
        }
    }

    #[test]
    #[ignore = "needs other chunk"]
    fn facts_modes() {
        for mode in ["on", "off", "both"] {
            let (code, out, err) =
                run_cmd(&["--backend", "fake", "--bucket", "benign", "--facts", mode]);
            assert!(
                code == 0
                    && out.contains("llm usage:")
                    && out.contains("== comparison ==") == (mode == "both"),
                "{mode}: code {code}, stderr {err:?}\n{out}"
            );
        }
        let (code, out, _) = run_cmd(&[
            "--backend",
            "fake",
            "--bucket",
            "benign",
            "--facts",
            "both",
            "--json",
        ]);
        assert!(
            code == 0 && out.contains("\"facts_on\"") && out.contains("\"facts_off\""),
            "json both: code {code}\n{out}"
        );
    }
}
