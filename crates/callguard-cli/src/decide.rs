//! `callguard decide`: request JSON on stdin, verdict JSON on stdout. Exit
//! codes: 0 allow, 1 deny, 2 ask, 3 bad request or policy error (a fallback
//! verdict is still printed), 64 bad flags.

use std::io::{Read, Write};

use callguard::engine::{self, Engine};
use callguard::fallback::fallback_verdict;
use callguard::gojson;
use callguard::schema::{Decision, Request};

use crate::flags::{self, FlagError, Kind, spec};

const MAX_REQUEST_BYTES: usize = 4 << 20;

const USAGE: &str = "usage: callguard decide [flags]

Flags:
  --policy FILE       system policy file (default: the platform path)
  --no-user-policy    skip the user policy layer
  --log PATH          decision log path, or - to disable
  --unattended        no human can answer a prompt
";

pub fn run(
    args: &[String],
    stdin: &mut dyn Read,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> i32 {
    let f = match flags::parse(
        &[
            spec("policy", Kind::Str),
            spec("no-user-policy", Kind::Bool),
            spec("log", Kind::Str),
            spec("unattended", Kind::Bool),
        ],
        args,
    ) {
        Ok(f) => f,
        Err(e) => {
            if let FlagError::Bad(m) = e {
                let _ = writeln!(stderr, "{m}");
            }
            let _ = stderr.write_all(USAGE.as_bytes());
            return 64;
        }
    };
    let unattended = f.bool("unattended");

    let fail = |req: &Request, stdout: &mut dyn Write, cause: &str| {
        let req = Request {
            unattended: req.unattended || unattended,
            ..Default::default()
        };
        print_json(stdout, &fallback_verdict(Some(&req), cause));
        3
    };
    let mut data = Vec::new();
    if let Err(e) = stdin
        .take(MAX_REQUEST_BYTES as u64 + 1)
        .read_to_end(&mut data)
    {
        return fail(
            &Request::default(),
            stdout,
            &format!("cannot read the request: {e}"),
        );
    }
    if data.len() > MAX_REQUEST_BYTES {
        return fail(
            &Request::default(),
            stdout,
            &format!("request is larger than {MAX_REQUEST_BYTES} bytes"),
        );
    }
    // A derived Deserialize would also take a JSON array as a field list.
    let is_object = data.iter().find(|b| !b.is_ascii_whitespace()) == Some(&b'{');
    let parsed = if is_object {
        serde_json::from_slice::<Request>(&data).map_err(|e| e.to_string())
    } else {
        Err("request is not a JSON object".to_owned())
    };
    let mut req = match parsed {
        Ok(r) => r,
        Err(e) => {
            return fail(
                &Request::default(),
                stdout,
                &format!("bad request JSON: {e}"),
            );
        }
    };
    if unattended {
        req.unattended = true;
    }
    if req.tool.name.is_empty() {
        return fail(&req, stdout, "request has no tool.name");
    }

    let lo = engine::LoadOptions {
        system_policy: f.str("policy"),
        project_dir: engine::resolve_project_dir(&req),
        user_config_dir: if f.bool("no-user-policy") {
            "-".into()
        } else {
            String::new()
        },
        options: engine::Options {
            log_path: f.str("log"),
            ..Default::default()
        },
    };
    let eng = match Engine::load(lo) {
        Ok(e) => e,
        Err(e) => return fail(&req, stdout, &format!("policy: {e}")),
    };
    let v = eng.decide(&req);
    print_json(stdout, &v);
    match v.decision {
        Decision::Allow => 0,
        Decision::Deny => 1,
        Decision::Ask => 2,
    }
}

fn print_json<T: serde::Serialize>(w: &mut dyn Write, v: &T) {
    let b = gojson::to_string(v).unwrap_or_default();
    let _ = writeln!(w, "{b}");
}

#[cfg(test)]
mod tests {
    use callguard::schema::{VERDICT_SCHEMA, Verdict};

    use super::*;

    fn run_cmd(stdin: &str, args: &[&str]) -> (i32, String, String) {
        let args: Vec<String> = args.iter().map(|s| (*s).to_owned()).collect();
        let (mut out, mut err) = (Vec::new(), Vec::new());
        let code = run(&args, &mut stdin.as_bytes(), &mut out, &mut err);
        (
            code,
            String::from_utf8(out).unwrap(),
            String::from_utf8(err).unwrap(),
        )
    }

    fn write_file(dir: &std::path::Path, name: &str, content: &str) -> String {
        let p = dir.join(name);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(&p, content).unwrap();
        p.to_string_lossy().into_owned()
    }

    fn req_json(
        dir: &std::path::Path,
        tool: &str,
        input: serde_json::Value,
        extra: serde_json::Value,
    ) -> String {
        let dir = dir.to_string_lossy();
        let mut m = serde_json::json!({
            "schema": "callguard/request/v1", "v": 1, "harness": "claude", "session_id": "s",
            "cwd": dir, "project_dir": dir, "tool": {"name": tool, "input": input}
        });
        if let Some(extra) = extra.as_object() {
            for (k, v) in extra {
                m[k] = v.clone();
            }
        }
        m.to_string()
    }

    // The cases that fail before the policy loads run on their own.

    #[test]
    fn bad_requests_get_a_fallback_verdict_and_exit_3() {
        let cases: Vec<(&str, String, Vec<&str>, &str)> = vec![
            ("bad json", "{not json".into(), vec![], "ask"),
            (
                "bad json unattended",
                String::new(),
                vec!["--unattended"],
                "deny",
            ),
            ("array", "[]".into(), vec![], "ask"),
            ("no tool", r#"{"cwd":"/x"}"#.into(), vec![], "ask"),
            (
                "oversized",
                format!(
                    r#"{{"tool":{{"name":"Bash"}},"pad":"{}"}}"#,
                    "x".repeat(4 << 20)
                ),
                vec![],
                "ask",
            ),
        ];
        for (name, stdin, extra, decision) in cases {
            let mut args = vec!["--policy", "unused.json", "--no-user-policy", "--log", "-"];
            args.extend(extra);
            let (code, out, errs) = run_cmd(&stdin, &args);
            let v: Verdict = serde_json::from_str(&out).unwrap_or_else(|e| {
                panic!("{name}: stdout is not a verdict: {out:?} ({e}) stderr {errs:?}")
            });
            assert!(out.ends_with('\n'), "{name}: {out:?}");
            assert!(
                code == 3
                    && v.decision.as_str() == decision
                    && v.layer == "fallback"
                    && v.schema == VERDICT_SCHEMA,
                "{name}: exit {code} verdict {v:?}"
            );
        }
    }

    #[test]
    fn bad_flags_exit_64() {
        let req = req_json(
            std::path::Path::new("/w"),
            "Read",
            serde_json::json!({"file_path": "a.go"}),
            serde_json::json!({}),
        );
        assert_eq!(run_cmd(&req, &["--bogus"]).0, 64);
        assert_eq!(run_cmd(&req, &["-h"]).0, 64);
        assert_eq!(run_cmd(&req, &["--policy"]).0, 64);
    }

    // The cases below load the policy and run the pipeline, which the other
    // chunk (policy, rules, engine) ports.

    #[test]
    #[ignore = "needs other chunk"]
    fn decide_exit_codes() {
        let dir = tempfile::tempdir().unwrap();
        // LLM off so that nothing needs a backend.
        let pol = write_file(
            dir.path(),
            "sys.json",
            r#"{"policy_version":1,"llm":{"enabled":false}}"#,
        );
        let base = ["--policy", pol.as_str(), "--no-user-policy", "--log", "-"];
        let d = dir.path();
        let git_push = || {
            req_json(
                d,
                "Bash",
                serde_json::json!({"command": "git push --force"}),
                serde_json::json!({}),
            )
        };
        type Case<'a> = (&'a str, String, Vec<&'a str>, i32, &'a str, &'a str);
        let cases: Vec<Case> = vec![
            (
                "allow",
                req_json(
                    d,
                    "Read",
                    serde_json::json!({"file_path": "a.go"}),
                    serde_json::json!({}),
                ),
                vec![],
                0,
                "allow",
                "rules",
            ),
            (
                "deny",
                req_json(
                    d,
                    "Bash",
                    serde_json::json!({"command": "rm -rf /"}),
                    serde_json::json!({}),
                ),
                vec![],
                1,
                "deny",
                "builtin",
            ),
            ("ask", git_push(), vec![], 2, "ask", "rules"),
            (
                "none is ask",
                req_json(
                    d,
                    "Bash",
                    serde_json::json!({"command": "go test"}),
                    serde_json::json!({}),
                ),
                vec![],
                2,
                "ask",
                "none",
            ),
            (
                "unattended flag",
                git_push(),
                vec!["--unattended"],
                1,
                "deny",
                "rules",
            ),
            (
                "unattended in request",
                req_json(
                    d,
                    "Bash",
                    serde_json::json!({"command": "git push --force"}),
                    serde_json::json!({"unattended": true}),
                ),
                vec![],
                1,
                "deny",
                "rules",
            ),
        ];
        for (name, stdin, extra, code, dec, layer) in cases {
            let mut args = base.to_vec();
            args.extend(extra);
            let (c, out, errs) = run_cmd(&stdin, &args);
            let v: Verdict = serde_json::from_str(&out).unwrap_or_else(|e| {
                panic!("{name}: stdout is not one JSON line: {out:?} ({e}) stderr {errs:?}")
            });
            assert!(
                c == code
                    && v.decision.as_str() == dec
                    && v.layer == layer
                    && v.schema == VERDICT_SCHEMA,
                "{name}: exit {c} verdict {v:?}, want exit {code} {dec}/{layer}"
            );
        }
    }

    #[test]
    #[ignore = "needs other chunk"]
    fn decide_load_errors() {
        let dir = tempfile::tempdir().unwrap();
        let req = req_json(
            dir.path(),
            "Read",
            serde_json::json!({"file_path": "a.go"}),
            serde_json::json!({}),
        );
        let missing = dir.path().join("missing.json");
        let (code, out, _) = run_cmd(
            &req,
            &[
                "--policy",
                missing.to_str().unwrap(),
                "--no-user-policy",
                "--log",
                "-",
            ],
        );
        assert!(
            code == 3
                && out.contains(r#""layer":"fallback""#)
                && out.contains(r#""decision":"ask""#),
            "{code} {out}"
        );
        let bad = write_file(dir.path(), "bad.json", r#"{"policy_version":9}"#);
        let (code, out, _) = run_cmd(
            &req,
            &[
                "--policy",
                &bad,
                "--no-user-policy",
                "--log",
                "-",
                "--unattended",
            ],
        );
        assert!(
            code == 3 && out.contains(r#""decision":"deny""#),
            "{code} {out}"
        );
        assert_eq!(run_cmd(&req, &["--bogus"]).0, 64);
    }

    #[test]
    #[ignore = "needs other chunk"]
    fn decide_uses_project_policy_and_log() {
        let dir = tempfile::tempdir().unwrap();
        let pol = write_file(
            dir.path(),
            "sys.json",
            r#"{"policy_version":1,"llm":{"enabled":false}}"#,
        );
        write_file(
            dir.path(),
            ".callguard/policy.json",
            r#"{"policy_version":1,"rules":[{"id":"no-make","decision":"deny","description":"no make","match":{"kind":["shell"],"command":"^make"}}]}"#,
        );
        let logp = dir.path().join("d.jsonl");
        let (code, out, _) = run_cmd(
            &req_json(
                dir.path(),
                "Bash",
                serde_json::json!({"command": "make all"}),
                serde_json::json!({}),
            ),
            &[
                "--policy",
                &pol,
                "--no-user-policy",
                "--log",
                logp.to_str().unwrap(),
            ],
        );
        assert!(
            code == 1 && out.contains(r#""rule":"no-make""#),
            "project rule: {code} {out}"
        );
        let log = std::fs::read_to_string(&logp).unwrap();
        assert!(log.contains(r#""rule":"no-make""#), "log: {log}");
    }
}
