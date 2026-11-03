//! `callguard policy check`.

use std::collections::HashSet;
use std::io::Write;

use callguard::gojson;
use callguard::policy::{self, LoadOptions, Policy};
use callguard::rules::{Env, Set};
use serde::Serialize;

use crate::flags::{self, Kind, spec};

const USAGE: &str = "usage: callguard policy check [--policy file] [--project-dir dir] [--no-user-policy] [--json]\n";

/// `callguard policy check`.
pub fn run(args: &[String], stdout: &mut dyn Write, stderr: &mut dyn Write) -> i32 {
    if args.first().map(String::as_str) != Some("check") {
        let _ = stderr.write_all(USAGE.as_bytes());
        return 64;
    }
    let f = match flags::parse(
        &[
            spec("policy", Kind::Str),
            spec("project-dir", Kind::Str),
            spec("no-user-policy", Kind::Bool),
            spec("json", Kind::Bool),
        ],
        &args[1..],
    ) {
        Ok(f) => f,
        Err(e) => {
            if let flags::FlagError::Bad(m) = e {
                let _ = writeln!(stderr, "{m}");
            }
            let _ = stderr.write_all(USAGE.as_bytes());
            return 64;
        }
    };
    let lo = LoadOptions {
        system_policy: f.str("policy"),
        project_dir: f.str("project-dir"),
        user_config_dir: if f.bool("no-user-policy") {
            "-".into()
        } else {
            String::new()
        },
    };
    let rep = check_policy(&lo);
    if f.bool("json") {
        let b = gojson::to_string_indent(&rep).unwrap_or_default();
        let _ = writeln!(stdout, "{b}");
    } else {
        rep.print(stdout);
    }
    i32::from(!rep.errors.is_empty())
}

#[derive(Serialize)]
struct PolicyReport {
    files: Vec<String>,
    #[serde(skip_serializing_if = "String::is_empty")]
    policy_rev: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    policy: Option<Policy>,
    warnings: Vec<String>,
    errors: Vec<String>,
}

fn check_policy(lo: &LoadOptions) -> PolicyReport {
    let mut rep = PolicyReport {
        files: Vec::new(),
        policy_rev: String::new(),
        policy: None,
        warnings: Vec::new(),
        errors: Vec::new(),
    };
    let l = match policy::load(lo) {
        Ok(l) => l,
        Err(e) => {
            rep.errors.push(e.to_string());
            return rep;
        }
    };
    let mut seen = HashSet::new();
    for f in &l.files {
        rep.files.push(format!("{} ({})", f.path, f.layer));
        for k in &f.unknown {
            rep.errors.push(format!("{}: unknown key {k:?}", f.path));
        }
        for p in &f.problems {
            seen.insert(p.clone());
            rep.errors.push(format!("{}: {p}", f.path));
        }
    }
    for p in policy::validate(&l.policy, true) {
        if !seen.contains(&p) {
            rep.errors.push(format!("merged policy: {p}"));
        }
    }
    let env = Env::host();
    for r in &l.policy.rules {
        if let Err(e) = Set::compile(std::slice::from_ref(r), &env) {
            rep.errors.push(e.to_string());
        }
    }
    rep.warnings.extend(l.warnings);
    rep.policy_rev = policy::rev(&l.policy);
    rep.policy = Some(l.policy);
    rep
}

impl PolicyReport {
    fn print(&self, w: &mut dyn Write) {
        let _ = writeln!(w, "files read:");
        if self.files.is_empty() {
            let _ = writeln!(w, "  (none: built-in defaults only)");
        }
        for f in &self.files {
            let _ = writeln!(w, "  {f}");
        }
        if let Some(p) = &self.policy {
            let b = gojson::to_string_indent(p).unwrap_or_default();
            let _ = writeln!(w, "merged policy:\n{b}\npolicy_rev: {}", self.policy_rev);
        }
        for x in &self.warnings {
            let _ = writeln!(w, "warning: {x}");
        }
        for x in &self.errors {
            let _ = writeln!(w, "error: {x}");
        }
        if self.errors.is_empty() {
            let _ = writeln!(w, "ok");
        }
    }
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

    fn write_file(dir: &std::path::Path, name: &str, content: &str) -> String {
        let p = dir.join(name);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(&p, content).unwrap();
        p.to_string_lossy().into_owned()
    }

    #[test]
    fn usage_errors_exit_64() {
        for args in [vec!["policy"], vec!["frob"]] {
            let (code, _, errs) = run_cmd(&args);
            assert!(
                code == 64 && errs.contains("usage"),
                "{args:?}: {code} {errs:?}"
            );
        }
        assert_eq!(run_cmd(&["check", "--nope"]).0, 64);
    }

    #[test]
    fn policy_check() {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path();
        let ok = write_file(d, "ok.json", r#"{"policy_version":1}"#);
        let (code, out, _) = run_cmd(&["check", "--policy", &ok, "--no-user-policy"]);
        assert!(
            code == 0
                && out.contains("policy_rev: sha256:")
                && out.contains("read-in-project")
                && out.trim().ends_with("ok"),
            "ok: {code} {out}"
        );

        let bad = write_file(
            d,
            "bad.json",
            r#"{"policy_version":1,"bogus":1,
		"rules":[{"id":"nocond","decision":"ask"},{"id":"re","decision":"ask","match":{"command":"("}},
		{"id":"glob","decision":"ask","match":{"path":["[x"]}},{"id":"dec","decision":"maybe","match":{"kind":["shell"]}}],
		"llm":{"backend":"ghost"},
		"backends":{"m":{"type":"anthropic","model":"claude-haiku-latest"},"w":{"type":"weird"}}}"#,
        );
        let proj = d.join("proj");
        write_file(
            &proj,
            ".callguard/policy.json",
            r#"{"policy_version":1,"mode":"shadow"}"#,
        );
        let (code, out, _) = run_cmd(&[
            "check",
            "--policy",
            &bad,
            "--no-user-policy",
            "--project-dir",
            proj.to_str().unwrap(),
        ]);
        assert_eq!(code, 1, "bad policy exit");
        for want in [
            "unknown key \"bogus\"",
            "no match conditions",
            "match.command",
            "match.path",
            "decision \"maybe\"",
            "llm.backend \"ghost\"",
            "moving alias",
            "unknown type \"weird\"",
            "warning: ",
            "mode ignored",
            "proj",
        ] {
            assert!(out.contains(want), "missing {want:?} in:\n{out}");
        }

        let (code, out, _) = run_cmd(&["check", "--json", "--policy", &bad, "--no-user-policy"]);
        let rep: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert!(
            code == 1
                && rep["errors"].as_array().unwrap().len() >= 6
                && rep["files"].as_array().unwrap().len() == 1
                && rep["policy"].is_object(),
            "json report: {code} {out}"
        );

        let ok2 = write_file(d, "ok2.json", r#"{"policy_version":1}"#);
        let (code, out, _) = run_cmd(&["check", "--json", "--policy", &ok2, "--no-user-policy"]);
        let rep: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert!(
            code == 0
                && rep["errors"].as_array().unwrap().is_empty()
                && !rep["policy_rev"].as_str().unwrap().is_empty(),
            "json ok: {code} {out}"
        );

        let missing = d.join("missing.json");
        let (code, out, _) = run_cmd(&[
            "check",
            "--policy",
            missing.to_str().unwrap(),
            "--no-user-policy",
        ]);
        assert!(
            code == 1 && out.contains("error:"),
            "missing file: {code} {out}"
        );
        let v3 = write_file(d, "v.json", r#"{"policy_version":3}"#);
        assert_eq!(
            run_cmd(&["check", "--policy", &v3, "--no-user-policy"]).0,
            1,
            "bad version"
        );
    }
}
