//! Differential test: the last Go binary against the Rust binary, over
//! evals/cases.jsonl and every internal/hook/testdata fixture. Ignored until
//! the port lands; run with `cargo test -p callguard-cli --test differential
//! -- --ignored`.
//!
//! Both binaries run with a scrubbed environment: PATH holds an empty
//! directory (so no `nah`, no `git`), HOME and the config/state dirs are a
//! fresh temp dir, and the system policy file names no `nah.path`. The judge
//! is the fake backend, so the `judge` bucket (which only a real model can
//! decide) is skipped.

use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use serde_json::Value;

/// Listed expected differences: (case or fixture id, why). Empty until a
/// difference is understood and accepted.
/// Known so far: serde_json refuses JSON nested deeper than 128 levels, Go
/// accepts it; the Rust side takes the fail-safe path.
const EXPECTED_DIFFERENCES: &[(&str, &str)] = &[];

const POLICY: &str =
    r#"{"policy_version":1,"llm":{"backend":"fake"},"backends":{"fake":{"type":"fake"}}}"#;

struct Sandbox {
    _dir: tempfile::TempDir,
    empty_path: PathBuf,
    home: PathBuf,
    policy: PathBuf,
}

impl Sandbox {
    fn new() -> Sandbox {
        let dir = tempfile::tempdir().unwrap();
        let empty_path = dir.path().join("emptybin");
        let home = dir.path().join("home");
        std::fs::create_dir_all(&empty_path).unwrap();
        std::fs::create_dir_all(&home).unwrap();
        let policy = dir.path().join("policy.json");
        std::fs::write(&policy, POLICY).unwrap();
        Sandbox {
            _dir: dir,
            empty_path,
            home,
            policy,
        }
    }

    fn command(&self, bin: &Path) -> Command {
        let mut c = Command::new(bin);
        c.env_clear()
            .env("PATH", &self.empty_path)
            .env("HOME", &self.home)
            .env("USERPROFILE", &self.home)
            .env("APPDATA", self.home.join("AppData/Roaming"))
            .env("LOCALAPPDATA", self.home.join("AppData/Local"))
            .env("XDG_CONFIG_HOME", self.home.join(".config"))
            .env("XDG_STATE_HOME", self.home.join(".state"));
        // Windows needs these to start a process and to find system DLLs.
        for k in ["SystemRoot", "SYSTEMROOT", "windir", "TEMP", "TMP"] {
            if let Ok(v) = std::env::var(k) {
                c.env(k, v);
            }
        }
        c
    }

    fn run(&self, bin: &Path, args: &[&str], stdin: &str) -> (i32, String) {
        let mut child = self
            .command(bin)
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(stdin.as_bytes())
            .unwrap();
        let out = child.wait_with_output().unwrap();
        (
            out.status.code().unwrap_or(-1),
            String::from_utf8_lossy(&out.stdout).into_owned(),
        )
    }
}

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap()
}

fn build_go(out_dir: &Path) -> PathBuf {
    let exe = out_dir.join(if cfg!(windows) {
        "callguard-go.exe"
    } else {
        "callguard-go"
    });
    let status = Command::new("go")
        .args(["build", "-o"])
        .arg(&exe)
        .arg("./cmd/callguard")
        .current_dir(repo_root())
        .status()
        .expect("go is on PATH");
    assert!(status.success(), "go build failed");
    exe
}

/// Drops the fields that differ on every run.
fn scrub(v: &mut Value) {
    match v {
        Value::Object(m) => {
            for k in ["id", "latency_ms"] {
                m.remove(k);
            }
            m.values_mut().for_each(scrub);
        }
        Value::Array(a) => a.iter_mut().for_each(scrub),
        _ => {}
    }
}

/// What is compared for one run: decision, layer and rule of a verdict (or the
/// whole scrubbed output for a hook answer) plus the exit code.
fn summarize(code: i32, stdout: &str) -> Value {
    let mut v: Value = serde_json::from_str(stdout.trim()).unwrap_or(Value::String(stdout.into()));
    scrub(&mut v);
    serde_json::json!({ "exit": code, "out": v })
}

fn verdict_summary(code: i32, stdout: &str) -> Value {
    let v: Value = serde_json::from_str(stdout.trim()).unwrap_or(Value::Null);
    serde_json::json!({
        "exit": code,
        "decision": v["decision"], "layer": v["layer"], "rule": v["rule"],
    })
}

fn expected_difference(id: &str) -> Option<&'static str> {
    EXPECTED_DIFFERENCES
        .iter()
        .find(|(i, _)| *i == id)
        .map(|(_, why)| *why)
}

#[test]
#[ignore = "until the Rust port lands"]
fn go_and_rust_agree() {
    let sb = Sandbox::new();
    let tmp = tempfile::tempdir().unwrap();
    let go = build_go(tmp.path());
    let rust = PathBuf::from(env!("CARGO_BIN_EXE_callguard"));
    let policy = sb.policy.to_str().unwrap();
    let mut diffs: BTreeMap<String, (Value, Value)> = BTreeMap::new();

    // decide over the eval set
    let cases = std::fs::read_to_string(repo_root().join("evals/cases.jsonl")).unwrap();
    let decide_args = [
        "decide",
        "--policy",
        policy,
        "--no-user-policy",
        "--log",
        "-",
    ];
    let mut compared = 0;
    for line in cases
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with("//"))
    {
        let case: Value = serde_json::from_str(line).unwrap();
        if case["bucket"] == "judge" {
            continue; // only a language model can decide these
        }
        let id = case["id"].as_str().unwrap().to_owned();
        let req = serde_json::to_string(&case["request"]).unwrap();
        let (gc, go_out) = sb.run(&go, &decide_args, &req);
        let (rc, rust_out) = sb.run(&rust, &decide_args, &req);
        let (a, b) = (verdict_summary(gc, &go_out), verdict_summary(rc, &rust_out));
        compared += 1;
        if a != b && expected_difference(&id).is_none() {
            diffs.insert(format!("case {id}"), (a, b));
        }
    }

    // every hook fixture
    let dir = repo_root().join("internal/hook/testdata");
    let mut fixtures: Vec<_> = std::fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .collect();
    fixtures.sort();
    for path in fixtures {
        let name = path.file_name().unwrap().to_str().unwrap().to_owned();
        let harness = name.split('_').next().unwrap();
        let body = std::fs::read_to_string(&path).unwrap();
        let args = [
            "hook",
            harness,
            "--policy",
            policy,
            "--no-user-policy",
            "--log",
            "-",
        ];
        let (gc, go_out) = sb.run(&go, &args, &body);
        let (rc, rust_out) = sb.run(&rust, &args, &body);
        let (a, b) = (summarize(gc, &go_out), summarize(rc, &rust_out));
        compared += 1;
        if a != b && expected_difference(&name).is_none() {
            diffs.insert(format!("fixture {name}"), (a, b));
        }
    }

    assert!(compared > 50, "only {compared} comparisons ran");
    assert!(
        diffs.is_empty(),
        "unexplained differences (go, rust):\n{}",
        diffs
            .iter()
            .map(|(k, (a, b))| format!("{k}\n  go:   {a}\n  rust: {b}"))
            .collect::<Vec<_>>()
            .join("\n")
    );
}
