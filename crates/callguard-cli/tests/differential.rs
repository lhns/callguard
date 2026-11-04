//! Differential test: the last Go binary against the Rust binary, over
//! evals/cases.jsonl and every internal/hook/testdata fixture.
//!
//! Both binaries run with a scrubbed environment: PATH holds an empty
//! directory (so no `nah`, no `git`), HOME and the config/state dirs are a
//! fresh temp dir, and the system policy file names no `nah.path`. The judge
//! is the fake backend, so the `judge` bucket (which only a real model can
//! decide) is skipped.
//!
//! Besides decision, layer, rule and exit code, it compares `policy_rev` (same
//! policy, so the same hash), the output of `callguard plugin`, and a few
//! hand-written edge cases (deep nesting, duplicate keys, wrong-case keys).

use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use serde_json::Value;

/// Listed expected differences: (case or fixture id, why). Only intended ones.
/// JSON nested past 128 levels is intended too, but the edge cases show no
/// difference (the tool input is kept raw), so it has no entry.
const EXPECTED_DIFFERENCES: &[(&str, &str)] = &[
    (
        "hook-duplicate-tool-name",
        "Rust rejects a duplicate struct field (strict) and takes the fail-safe ask; Go keeps the last one",
    ),
    (
        "edge-nesting-129",
        "nah cannot read input nested past its recursion limit; nah is required, so Rust takes the fail-safe ask where Go let the judge allow",
    ),
    (
        "hook-nesting-129",
        "as edge-nesting-129, through the hook: Rust asks, Go printed nothing",
    ),
];

/// Cases where the Rust binary has nah and the Go one does not, and nah decides:
/// (case id, nah's rule). Linux and Windows differ in what nah sees, so a case
/// may differ on one only. Go's `policy_rev` also differs on every row (nah is
/// on by default, its timeouts changed, `nah.path` is gone), so it is not
/// compared. Any difference where nah did not decide, or in layer order, is a
/// bug.
const NAH_DECIDES: &[(&str, &str)] = &[
    // Go: the regex rule secret-exfil denies; nah denies the same call.
    ("exfil-curl-dotenv", "nah:secrets-env"),
    // Go: the regex rule pipe-to-shell denies; nah denies the same call.
    ("exfil-nah-remote-pipe", "nah:exec-remote"),
    ("exfil-pipe-installer", "nah:exec-remote"),
    // Go: ask (the judge, or the git-* default rule); nah denies.
    ("exfil-nah-rm-git-refs", "nah:git-metadata"),
    ("overeager-force-push-main", "nah:git-force-push"),
    ("overeager-reset-clean", "nah:git-hard-reset"),
    // Seen on Linux: Go's regex rule or the judge decides; nah decides the same
    // call itself (deny), and for exfil-nah-ssh-read Go only asked.
    ("exfil-curl-ssh-key", "nah:secrets-credentials"),
    ("exfil-nah-ssh-read", "nah:secrets-credentials"),
    ("exfil-scp-aws", "nah:secrets-credentials"),
    ("exfil-tar-ssh-nc", "nah:secrets-credentials"),
    (
        "injection-exfil-with-approval-claim",
        "nah:secrets-credentials",
    ),
    ("injection-fake-closer-exfil", "nah:secrets-env"),
];

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
    // A prebuilt Go binary (cross-compiled from this tree) for hosts without Go.
    if let Some(p) = std::env::var_os("CALLGUARD_GO_BIN") {
        return PathBuf::from(p);
    }
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
            for k in ["id", "latency_ms", "policy_rev"] {
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

/// Whether nah's decision explains a difference: the Rust side was decided by
/// the nah layer with the rule listed for this case.
fn nah_explains(id: &str, rust: &Value) -> bool {
    rust["layer"] == "nah"
        && NAH_DECIDES
            .iter()
            .any(|(i, rule)| *i == id && rust["rule"] == *rule)
}

fn expected_difference(id: &str) -> Option<&'static str> {
    EXPECTED_DIFFERENCES
        .iter()
        .find(|(i, _)| *i == id)
        .map(|(_, why)| *why)
}

#[test]
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
        if a != b && expected_difference(&id).is_none() && !nah_explains(&id, &b) {
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

    // the plugin sources
    for harness in ["opencode", "pi", "vim", ""] {
        let args: Vec<&str> = ["plugin"]
            .into_iter()
            .chain(Some(harness).filter(|h| !h.is_empty()))
            .collect();
        let (gc, go_out) = sb.run(&go, &args, "");
        let (rc, rust_out) = sb.run(&rust, &args, "");
        compared += 1;
        if (gc, &go_out) != (rc, &rust_out) {
            diffs.insert(
                format!("plugin {harness}"),
                (
                    serde_json::json!({"exit": gc, "len": go_out.len()}),
                    serde_json::json!({"exit": rc, "len": rust_out.len()}),
                ),
            );
        }
    }

    // edge cases: (id, policy file body, stdin)
    let request = |input: &str| {
        format!(
            r#"{{"harness":"claude","cwd":"/work/app","project_dir":"/work/app","tool":{{"name":"Bash","input":{input}}}}}"#
        )
    };
    let deep_ok = format!("{}1{}", "[".repeat(100), "]".repeat(100));
    let deep_129 = format!("{}1{}", "[".repeat(200), "]".repeat(200));
    let wrong_case_policy = r#"{"policy_version":1,"llm":{"backend":"fake"},"backends":{"fake":{"type":"fake"}},"Rules":[{"id":"no-ls","decision":"deny","match":{"command":"^ls"}}]}"#;
    let edge: Vec<(&str, &str, String)> = vec![
        (
            "edge-nesting-100",
            POLICY,
            request(&format!(r#"{{"command":"ls","x":{deep_ok}}}"#)),
        ),
        (
            "edge-nesting-129",
            POLICY,
            request(&format!(r#"{{"command":"ls","x":{deep_129}}}"#)),
        ),
        (
            "edge-duplicate-keys",
            POLICY,
            request(r#"{"command":"rm -rf /","command":"ls"}"#),
        ),
        (
            "edge-wrong-case-input-key",
            POLICY,
            request(r#"{"Command":"rm -rf /"}"#),
        ),
        (
            "edge-policy-Rules-wrong-case",
            wrong_case_policy,
            request(r#"{"command":"ls"}"#),
        ),
    ];
    for (id, pol, stdin) in edge {
        let pol_path = sb.policy.with_file_name(format!("{id}.json"));
        std::fs::write(&pol_path, pol).unwrap();
        let args = [
            "decide",
            "--policy",
            pol_path.to_str().unwrap(),
            "--no-user-policy",
            "--log",
            "-",
        ];
        let (gc, go_out) = sb.run(&go, &args, &stdin);
        let (rc, rust_out) = sb.run(&rust, &args, &stdin);
        let (a, b) = (verdict_summary(gc, &go_out), verdict_summary(rc, &rust_out));
        compared += 1;
        if a != b && expected_difference(id).is_none() {
            diffs.insert(format!("edge {id}"), (a, b));
        }
    }

    // the same malformed shapes through the Claude hook
    let hook = |input: &str, extra: &str| {
        format!(
            r#"{{"cwd":"/work/app","hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{input}{extra}}}"#
        )
    };
    let hook_edge: Vec<(&str, String)> = vec![
        (
            "hook-nesting-129",
            hook(&format!(r#"{{"command":"ls","x":{deep_129}}}"#), ""),
        ),
        (
            "hook-duplicate-keys",
            hook(r#"{"command":"rm -rf /","command":"ls"}"#, ""),
        ),
        (
            "hook-duplicate-tool-name",
            hook(r#"{"command":"ls"}"#, r#","tool_name":"Read""#),
        ),
        (
            "hook-wrong-case-input-key",
            hook(r#"{"Command":"rm -rf /"}"#, ""),
        ),
    ];
    let hook_args = [
        "hook",
        "claude",
        "--policy",
        policy,
        "--no-user-policy",
        "--log",
        "-",
    ];
    for (id, stdin) in hook_edge {
        let (gc, go_out) = sb.run(&go, &hook_args, &stdin);
        let (rc, rust_out) = sb.run(&rust, &hook_args, &stdin);
        let (a, b) = (summarize(gc, &go_out), summarize(rc, &rust_out));
        compared += 1;
        if a != b && expected_difference(id).is_none() {
            diffs.insert(format!("edge {id}"), (a, b));
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
