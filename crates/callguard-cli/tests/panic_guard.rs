//! A panic in the process itself, not just in the engine, must never fail
//! open. Needs `--features test-engines`, which adds `--test-panic` (a panic
//! at the start of dispatch):
//! `cargo test -p callguard-cli --features test-engines`.
#![cfg(feature = "test-engines")]

use std::io::Write;
use std::process::{Command, Stdio};

fn run(args: &[&str]) -> (i32, String, String) {
    let mut child = Command::new(env!("CARGO_BIN_EXE_callguard"))
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(b"{}").ok();
    let out = child.wait_with_output().unwrap();
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

fn decision(stdout: &str) -> String {
    let v: serde_json::Value = serde_json::from_str(stdout.trim())
        .unwrap_or_else(|e| panic!("stdout is not a verdict: {stdout:?} ({e})"));
    assert_eq!(v["enforced"], true, "{stdout}");
    v["decision"].as_str().unwrap().to_owned()
}

#[test]
fn claude_and_hermes_hooks_block_with_exit_2() {
    for harness in ["claude", "hermes"] {
        let (code, out, err) = run(&["hook", harness, "--test-panic"]);
        assert_eq!(
            code, 2,
            "{harness}: Claude and Hermes run the tool on any other exit"
        );
        assert!(out.is_empty(), "{harness}: {out:?}");
        assert!(
            err.contains("test panic") && err.contains("blocking"),
            "{harness}: {err:?}"
        );
    }
}

#[test]
fn generic_hook_denies_with_exit_0() {
    let (code, out, _) = run(&["hook", "generic", "--test-panic"]);
    assert_eq!(code, 0);
    assert_eq!(decision(&out), "deny");
}

#[test]
fn decide_prints_a_fallback_and_exits_3() {
    let (code, out, _) = run(&["decide", "--test-panic"]);
    assert_eq!(code, 3);
    assert_eq!(decision(&out), "ask");
    let (code, out, _) = run(&["decide", "--test-panic", "--unattended"]);
    assert_eq!(code, 3);
    assert_eq!(decision(&out), "deny");
}
