//! The supervisor against `examples/engine_child.rs`, a child that misbehaves
//! on request. No nah is involved.

use std::collections::BTreeMap;

use serde_json::value::RawValue;

use super::*;

fn child(mode: &str) -> SupervisedEngine {
    let exe = std::env::current_exe().unwrap();
    let name = format!("engine_child{}", std::env::consts::EXE_SUFFIX);
    let p = exe
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("examples")
        .join(&name);
    assert!(
        p.exists(),
        "{} is missing: run the tests with `cargo test` (not `--lib`), which builds the examples",
        p.display()
    );
    SupervisedEngine::with_exe(p).with_args(vec![mode.into()])
}

fn req(timeout_ms: u64) -> NahRequest {
    NahRequest {
        tool: "Bash".into(),
        input: RawValue::from_string(r#"{"command":"ls"}"#.into()).unwrap(),
        cwd: "/".into(),
        project_dir: "/".into(),
        guards: BTreeMap::new(),
        budget_ms: 100,
        timeout_ms,
    }
}

fn timed(mode: &str, timeout_ms: u64) -> (Result<NahResult, NahError>, Duration) {
    let t = Instant::now();
    let r = child(mode).decide(&req(timeout_ms));
    (r, t.elapsed())
}

#[test]
fn an_answer_round_trips() {
    let (r, _) = timed("ok", 10_000);
    let r = r.unwrap();
    assert_eq!(r.reason, "saw Bash");
    assert_eq!(r.coverage, "full");
}

#[test]
fn a_panic_an_abort_and_a_nonzero_exit_are_crashes() {
    for mode in ["panic", "abort", "exit3"] {
        let (r, took) = timed(mode, 10_000);
        assert!(matches!(r, Err(NahError::Crashed(_))), "{mode}: {r:?}");
        assert!(took < Duration::from_secs(8), "{mode} took {took:?}");
    }
}

#[test]
fn a_hang_is_killed_at_the_deadline() {
    let (r, took) = timed("hang", 400);
    assert_eq!(r.unwrap_err(), NahError::Timeout(400));
    assert!(took >= Duration::from_millis(350), "{took:?}");
    assert!(took < Duration::from_secs(5), "{took:?}");
}

#[test]
fn garbage_and_too_much_output_are_failures() {
    let (r, _) = timed("garbage", 10_000);
    assert!(matches!(r, Err(NahError::Failed(_))), "{r:?}");
    let (r, _) = timed("big", 10_000);
    assert!(matches!(r, Err(NahError::Failed(_))), "{r:?}");
}

#[test]
fn a_grandchild_holding_the_pipe_does_not_hold_the_answer() {
    let (r, took) = timed("grandchild-ok", 20_000);
    assert!(r.is_ok(), "{r:?}");
    assert!(took < Duration::from_secs(10), "{took:?}");
    // And a kill at the deadline does not wait for the pipe to close.
    let (r, took) = timed("grandchild-hang", 400);
    assert_eq!(r.unwrap_err(), NahError::Timeout(400));
    assert!(took < Duration::from_secs(5), "{took:?}");
}

#[test]
fn a_missing_executable_is_a_failure_not_a_panic() {
    let r = SupervisedEngine::with_exe("/does/not/exist".into()).decide(&req(1000));
    assert!(matches!(r, Err(NahError::Failed(_))), "{r:?}");
}

#[test]
fn serve_reports_an_unreadable_request() {
    let mut out = Vec::new();
    let code = serve(&crate::nah::DelegatingEngine, &mut &b"{"[..], &mut out);
    assert_eq!(code, 0);
    let reply: Reply = serde_json::from_slice(&out).unwrap();
    assert!(matches!(reply, Reply::Error(_)));
}

#[test]
fn a_child_whose_parent_is_gone_ends_itself_after_the_deadline() {
    // Not through SupervisedEngine: the parent here never kills the child.
    let exe = child("serve-hang");
    let body = serde_json::to_vec(&req(300)).unwrap();
    let mut c = Command::new(&exe.exe)
        .arg(ENGINE_VERB)
        .args(&exe.args)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    c.stdin.take().unwrap().write_all(&body).unwrap();
    let started = Instant::now();
    let status = wait_until(&mut c, Instant::now() + Duration::from_secs(10)).unwrap();
    let Some(status) = status else {
        let _ = c.kill();
        panic!("the child did not end itself");
    };
    assert_eq!(status.code(), Some(3));
    assert!(started.elapsed() < Duration::from_secs(6));
}
