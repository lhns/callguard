use std::io::Cursor;
use std::sync::{Arc, Mutex};

use super::*;

fn payload(name: &str) -> String {
    let p = format!("{}/testdata/hook/{name}", env!("CARGO_MANIFEST_DIR"));
    std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("{p}: {e}"))
}

fn verdict(d: Decision, enforced: bool) -> Verdict {
    Verdict {
        schema: VERDICT_SCHEMA.into(),
        v: 1,
        id: "id1".into(),
        decision: d,
        enforced,
        reason: "because".into(),
        layer: "rules".into(),
        rule: "r1".into(),
        confidence: 1.0,
        policy_rev: String::new(),
        backend: String::new(),
        latency_ms: 0,
        warnings: Vec::new(),
    }
}

type Seen = Arc<Mutex<Option<Request>>>;

/// A decider that records the request and returns `v`.
fn capture(v: Verdict) -> (impl Fn(&Request) -> Verdict + Sync, Seen) {
    let got: Seen = Arc::new(Mutex::new(None));
    let got2 = got.clone();
    (
        move |r: &Request| {
            *got2.lock().unwrap() = Some(r.clone());
            v.clone()
        },
        got,
    )
}

fn seen(s: &Seen) -> Request {
    s.lock().unwrap().clone().expect("decider not called")
}

fn panicking(_: &Request) -> Verdict {
    panic!("boom")
}

type Runner = fn(&mut dyn Read, &mut dyn Write, &mut dyn Write, &Options, Decider) -> i32;

fn run_with(f: Runner, input: &str, opt: &Options, d: Decider) -> (String, String, i32) {
    let (mut o, mut e) = (Vec::new(), Vec::new());
    let code = f(
        &mut Cursor::new(input.as_bytes().to_vec()),
        &mut o,
        &mut e,
        opt,
        d,
    );
    (
        String::from_utf8(o).unwrap(),
        String::from_utf8(e).unwrap(),
        code,
    )
}

fn run_claude(input: &str, opt: &Options, d: Decider) -> (String, String, i32) {
    run_with(claude, input, opt, d)
}
fn run_hermes(input: &str, opt: &Options, d: Decider) -> (String, String, i32) {
    run_with(hermes, input, opt, d)
}
fn run_generic(input: &str, opt: &Options, d: Decider) -> (String, String, i32) {
    run_with(generic, input, opt, d)
}

const ASK_MSG: &str = "callguard: because [rules/r1]";
const DENY_MSG: &str = "callguard: because [rules/r1]. Do not try to work around this block; if the action is needed, ask the user to run or approve it.";

fn claude_json(decision: &str, reason: &str) -> String {
    format!(
        "{}\n",
        serde_json::json!({"hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": decision,
            "permissionDecisionReason": reason,
        }})
    )
}

#[test]
fn claude_table() {
    use Decision::{Allow, Ask, Deny};
    let bash = "claude_pretooluse_bash.json";
    let aq = "claude_askuserquestion.json";
    let auto = "claude_auto_mode_write.json";
    let auto_flag = Options {
        allow_in_auto: true,
        ..Default::default()
    };
    let cases: Vec<(&str, &str, Verdict, Options, String)> = vec![
        (
            "allow",
            bash,
            verdict(Allow, true),
            Options::default(),
            claude_json("allow", ASK_MSG),
        ),
        (
            "ask",
            bash,
            verdict(Ask, true),
            Options::default(),
            claude_json("ask", ASK_MSG),
        ),
        (
            "deny",
            bash,
            verdict(Deny, true),
            Options::default(),
            claude_json("deny", DENY_MSG),
        ),
        (
            "allow not enforced",
            bash,
            verdict(Allow, false),
            Options::default(),
            String::new(),
        ),
        (
            "ask not enforced",
            bash,
            verdict(Ask, false),
            Options::default(),
            String::new(),
        ),
        (
            "deny not enforced",
            bash,
            verdict(Deny, false),
            Options::default(),
            String::new(),
        ),
        (
            "AskUserQuestion allow is silent",
            aq,
            verdict(Allow, true),
            Options::default(),
            String::new(),
        ),
        (
            "AskUserQuestion ask",
            aq,
            verdict(Ask, true),
            Options::default(),
            claude_json("ask", ASK_MSG),
        ),
        (
            "AskUserQuestion deny",
            aq,
            verdict(Deny, true),
            Options::default(),
            claude_json("deny", DENY_MSG),
        ),
        (
            "auto mode allow is silent",
            auto,
            verdict(Allow, true),
            Options::default(),
            String::new(),
        ),
        (
            "auto mode allow with flag",
            auto,
            verdict(Allow, true),
            auto_flag,
            claude_json("allow", ASK_MSG),
        ),
        (
            "auto mode ask",
            auto,
            verdict(Ask, true),
            Options::default(),
            claude_json("ask", ASK_MSG),
        ),
        (
            "auto mode deny",
            auto,
            verdict(Deny, true),
            Options::default(),
            claude_json("deny", DENY_MSG),
        ),
        (
            "dontAsk allow",
            "claude_dontask_bash.json",
            verdict(Allow, true),
            Options::default(),
            claude_json("allow", ASK_MSG),
        ),
        (
            "PostToolUse is ignored",
            "claude_posttooluse.json",
            verdict(Deny, true),
            Options::default(),
            String::new(),
        ),
    ];
    for (name, file, v, opt, want) in cases {
        let (d, _) = capture(v);
        let (out, err, code) = run_claude(&payload(file), &opt, &d);
        assert!(
            out == want && code == 0 && err.is_empty(),
            "{name}: out={out:?} err={err:?} code={code}, want out={want:?} code=0"
        );
    }
}

#[test]
fn claude_post_tool_use_does_not_decide() {
    let d = |_: &Request| -> Verdict { panic!("decider called for PostToolUse") };
    let (out, _, code) = run_claude(&payload("claude_posttooluse.json"), &Options::default(), &d);
    assert!(out.is_empty() && code == 0, "out={out:?} code={code}");
}

#[test]
fn claude_request_mapping() {
    let (d, got) = capture(verdict(Decision::Allow, true));
    run_claude(
        &payload("claude_pretooluse_bash.json"),
        &Options::default(),
        &d,
    );
    let r = seen(&got);
    assert_eq!(r.tool.name, "Bash");
    let input: serde_json::Value = serde_json::from_str(r.tool.input_str()).unwrap();
    assert_eq!(input["command"], "npm test");
    assert_eq!(input["timeout"], 120000.0);
    assert_eq!(
        (
            r.schema.as_str(),
            r.v,
            r.harness.as_str(),
            r.session_id.as_str(),
            r.tool_use_id.as_str(),
            r.cwd.as_str(),
            r.permission_mode.as_str(),
            r.unattended,
        ),
        (
            REQUEST_SCHEMA,
            1,
            "claude",
            "abc123",
            "toolu_01ABC123",
            "/home/user/my-project",
            "default",
            false
        )
    );
    let t = r.transcript.unwrap();
    assert_eq!(
        (t.path.as_str(), t.format.as_str(), t.messages.len()),
        (
            "/home/user/.claude/projects/my-project/00893aaf-19fa-41d2-8238-13269b9b3ca0.jsonl",
            "claude-jsonl",
            0
        )
    );
    assert!(
        r.project_dir.is_empty() && r.context.is_empty() && r.meta.is_none() && r.facts.is_none()
    );

    // dontAsk and --unattended both set unattended.
    let (d, got) = capture(verdict(Decision::Allow, true));
    run_claude(
        &payload("claude_dontask_bash.json"),
        &Options::default(),
        &d,
    );
    let r = seen(&got);
    assert!(
        r.unattended && r.permission_mode == "dontAsk",
        "dontAsk: {r:?}"
    );
    let (d, got) = capture(verdict(Decision::Allow, true));
    let opt = Options {
        unattended: true,
        ..Default::default()
    };
    run_claude(&payload("claude_pretooluse_bash.json"), &opt, &d);
    assert!(seen(&got).unattended, "--unattended not applied");

    // Unknown fields are ignored; no transcript path means no transcript.
    let (d, got) = capture(verdict(Decision::Allow, true));
    run_claude(
        r#"{"hook_event_name":"PreToolUse","tool_name":"Read","tool_input":{"file_path":"/x"},"extra":1}"#,
        &Options::default(),
        &d,
    );
    let r = seen(&got);
    assert!(r.tool.name == "Read" && r.transcript.is_none(), "{r:?}");
}

/// Checks the exit-code rule and that nothing allows.
fn assert_claude_safe(out: &str, err: &str, code: i32, want_decision: &str) {
    assert!(
        code == 0 || code == 2,
        "exit {code}: Claude would run the tool (out={out:?} err={err:?})"
    );
    if code == 2 {
        assert!(!err.trim().is_empty(), "exit 2 without a reason on stderr");
        return;
    }
    let v: serde_json::Value = serde_json::from_str(out)
        .unwrap_or_else(|_| panic!("exit 0 without a JSON decision: {out:?}"));
    assert_eq!(
        v["hookSpecificOutput"]["permissionDecision"], want_decision,
        "{out:?}"
    );
}

#[test]
fn instructions_loaded_is_recorded_silently_and_the_next_pretooluse_carries_the_text() {
    let t = tempfile::tempdir().unwrap();
    let md = t.path().join("CLAUDE.md");
    std::fs::write(
        &md,
        "<!-- note -->
use pnpm
",
    )
    .unwrap();
    let state = t.path().join("state").join("instructions");
    let opt = Options {
        instructions_dir: Some(state.clone()),
        ..Default::default()
    };
    let (d, got) = capture(verdict(Decision::Allow, true));
    let mut ev: serde_json::Value =
        serde_json::from_str(&payload("claude_instructionsloaded.json")).unwrap();
    ev["file_path"] = md.to_string_lossy().into_owned().into();
    let (out, err, code) = run_claude(&ev.to_string(), &opt, &d);
    assert_eq!((out.as_str(), err.as_str(), code), ("", "", 0));
    assert!(got.lock().unwrap().is_none(), "no decision for the event");
    // Twice: still one entry. A bad session id stays inside the directory.
    run_claude(&ev.to_string(), &opt, &d);
    ev["session_id"] = "../../evil".into();
    run_claude(&ev.to_string(), &opt, &d);
    assert_eq!(std::fs::read_dir(&state).unwrap().count(), 2);
    assert_eq!(
        std::fs::read_to_string(state.join("abc123.txt"))
            .unwrap()
            .lines()
            .count(),
        1
    );
    run_claude(&payload("claude_pretooluse_bash.json"), &opt, &d);
    assert_eq!(
        seen(&got).instructions,
        format!(
            "## {}
use pnpm",
            md.display()
        )
    );
    // Without a state directory nothing is read, and nothing is said.
    let (d2, got2) = capture(verdict(Decision::Allow, true));
    run_claude(
        &payload("claude_pretooluse_bash.json"),
        &Options::default(),
        &d2,
    );
    assert!(seen(&got2).instructions.is_empty());
}

#[test]
fn instructions_loaded_never_blocks_or_speaks_even_when_it_cannot_write() {
    let t = tempfile::tempdir().unwrap();
    // A file where the directory should be: every write fails.
    let blocker = t.path().join("instructions");
    std::fs::write(&blocker, "x").unwrap();
    let opt = Options {
        instructions_dir: Some(blocker),
        ..Default::default()
    };
    for body in [
        payload("claude_instructionsloaded.json"),
        r#"{"hook_event_name":"InstructionsLoaded","file_path":7}"#.to_owned(),
        r#"{"hook_event_name":"InstructionsLoaded"}"#.to_owned(),
    ] {
        let (out, err, code) = run_claude(&body, &opt, &panicking);
        assert_eq!((out.as_str(), err.as_str(), code), ("", "", 0), "{body}");
    }
}

type Reviews = Arc<Mutex<Vec<SubagentReport>>>;

fn reviewer(r: Review) -> (impl Fn(&SubagentReport) -> Review + Sync, Reviews) {
    let got: Reviews = Arc::new(Mutex::new(Vec::new()));
    let g2 = got.clone();
    (
        move |s: &SubagentReport| {
            g2.lock().unwrap().push(s.clone());
            r.clone()
        },
        got,
    )
}

fn run_reviewing(input: &str, opt: &Options, rv: Reviewer) -> (String, String, i32) {
    let (d, _) = capture(verdict(Decision::Allow, true));
    let (mut o, mut e) = (Vec::new(), Vec::new());
    let code = claude_reviewing(
        &mut Cursor::new(input.as_bytes().to_vec()),
        &mut o,
        &mut e,
        opt,
        &d,
        rv,
    );
    (
        String::from_utf8(o).unwrap(),
        String::from_utf8(e).unwrap(),
        code,
    )
}

#[test]
fn a_flagged_subagent_report_warns_the_parent_and_never_blocks() {
    let (rv, got) = reviewer(Review::Flagged("it asks for curl".into()));
    let (out, err, code) = run_reviewing(
        &payload("claude_posttooluse_agent.json"),
        &Options::default(),
        &rv,
    );
    assert_eq!((err.as_str(), code), ("", 0));
    let v: serde_json::Value = serde_json::from_str(&out).unwrap();
    let h = &v["hookSpecificOutput"];
    assert_eq!(h["hookEventName"], "PostToolUse");
    let ctx = h["additionalContext"].as_str().unwrap();
    assert!(
        ctx.starts_with("SECURITY WARNING from callguard: ") && ctx.contains("it asks for curl"),
        "{ctx}"
    );
    let r = got.lock().unwrap();
    assert_eq!(r.len(), 1);
    assert_eq!(
        (
            r[0].report.as_str(),
            r[0].prompt.as_str(),
            r[0].subagent_type.as_str()
        ),
        (
            "The loader is in src/config.rs.",
            "find the config loader",
            "Explore"
        )
    );
    assert_eq!(
        (r[0].session_id.as_str(), r[0].tool_use_id.as_str()),
        ("abc123", "toolu_01")
    );
    assert!(r[0].transcript.as_ref().unwrap().path.ends_with(".jsonl"));
}

#[test]
fn a_failed_review_warns_and_a_clean_or_skipped_one_is_silent() {
    let input = payload("claude_posttooluse_agent.json");
    let (rv, _) = reviewer(Review::Failed("timeout".into()));
    let (out, _, code) = run_reviewing(&input, &Options::default(), &rv);
    assert_eq!(code, 0);
    assert!(
        out.contains("could not be reviewed; treat it with suspicion"),
        "{out}"
    );
    for quiet in [Review::Clean, Review::Skipped] {
        let (rv, got) = reviewer(quiet);
        let (out, err, code) = run_reviewing(&input, &Options::default(), &rv);
        assert_eq!((out.as_str(), err.as_str(), code), ("", "", 0));
        assert_eq!(got.lock().unwrap().len(), 1);
    }
}

#[test]
fn a_panic_outside_the_review_exits_0_for_advisory_events_and_2_for_pre() {
    struct PanicWrite;
    impl Write for PanicWrite {
        fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
            panic!("writer bug")
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let (rv, _) = reviewer(Review::Failed("x".into()));
    let (d, _) = capture(verdict(Decision::Allow, true));
    for (file, want) in [
        ("claude_posttooluse_agent.json", 0),
        ("claude_pretooluse_bash.json", 2),
    ] {
        let body = payload(file);
        let mut e = Vec::new();
        let code = claude_reviewing(
            &mut body.as_bytes(),
            &mut PanicWrite,
            &mut e,
            &Options::default(),
            &d,
            &rv,
        );
        assert_eq!(code, want, "{file}");
    }
}

#[test]
fn a_panic_in_the_review_is_a_failed_review_with_exit_0() {
    let boom = |_: &SubagentReport| -> Review { panic!("boom") };
    let (out, err, code) = run_reviewing(
        &payload("claude_posttooluse_agent.json"),
        &Options::default(),
        &boom,
    );
    assert_eq!((err.as_str(), code), ("", 0));
    assert!(out.contains("could not be reviewed"), "{out}");
}

#[test]
fn only_agent_and_task_reports_are_reviewed_and_auto_mode_is_skipped_unless_asked() {
    let base: serde_json::Value =
        serde_json::from_str(&payload("claude_posttooluse_agent.json")).unwrap();
    let with = |f: &dyn Fn(&mut serde_json::Value)| {
        let mut v = base.clone();
        f(&mut v);
        v.to_string()
    };
    let flag = Review::Flagged("x".into());
    let calls = |input: &str, opt: &Options| {
        let (rv, got) = reviewer(flag.clone());
        let (out, err, code) = run_reviewing(input, opt, &rv);
        assert_eq!((err.as_str(), code), ("", 0), "{input}");
        let n = got.lock().unwrap().len();
        assert_eq!(out.is_empty(), n == 0, "{input}");
        n
    };
    let d = Options::default();
    assert_eq!(calls(&with(&|_| {}), &d), 1);
    assert_eq!(calls(&with(&|v| v["tool_name"] = "Task".into()), &d), 1);
    assert_eq!(calls(&with(&|v| v["tool_name"] = "Bash".into()), &d), 0);
    assert_eq!(calls(&payload("claude_posttooluse.json"), &d), 0);
    assert_eq!(
        calls(&with(&|v| v["tool_response"] = serde_json::json!({})), &d),
        1
    );
    assert_eq!(
        calls(&with(&|v| v["tool_response"] = serde_json::Value::Null), &d),
        0
    );
    assert_eq!(calls(&with(&|v| v["tool_response"] = "".into()), &d), 0);
    assert_eq!(calls(&with(&|v| v["tool_response"] = 7.into()), &d), 1);
    let auto = with(&|v| v["permission_mode"] = "auto".into());
    assert_eq!(calls(&auto, &d), 0, "Claude reviews it itself");
    let on = Options {
        review_in_auto: true,
        ..Default::default()
    };
    assert_eq!(calls(&auto, &on), 1, "--review-in-auto");
    // A payload with a mistyped field is not reviewed, and is not an error.
    assert_eq!(calls(&with(&|v| v["cwd"] = 7.into()), &d), 0);
}

#[test]
fn without_a_reviewer_post_tool_use_is_as_before() {
    let (d, _) = capture(verdict(Decision::Deny, true));
    for f in ["claude_posttooluse_agent.json", "claude_posttooluse.json"] {
        let (out, err, code) = run_claude(&payload(f), &Options::default(), &d);
        assert_eq!((out.as_str(), err.as_str(), code), ("", "", 0), "{f}");
    }
}

#[test]
fn the_subagent_record_adds_its_calls() {
    let t = tempfile::tempdir().unwrap();
    let main = t.path().join("s.jsonl");
    let dir = t.path().join("s").join("subagents");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("agent-a1b2.jsonl"),
        r#"{"type":"assistant","isSidechain":true,"message":{"content":[{"type":"tool_use","id":"t","name":"Bash","input":{"command":"ls"}}]}}"#,
    )
    .unwrap();
    let mut v: serde_json::Value =
        serde_json::from_str(&payload("claude_posttooluse_agent.json")).unwrap();
    v["transcript_path"] = main.to_string_lossy().into_owned().into();
    let (rv, got) = reviewer(Review::Clean);
    run_reviewing(&v.to_string(), &Options::default(), &rv);
    let r = got.lock().unwrap();
    assert_eq!(r[0].calls.len(), 1);
    assert_eq!(r[0].calls[0].tool, "Bash");
}

#[test]
fn claude_never_fails_open() {
    let (ok_decider, _) = capture(verdict(Decision::Allow, true));
    let bash = payload("claude_pretooluse_bash.json");
    let oversize = format!("{{\"x\":\"{}\"}}", "a".repeat(MAX_INPUT));
    let cases: Vec<(&str, String, Decider)> = vec![
        ("garbage", "this is not json".into(), &ok_decider),
        ("empty body", String::new(), &ok_decider),
        ("empty object", "{}".into(), &ok_decider),
        ("json array", "[1,2]".into(), &ok_decider),
        (
            "json array of strings",
            r#"["PreToolUse","Bash"]"#.into(),
            &ok_decider,
        ),
        (
            "missing tool_name",
            r#"{"hook_event_name":"PreToolUse"}"#.into(),
            &ok_decider,
        ),
        ("panicking decider", bash, &panicking),
        ("oversize", oversize, &ok_decider),
    ];
    for (name, input, d) in cases {
        for unattended in [false, true] {
            let opt = Options {
                unattended,
                ..Default::default()
            };
            let want = if unattended { "deny" } else { "ask" };
            let (out, err, code) = run_claude(&input, &opt, d);
            assert_claude_safe(&out, &err, code, want);
            assert!(
                !(code == 0 && out.is_empty()),
                "{name}: silent exit 0 on a failure"
            );
        }
    }
}

/// A field of the wrong type must not hide the rest of the payload: the
/// permission mode still makes the missing tool a deny.
#[test]
fn claude_mistyped_field_keeps_the_rest_of_the_payload() {
    let (d, _) = capture(verdict(Decision::Allow, true));
    let (out, err, code) = run_claude(
        r#"{"hook_event_name":"PreToolUse","permission_mode":"dontAsk","tool_name":5}"#,
        &Options::default(),
        &d,
    );
    assert_claude_safe(&out, &err, code, "deny");
    // A mistyped field of any kind makes the payload bad: the decider that
    // would allow is not called, and the verdict is the fail-safe one.
    let (allow, called) = capture(verdict(Decision::Allow, true));
    let ls = r#""hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"ls"}"#;
    let (out, err, code) = run_claude(&format!("{{{ls},\"cwd\":7}}"), &Options::default(), &allow);
    assert_claude_safe(&out, &err, code, "ask");
    let (out, err, code) = run_claude(
        &format!("{{{ls},\"cwd\":7,\"permission_mode\":\"dontAsk\"}}"),
        &Options::default(),
        &allow,
    );
    assert_claude_safe(&out, &err, code, "deny");
    let (out, err, code) = run_claude(
        &format!("{{{ls},\"permission_mode\":5}}"),
        &Options::default(),
        &allow,
    );
    assert_claude_safe(&out, &err, code, "ask");
    assert!(
        called.lock().unwrap().is_none(),
        "the decider ran for a bad payload"
    );
}

#[test]
fn hermes_mistyped_field_is_a_bad_payload() {
    let (allow, called) = capture(verdict(Decision::Allow, true));
    let body =
        r#"{"hook_event_name":"pre_tool_call","tool_name":"terminal","tool_input":{},"cwd":7}"#;
    let (out, _, code) = run_hermes(body, &Options::default(), &allow);
    assert!(
        code == 0 && out.contains(r#""action":"approve""#),
        "interactive: out={out:?} code={code}"
    );
    let opt = Options {
        unattended: true,
        ..Default::default()
    };
    let (out, _, code) = run_hermes(body, &opt, &allow);
    assert!(
        code == 2 && out.contains(r#""action":"block""#),
        "unattended: out={out:?} code={code}"
    );
    assert!(
        called.lock().unwrap().is_none(),
        "the decider ran for a bad payload"
    );
}

/// Hook field names are read in any letter case.
#[test]
fn hook_fields_are_read_in_any_letter_case() {
    let (d, got) = capture(verdict(Decision::Allow, true));
    run_claude(
        r#"{"Hook_Event_Name":"PreToolUse","TOOL_NAME":"Bash","tool_input":{"Command":"ls"},"permission_mode":"dontAsk"}"#,
        &Options::default(),
        &d,
    );
    let r = seen(&got);
    assert!(r.unattended && r.tool.name == "Bash", "{r:?}");
    // The input stays as sent.
    assert_eq!(r.tool.input_str(), r#"{"Command":"ls"}"#);
    // The exact spelling wins over another case.
    let (d, got) = capture(verdict(Decision::Allow, true));
    run_hermes(
        r#"{"hook_event_name":"pre_tool_call","TOOL_NAME":"A","tool_name":"B","tool_input":{}}"#,
        &Options::default(),
        &d,
    );
    assert_eq!(seen(&got).tool.name, "B");
    let (d, got) = capture(verdict(Decision::Allow, true));
    run_generic(r#"{"Tool":"Read","input":{}}"#, &Options::default(), &d);
    assert_eq!(seen(&got).tool.name, "Read");
}

#[test]
fn claude_bad_payload_in_dont_ask_denies() {
    let (d, _) = capture(verdict(Decision::Allow, true));
    let (out, err, code) = run_claude(
        r#"{"hook_event_name":"PreToolUse","permission_mode":"dontAsk"}"#,
        &Options::default(),
        &d,
    );
    assert_claude_safe(&out, &err, code, "deny");
}

struct FailWriter;

impl Write for FailWriter {
    fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
        Err(std::io::Error::other("closed"))
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[test]
fn claude_write_failure_exits_2() {
    let mut e = Vec::new();
    let (d, _) = capture(verdict(Decision::Deny, true));
    let code = claude(
        &mut Cursor::new(payload("claude_pretooluse_bash.json").into_bytes()),
        &mut FailWriter,
        &mut e,
        &Options::default(),
        &d,
    );
    assert!(code == 2 && !e.is_empty(), "code={code} stderr={e:?}");
}

#[test]
fn context_flags_and_file() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("ctx.json");
    std::fs::write(
        &file,
        r#"{"trust":"tainted","data_class":"private","principal":"alice"}"#,
    )
    .unwrap();
    let opt = Options {
        context: [("data_class", "open"), ("zone", "z1")]
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect(),
        context_file: file.to_string_lossy().into_owned(),
        ..Default::default()
    };
    let want: BTreeMap<String, String> = [
        ("trust", "tainted"),
        ("data_class", "open"),
        ("principal", "alice"),
        ("zone", "z1"),
    ]
    .iter()
    .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
    .collect();
    let runs: Vec<(&str, Runner, String)> = vec![
        ("claude", claude, payload("claude_pretooluse_bash.json")),
        (
            "hermes",
            hermes,
            payload("hermes_pre_tool_call_terminal.json"),
        ),
        (
            "generic",
            generic,
            r#"{"tool":"bash","input":{"command":"ls"}}"#.into(),
        ),
    ];
    for (name, f, input) in runs {
        let (d, got) = capture(verdict(Decision::Ask, true));
        run_with(f, &input, &opt, &d);
        assert_eq!(seen(&got).context, want, "{name}");
    }

    // Generic ignores host observations on stdin.
    let (d, got) = capture(verdict(Decision::Ask, true));
    run_generic(
        r#"{"harness":"opencode","tool":"bash","input":{"command":"git push"},"cwd":"/w","meta":{"git_status":{"clean":true}},"facts":{"source":"x"}}"#,
        &Options::default(),
        &d,
    );
    let r = seen(&got);
    assert!(
        r.meta.is_none() && r.facts.is_none(),
        "meta or facts copied from stdin: {r:?}"
    );

    // Flags override the generic request context.
    let (d, got) = capture(verdict(Decision::Ask, true));
    let opt2 = Options {
        context: [("trust".to_owned(), "trusted".to_owned())].into(),
        ..Default::default()
    };
    run_generic(&payload("generic_opencode_bash.json"), &opt2, &d);
    assert_eq!(seen(&got).context["trust"], "trusted");

    for (name, content) in [
        ("missing", ""),
        ("invalid JSON", "{"),
        ("not strings", r#"{"a":1}"#),
        ("array", "[]"),
    ] {
        let path = if content.is_empty() {
            dir.path().join("does-not-exist.json")
        } else {
            let p = dir.path().join("bad.json");
            std::fs::write(&p, content).unwrap();
            p
        };
        let opt = Options {
            context_file: path.to_string_lossy().into_owned(),
            ..Default::default()
        };
        let decided = Arc::new(Mutex::new(false));
        let decided2 = decided.clone();
        let d = move |_: &Request| {
            *decided2.lock().unwrap() = true;
            verdict(Decision::Allow, true)
        };
        let (out, err, code) = run_claude(&payload("claude_pretooluse_bash.json"), &opt, &d);
        assert!(
            !*decided.lock().unwrap(),
            "{name}: decider ran despite a bad context file"
        );
        assert_claude_safe(&out, &err, code, "ask");
        let (out, _, code) = run_claude(&payload("claude_dontask_bash.json"), &opt, &d);
        assert_claude_safe(&out, "", code, "deny");
    }
}

fn hermes_json(action: &str, msg: &str, key: &str) -> String {
    let mut m = serde_json::json!({"action": action, "message": msg});
    if !key.is_empty() {
        m["rule_key"] = key.into();
    }
    format!("{m}\n")
}

#[test]
fn hermes_table() {
    use Decision::{Allow, Ask, Deny};
    let t = "hermes_pre_tool_call_terminal.json";
    let cases: Vec<(&str, &str, Verdict, String, i32)> = vec![
        ("allow", t, verdict(Allow, true), "{}\n".into(), 0),
        (
            "ask",
            t,
            verdict(Ask, true),
            hermes_json("approve", ASK_MSG, "callguard:rules:r1"),
            0,
        ),
        (
            "deny",
            t,
            verdict(Deny, true),
            hermes_json("block", DENY_MSG, ""),
            2,
        ),
        (
            "allow not enforced",
            t,
            verdict(Allow, false),
            "{}\n".into(),
            0,
        ),
        ("ask not enforced", t, verdict(Ask, false), "{}\n".into(), 0),
        (
            "deny not enforced",
            t,
            verdict(Deny, false),
            "{}\n".into(),
            0,
        ),
        (
            "post_tool_call",
            "hermes_post_tool_call.json",
            verdict(Deny, true),
            "{}\n".into(),
            0,
        ),
    ];
    for (name, file, v, want_out, want_code) in cases {
        let (d, _) = capture(v);
        let (out, err, code) = run_hermes(&payload(file), &Options::default(), &d);
        assert!(
            out == want_out && code == want_code && err.is_empty(),
            "{name}: out={out:?} err={err:?} code={code}, want out={want_out:?} code={want_code}"
        );
    }

    // Ask rule key without a rule.
    let mut v = verdict(Ask, true);
    v.rule.clear();
    let (d, _) = capture(v);
    let (out, _, _) = run_hermes(&payload(t), &Options::default(), &d);
    assert!(out.contains(r#""rule_key":"callguard:rules""#), "{out}");
}

#[test]
fn hermes_request_mapping() {
    let (d, got) = capture(verdict(Decision::Allow, true));
    run_hermes(
        &payload("hermes_pre_tool_call_terminal.json"),
        &Options::default(),
        &d,
    );
    let r = seen(&got);
    assert!(
        r.harness == "hermes"
            && r.session_id == "sess_42"
            && r.cwd == "/home/user/my-project"
            && r.tool.name == "terminal"
            && r.tool.input_str() == r#"{"command": "ls -la"}"#
            && !r.unattended,
        "{r:?}"
    );
    let (d, got) = capture(verdict(Decision::Allow, true));
    let opt = Options {
        unattended: true,
        ..Default::default()
    };
    run_hermes(&payload("hermes_pre_tool_call_terminal.json"), &opt, &d);
    assert!(seen(&got).unattended, "--unattended not applied");
}

#[test]
fn hermes_never_fails_open() {
    let (ok, _) = capture(verdict(Decision::Allow, true));
    let term = payload("hermes_pre_tool_call_terminal.json");
    let cases: Vec<(&str, String, Decider)> = vec![
        ("garbage", "nope".into(), &ok),
        ("empty", String::new(), &ok),
        ("array", "[1]".into(), &ok),
        ("panic", term, &panicking),
    ];
    for (name, input, d) in cases {
        let (out, _, code) = run_hermes(&input, &Options::default(), d);
        assert!(
            code == 0 && out.contains(r#""action":"approve""#),
            "{name} interactive: out={out:?} code={code}"
        );
        let opt = Options {
            unattended: true,
            ..Default::default()
        };
        let (out, _, code) = run_hermes(&input, &opt, d);
        assert!(
            code == 2 && out.contains(r#""action":"block""#),
            "{name} unattended: out={out:?} code={code}"
        );
    }
}

#[test]
fn generic_table() {
    use Decision::{Allow, Ask, Deny};
    for (name, v) in [
        ("allow", verdict(Allow, true)),
        ("ask", verdict(Ask, true)),
        ("deny", verdict(Deny, true)),
        ("allow not enforced", verdict(Allow, false)),
        ("deny not enforced", verdict(Deny, false)),
    ] {
        let (d, _) = capture(v.clone());
        let (out, err, code) = run_generic(
            &payload("generic_opencode_bash.json"),
            &Options::default(),
            &d,
        );
        let want = format!("{}\n", json_text::to_string(&v).unwrap());
        assert!(
            out == want && code == 0 && err.is_empty(),
            "{name}: out={out:?} err={err:?} code={code}"
        );
    }
}

#[test]
fn generic_request_mapping() {
    let (d, got) = capture(verdict(Decision::Allow, true));
    run_generic(
        &payload("generic_opencode_bash.json"),
        &Options::default(),
        &d,
    );
    let r = seen(&got);
    assert!(
        r.harness == "opencode"
            && r.tool.name == "bash"
            && r.cwd == "/home/user/my-project"
            && r.session_id == "ses_9"
            && r.context["trust"] == "tainted"
            && !r.unattended,
        "{r:?}"
    );
    let (d, got) = capture(verdict(Decision::Allow, true));
    run_generic(&payload("generic_pi_read.json"), &Options::default(), &d);
    let r = seen(&got);
    assert!(
        r.harness == "pi"
            && r.project_dir == "/home/user/my-project"
            && r.unattended
            && r.tool.name == "read",
        "{r:?}"
    );
}

#[test]
fn generic_never_fails_open() {
    let (ok, _) = capture(verdict(Decision::Allow, true));
    let cases: Vec<(&str, String, Decider)> = vec![
        ("garbage", "nope".into(), &ok),
        ("empty", String::new(), &ok),
        ("array", "[]".into(), &ok),
        ("missing tool", r#"{"harness":"pi"}"#.into(), &ok),
        ("panic", payload("generic_pi_read.json"), &panicking),
    ];
    for (name, input, d) in cases {
        let (out, _, code) = run_generic(&input, &Options::default(), d);
        let v: Verdict =
            serde_json::from_str(&out).unwrap_or_else(|e| panic!("{name}: out={out:?} {e}"));
        assert!(
            code == 0 && v.decision != Decision::Allow && v.enforced,
            "{name}: {v:?}"
        );
    }
    let (out, _, _) = run_generic(
        "nope",
        &Options {
            unattended: true,
            ..Default::default()
        },
        &ok,
    );
    let v: Verdict = serde_json::from_str(&out).unwrap();
    assert_eq!(v.decision, Decision::Deny, "{out}");
}

#[test]
fn last_resort_json_is_a_valid_deny() {
    let v: Verdict = serde_json::from_str(LAST_RESORT_JSON).unwrap();
    assert!(v.decision == Decision::Deny && v.enforced);
    // The constant matches what the marshalled verdict would be.
    let lr = Verdict {
        reason: "callguard could not produce a verdict".into(),
        ..last_resort(
            Some(&Request {
                unattended: true,
                ..Default::default()
            }),
            "x",
        )
    };
    assert_eq!(
        format!("{}\n", json_text::to_string(&lr).unwrap()),
        LAST_RESORT_JSON
    );
}

#[test]
fn a_panic_in_the_adapter_itself_blocks() {
    // A reader that panics stands in for any bug in the adapter's own code.
    struct Boom;
    impl Read for Boom {
        fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
            panic!("adapter bug")
        }
    }
    let (d, _) = capture(verdict(Decision::Allow, true));
    let (mut o, mut e) = (Vec::new(), Vec::new());
    assert_eq!(
        claude(&mut Boom, &mut o, &mut e, &Options::default(), &d),
        2
    );
    assert!(String::from_utf8_lossy(&e).contains("adapter bug"));
    let (mut o, mut e) = (Vec::new(), Vec::new());
    assert_eq!(
        hermes(&mut Boom, &mut o, &mut e, &Options::default(), &d),
        2
    );
    let (mut o, mut e) = (Vec::new(), Vec::new());
    assert_eq!(
        generic(&mut Boom, &mut o, &mut e, &Options::default(), &d),
        0
    );
    assert_eq!(String::from_utf8(o).unwrap(), LAST_RESORT_JSON);
}
