//! Turns harness hook payloads into callguard requests and callguard verdicts
//! into each harness's native answer. The adapters never fail open: every
//! internal failure becomes an ask/deny answer the harness honours
//! (docs/design.md sections 9 and 10).
//!
//! A [`Decider`] borrows the request; the adapters catch panics from it
//! (`catch_unwind`) and answer with the fallback.

use std::any::Any;
use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::panic::{AssertUnwindSafe, catch_unwind};

use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;

use crate::fallback::fallback_verdict;
use crate::gojson;
use crate::schema::{
    Decision, LAYER_FALLBACK, REQUEST_SCHEMA, Request, ToolCall, Transcript, VERDICT_SCHEMA,
    Verdict,
};
use crate::serde_util::{nullable, raw_some};

/// Caps the hook payload read from stdin.
pub const MAX_INPUT: usize = 4 << 20;

/// Caps `--context-file`.
const MAX_CONTEXT_FILE: usize = 1 << 20;

/// Decides one request.
pub type Decider<'a> = &'a (dyn Fn(&Request) -> Verdict + Sync);

/// The adapter flags shared by all harnesses.
#[derive(Debug, Clone, Default)]
pub struct Options {
    /// Marks every request as unattended (`--unattended`).
    pub unattended: bool,
    /// `--context key=value` entries, merged into `req.context`.
    pub context: BTreeMap<String, String>,
    /// A JSON object of strings merged into `req.context` (`--context-file`).
    /// Read on every call; an unreadable or invalid file yields a fallback
    /// verdict. It must be root-owned: the agent must not be able to write it.
    pub context_file: String,
    /// Lets the Claude adapter emit allow in permission_mode auto.
    pub allow_in_auto: bool,
}

/// Reads `input` up to [`MAX_INPUT`].
fn read_input(input: &mut dyn Read) -> Result<Vec<u8>, String> {
    let mut b = Vec::new();
    input
        .take(MAX_INPUT as u64 + 1)
        .read_to_end(&mut b)
        .map_err(|e| format!("reading stdin: {e}"))?;
    if b.len() > MAX_INPUT {
        return Err(format!("input larger than {MAX_INPUT} bytes"));
    }
    Ok(b)
}

/// Parses a hook payload: a JSON object, or an error. (A derived `Deserialize`
/// would also take a JSON array as a field list; it is refused.)
fn parse_object<T: for<'de> Deserialize<'de>>(body: &[u8]) -> Result<T, String> {
    if body.iter().find(|b| !b.is_ascii_whitespace()) != Some(&b'{') {
        return Err("payload is not a JSON object".into());
    }
    serde_json::from_slice(body).map_err(|e| e.to_string())
}

/// The text of a panic payload.
pub fn panic_message(p: &(dyn Any + Send)) -> String {
    p.downcast_ref::<&str>().map_or_else(
        || {
            p.downcast_ref::<String>()
                .cloned()
                .unwrap_or_else(|| "panic".into())
        },
        |s| (*s).to_owned(),
    )
}

/// callguard's fallback verdict, or a local ask/deny when that cannot be
/// produced. It never returns allow.
fn fallback(req: Option<&Request>, cause: &str) -> Verdict {
    catch_unwind(AssertUnwindSafe(|| fallback_verdict(req, cause)))
        .ok()
        .filter(|v| v.decision != Decision::Allow)
        .unwrap_or_else(|| last_resort(req, cause))
}

/// The verdict for when even the fallback failed.
pub fn last_resort(req: Option<&Request>, cause: &str) -> Verdict {
    Verdict {
        schema: VERDICT_SCHEMA.into(),
        v: 1,
        id: String::new(),
        decision: if req.is_some_and(|r| r.unattended) {
            Decision::Deny
        } else {
            Decision::Ask
        },
        enforced: true,
        reason: format!("could not evaluate this call ({cause}); a human has to approve it"),
        layer: LAYER_FALLBACK.into(),
        rule: String::new(),
        confidence: 1.0,
        policy_rev: String::new(),
        backend: String::new(),
        latency_ms: 0,
        warnings: Vec::new(),
    }
}

/// Written when even a verdict cannot be marshalled.
pub const LAST_RESORT_JSON: &str = concat!(
    r#"{"schema":"callguard/verdict/v1","v":1,"id":"","decision":"deny","enforced":true,"#,
    r#""reason":"callguard could not produce a verdict","layer":"fallback","confidence":1,"latency_ms":0}"#,
    "\n"
);

/// Applies the context options and runs `d`. A panic and a context error
/// become fallback verdicts.
fn run_decider(d: Decider, opt: &Options, req: &mut Request) -> Verdict {
    if let Err(e) = apply_context(req, opt) {
        return fallback(Some(req), &format!("context: {e}"));
    }
    match catch_unwind(AssertUnwindSafe(|| d(req))) {
        Ok(v) => v,
        Err(p) => fallback(
            Some(req),
            &format!("internal error: {}", panic_message(p.as_ref())),
        ),
    }
}

/// Merges the file, then the flags, into `req.context`.
fn apply_context(req: &mut Request, opt: &Options) -> Result<(), String> {
    if !opt.context_file.is_empty() {
        let f = std::fs::File::open(&opt.context_file).map_err(|e| e.to_string())?;
        let mut b = Vec::new();
        f.take(MAX_CONTEXT_FILE as u64 + 1)
            .read_to_end(&mut b)
            .map_err(|e| e.to_string())?;
        if b.len() > MAX_CONTEXT_FILE {
            return Err(format!(
                "{} is larger than {MAX_CONTEXT_FILE} bytes",
                opt.context_file
            ));
        }
        let m: Option<BTreeMap<String, String>> =
            serde_json::from_slice(&b).map_err(|e| format!("{}: {e}", opt.context_file))?;
        merge_context(req, m.unwrap_or_default());
    }
    merge_context(req, opt.context.clone());
    Ok(())
}

fn merge_context(req: &mut Request, m: BTreeMap<String, String>) {
    req.context.extend(m);
}

/// A request with the schema fields set.
fn new_request(harness: &str) -> Request {
    Request {
        schema: REQUEST_SCHEMA.into(),
        v: 1,
        harness: harness.into(),
        ..Default::default()
    }
}

/// Renders " [layer/rule]".
fn label(v: &Verdict) -> String {
    match (v.layer.is_empty(), v.rule.is_empty()) {
        (true, true) => String::new(),
        (false, true) => format!(" [{}]", v.layer),
        _ => format!(" [{}/{}]", v.layer, v.rule),
    }
}

const DENY_ADVICE: &str = " Do not try to work around this block; if the action is needed, ask the user to run or approve it.";

fn ask_message(v: &Verdict) -> String {
    format!("callguard: {}{}", v.reason, label(v))
}

fn deny_message(v: &Verdict) -> String {
    format!("callguard: {}{}.{DENY_ADVICE}", v.reason, label(v))
}

// ---------------------------------------------------------------------------
// Claude Code

#[derive(Deserialize, Default)]
#[serde(default)]
struct ClaudeInput {
    #[serde(deserialize_with = "nullable")]
    session_id: String,
    #[serde(deserialize_with = "nullable")]
    transcript_path: String,
    #[serde(deserialize_with = "nullable")]
    cwd: String,
    #[serde(deserialize_with = "nullable")]
    permission_mode: String,
    #[serde(deserialize_with = "nullable")]
    hook_event_name: String,
    #[serde(deserialize_with = "nullable")]
    tool_name: String,
    #[serde(deserialize_with = "raw_some")]
    tool_input: Option<Box<RawValue>>,
    #[serde(deserialize_with = "nullable")]
    tool_use_id: String,
}

#[derive(Serialize)]
struct ClaudeOutput<'a> {
    #[serde(rename = "hookSpecificOutput")]
    hook_specific_output: ClaudeDecision<'a>,
}

#[derive(Serialize)]
struct ClaudeDecision<'a> {
    #[serde(rename = "hookEventName")]
    hook_event_name: &'a str,
    #[serde(rename = "permissionDecision")]
    permission_decision: &'a str,
    #[serde(rename = "permissionDecisionReason")]
    permission_decision_reason: &'a str,
}

/// The Claude Code PreToolUse hook. Returns the process exit code.
///
/// Claude treats any non-zero exit other than 2 as a non-blocking error and
/// runs the tool, so this function returns only 0 (JSON decision, or no output
/// for "no opinion") or 2 (blocking, reason on `err_out`).
pub fn claude(
    input: &mut dyn Read,
    out: &mut dyn Write,
    err_out: &mut dyn Write,
    opt: &Options,
    d: Decider,
) -> i32 {
    match catch_unwind(AssertUnwindSafe(|| {
        claude_inner(input, &mut *out, &mut *err_out, opt, d)
    })) {
        Ok(code) => code,
        Err(p) => {
            let _ = writeln!(
                err_out,
                "callguard: internal error: {}; blocking the call",
                panic_message(p.as_ref())
            );
            2
        }
    }
}

fn claude_inner(
    input: &mut dyn Read,
    out: &mut dyn Write,
    err_out: &mut dyn Write,
    opt: &Options,
    d: Decider,
) -> i32 {
    let mut req = new_request("claude");
    let mut in0 = ClaudeInput::default();
    let parsed = read_input(input).and_then(|body| parse_object::<ClaudeInput>(&body));
    let mut err = None;
    match parsed {
        Ok(v) if v.hook_event_name.is_empty() => {
            in0 = v;
            err = Some("missing hook_event_name".to_owned());
        }
        Ok(v) => in0 = v,
        Err(e) => err = Some(e),
    }
    // Set before any fallback, so a malformed payload in dontAsk still denies.
    req.unattended = opt.unattended || in0.permission_mode == "dontAsk";
    let v = if let Some(e) = err {
        fallback(Some(&req), &format!("bad hook input: {e}"))
    } else if in0.hook_event_name != "PreToolUse" {
        return 0;
    } else if in0.tool_name.is_empty() {
        fallback(Some(&req), "bad hook input: missing tool_name")
    } else {
        req.session_id = in0.session_id.clone();
        req.tool_use_id = in0.tool_use_id.clone();
        req.cwd = in0.cwd.clone();
        req.tool = ToolCall {
            name: in0.tool_name.clone(),
            input: in0.tool_input.take(),
        };
        req.permission_mode = in0.permission_mode.clone();
        if !in0.transcript_path.is_empty() {
            req.transcript = Some(Transcript {
                path: in0.transcript_path.clone(),
                format: "claude-jsonl".into(),
                messages: Vec::new(),
            });
        }
        run_decider(d, opt, &mut req)
    };

    if !v.enforced {
        return 0;
    }
    let msg = match v.decision {
        Decision::Allow => {
            // A bare allow is wrong for tools that need a user answer, and in
            // auto mode it would pre-empt Claude Code's own classifier (design
            // section 10).
            if in0.tool_name == "AskUserQuestion"
                || in0.tool_name == "ExitPlanMode"
                || (in0.permission_mode == "auto" && !opt.allow_in_auto)
            {
                return 0;
            }
            ask_message(&v)
        }
        Decision::Ask => ask_message(&v),
        Decision::Deny => deny_message(&v),
    };
    let written = gojson::to_string(&ClaudeOutput {
        hook_specific_output: ClaudeDecision {
            hook_event_name: "PreToolUse",
            permission_decision: v.decision.as_str(),
            permission_decision_reason: &msg,
        },
    })
    .map_err(|e| e.to_string())
    .and_then(|b| {
        out.write_all(format!("{b}\n").as_bytes())
            .map_err(|e| e.to_string())
    });
    if let Err(e) = written {
        let _ = writeln!(
            err_out,
            "{} (could not write the decision: {e})",
            deny_message(&last_resort(Some(&req), "output"))
        );
        return 2;
    }
    0
}

// ---------------------------------------------------------------------------
// Hermes

#[derive(Deserialize, Default)]
#[serde(default)]
struct HermesInput {
    #[serde(deserialize_with = "nullable")]
    hook_event_name: String,
    #[serde(deserialize_with = "nullable")]
    tool_name: String,
    #[serde(deserialize_with = "raw_some")]
    tool_input: Option<Box<RawValue>>,
    #[serde(deserialize_with = "nullable")]
    session_id: String,
    #[serde(deserialize_with = "nullable")]
    cwd: String,
}

#[derive(Serialize, Default)]
struct HermesOutput {
    #[serde(skip_serializing_if = "String::is_empty")]
    action: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    message: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    rule_key: String,
}

/// The Hermes pre_tool_call shell hook. Returns the exit code: 0 with `{}` or
/// an approve answer, 2 with a block answer (Hermes blocks on exit 2 even
/// without JSON).
pub fn hermes(
    input: &mut dyn Read,
    out: &mut dyn Write,
    err_out: &mut dyn Write,
    opt: &Options,
    d: Decider,
) -> i32 {
    match catch_unwind(AssertUnwindSafe(|| {
        hermes_inner(input, &mut *out, &mut *err_out, opt, d)
    })) {
        Ok(code) => code,
        Err(p) => {
            let _ = writeln!(
                err_out,
                "callguard: internal error: {}; blocking the call",
                panic_message(p.as_ref())
            );
            2
        }
    }
}

fn hermes_inner(
    input: &mut dyn Read,
    out: &mut dyn Write,
    err_out: &mut dyn Write,
    opt: &Options,
    d: Decider,
) -> i32 {
    let mut req = new_request("hermes");
    req.unattended = opt.unattended;
    let mut in0 = HermesInput::default();
    let mut err = None;
    match read_input(input).and_then(|body| parse_object::<HermesInput>(&body)) {
        Ok(v) if v.hook_event_name.is_empty() => {
            in0 = v;
            err = Some("missing hook_event_name".to_owned());
        }
        Ok(v) => in0 = v,
        Err(e) => err = Some(e),
    }
    let v = if let Some(e) = err {
        fallback(Some(&req), &format!("bad hook input: {e}"))
    } else if in0.hook_event_name != "pre_tool_call" {
        return hermes_write(out, err_out, &HermesOutput::default(), 0);
    } else if in0.tool_name.is_empty() {
        fallback(Some(&req), "bad hook input: missing tool_name")
    } else {
        req.session_id = in0.session_id;
        req.cwd = in0.cwd;
        req.tool = ToolCall {
            name: in0.tool_name,
            input: in0.tool_input,
        };
        run_decider(d, opt, &mut req)
    };

    if !v.enforced || v.decision == Decision::Allow {
        return hermes_write(out, err_out, &HermesOutput::default(), 0);
    }
    if v.decision == Decision::Ask {
        let mut key = format!("callguard:{}", v.layer);
        if !v.rule.is_empty() {
            key.push(':');
            key.push_str(&v.rule);
        }
        let o = HermesOutput {
            action: "approve".into(),
            message: ask_message(&v),
            rule_key: key,
        };
        return hermes_write(out, err_out, &o, 0);
    }
    let o = HermesOutput {
        action: "block".into(),
        message: deny_message(&v),
        rule_key: String::new(),
    };
    hermes_write(out, err_out, &o, 2)
}

fn hermes_write(out: &mut dyn Write, err_out: &mut dyn Write, o: &HermesOutput, code: i32) -> i32 {
    let written = gojson::to_string(o)
        .map_err(|e| e.to_string())
        .and_then(|b| {
            out.write_all(format!("{b}\n").as_bytes())
                .map_err(|e| e.to_string())
        });
    if let Err(e) = written {
        let _ = writeln!(
            err_out,
            "callguard: could not write the decision: {e}; blocking the call"
        );
        return 2;
    }
    code
}

// ---------------------------------------------------------------------------
// opencode and pi

#[derive(Deserialize, Default)]
#[serde(default)]
struct GenericInput {
    #[serde(deserialize_with = "nullable")]
    harness: String,
    #[serde(deserialize_with = "nullable")]
    tool: String,
    #[serde(deserialize_with = "raw_some")]
    input: Option<Box<RawValue>>,
    #[serde(deserialize_with = "nullable")]
    cwd: String,
    #[serde(deserialize_with = "nullable")]
    session_id: String,
    #[serde(deserialize_with = "nullable")]
    project_dir: String,
    #[serde(deserialize_with = "nullable")]
    context: BTreeMap<String, String>,
    #[serde(deserialize_with = "nullable")]
    unattended: bool,
}

/// The adapter for the opencode and pi plugins: request fields on stdin, a
/// callguard verdict on stdout, exit 0 always. The plugins fail closed on
/// anything else.
pub fn generic(
    input: &mut dyn Read,
    out: &mut dyn Write,
    err_out: &mut dyn Write,
    opt: &Options,
    d: Decider,
) -> i32 {
    match catch_unwind(AssertUnwindSafe(|| {
        generic_inner(input, &mut *out, &mut *err_out, opt, d)
    })) {
        Ok(code) => code,
        Err(p) => {
            let _ = writeln!(
                err_out,
                "callguard: internal error: {}",
                panic_message(p.as_ref())
            );
            let _ = out.write_all(LAST_RESORT_JSON.as_bytes());
            0
        }
    }
}

fn generic_inner(
    input: &mut dyn Read,
    out: &mut dyn Write,
    err_out: &mut dyn Write,
    opt: &Options,
    d: Decider,
) -> i32 {
    let mut req = new_request("generic");
    req.unattended = opt.unattended;
    let v = match read_input(input).and_then(|body| parse_object::<GenericInput>(&body)) {
        Err(e) => fallback(Some(&req), &format!("bad hook input: {e}")),
        Ok(in0) if in0.tool.is_empty() => fallback(Some(&req), "bad hook input: missing tool"),
        Ok(in0) => {
            if !in0.harness.is_empty() {
                req.harness = in0.harness;
            }
            req.session_id = in0.session_id;
            req.cwd = in0.cwd;
            req.project_dir = in0.project_dir;
            req.tool = ToolCall {
                name: in0.tool,
                input: in0.input,
            };
            req.context = in0.context;
            req.unattended = opt.unattended || in0.unattended;
            run_decider(d, opt, &mut req)
        }
    };

    let Ok(b) = gojson::to_string(&v) else {
        let _ = out.write_all(LAST_RESORT_JSON.as_bytes());
        return 0;
    };
    if let Err(e) = out.write_all(format!("{b}\n").as_bytes()) {
        let _ = writeln!(err_out, "callguard: could not write the verdict: {e}");
    }
    0
}

#[cfg(test)]
mod tests {
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
        let (out, _, code) =
            run_claude(&payload("claude_posttooluse.json"), &Options::default(), &d);
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
            r.project_dir.is_empty()
                && r.context.is_empty()
                && r.meta.is_none()
                && r.facts.is_none()
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
            let want = format!("{}\n", gojson::to_string(&v).unwrap());
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
            format!("{}\n", gojson::to_string(&lr).unwrap()),
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
}
