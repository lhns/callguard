//! Turns harness hook payloads into callguard requests and callguard verdicts
//! into each harness's native answer. The adapters never fail open: every
//! internal failure becomes an ask/deny answer the harness honours
//! (docs/design.md sections 9 and 10).
//!
//! A [`Decider`] borrows the request; the adapters catch panics from it
//! (`catch_unwind`) and answer with the fallback.

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::panic::{AssertUnwindSafe, catch_unwind};

use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;

use crate::fallback::{fallback_verdict, panic_message};
use crate::handback::{self, Review, SubagentReport};
use crate::io_util::{MAX_INPUT, read_capped};
use crate::json_text;
use crate::schema::{
    Decision, LAYER_FALLBACK, REQUEST_SCHEMA, Request, ToolCall, Transcript, VERDICT_SCHEMA,
    Verdict,
};
use crate::serde_util::{decode_object, decode_partial, nullable, raw_some};

/// Caps `--context-file`.
const MAX_CONTEXT_FILE: usize = 1 << 20;

/// Decides one request.
pub(crate) type Decider<'a> = &'a (dyn Fn(&Request) -> Verdict + Sync);

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
    /// `--add-dir` entries, appended to `req.additional_dirs`.
    pub additional_dirs: Vec<String>,
    /// Claude only: where `InstructionsLoaded` events are recorded and where
    /// PreToolUse reads them from (see [`crate::instructions`]). None = off.
    pub instructions_dir: Option<std::path::PathBuf>,
    /// Claude only: review sub-agent reports in `permission_mode` auto too
    /// (`--review-in-auto`); Claude reviews them itself there.
    pub review_in_auto: bool,
}

/// Reviews a sub-agent's report (Claude's `PostToolUse` on `Agent`/`Task`).
/// Advisory: whatever it returns, the hook exits 0.
pub type Reviewer<'a> = &'a (dyn Fn(&SubagentReport) -> Review + Sync);

/// Reads `input` up to [`MAX_INPUT`].
fn read_input(input: &mut dyn Read) -> Result<Vec<u8>, String> {
    read_capped(input, MAX_INPUT)
        .map_err(|e| format!("reading stdin: {e}"))?
        .ok_or_else(|| format!("input larger than {MAX_INPUT} bytes"))
}

/// Parses a hook payload: a JSON object, or an error. Field names match in any
/// letter case.
fn parse_object<T: for<'de> Deserialize<'de>>(body: &[u8], known: &[&str]) -> Result<T, String> {
    decode_object(body, known, &[]).map_err(|e| format!("payload: {e}"))
}

/// Like [`parse_object`], but a payload with a mistyped field still yields the
/// fields that are right, next to the error: the caller must treat the payload
/// as bad, and can still use `permission_mode` to make that a deny.
fn parse_partial<T: for<'de> Deserialize<'de> + Default>(
    input: &mut dyn Read,
    known: &[&str],
) -> (T, Option<String>) {
    match read_input(input) {
        Ok(body) => {
            let (v, e) = decode_partial(&body, known);
            (v, e.map(|e| format!("payload: {e}")))
        }
        Err(e) => (T::default(), Some(e)),
    }
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
    req.additional_dirs.extend(opt.additional_dirs.clone());
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
        let b = read_capped(&mut { f }, MAX_CONTEXT_FILE)
            .map_err(|e| e.to_string())?
            .ok_or_else(|| {
                format!(
                    "{} is larger than {MAX_CONTEXT_FILE} bytes",
                    opt.context_file
                )
            })?;
        let m: Option<BTreeMap<String, String>> =
            serde_json::from_slice(&b).map_err(|e| format!("{}: {e}", opt.context_file))?;
        req.context.extend(m.unwrap_or_default());
    }
    req.context.extend(opt.context.clone());
    Ok(())
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

const CLAUDE_FIELDS: &[&str] = &[
    "session_id",
    "transcript_path",
    "cwd",
    "permission_mode",
    "hook_event_name",
    "tool_name",
    "tool_input",
    "tool_use_id",
    "file_path",
    "tool_response",
];

#[derive(Deserialize, Default)]
#[serde(default)]
struct ClaudeInput {
    #[serde(deserialize_with = "nullable")]
    file_path: String,
    #[serde(deserialize_with = "raw_some")]
    tool_response: Option<Box<RawValue>>,
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

/// Whether a Claude payload is for an event that cannot block (PostToolUse,
/// InstructionsLoaded). False for anything unreadable: that stays fail-closed.
fn is_advisory_event(body: &[u8]) -> bool {
    catch_unwind(|| {
        let Ok(serde_json::Value::Object(o)) = serde_json::from_slice::<serde_json::Value>(body)
        else {
            return false;
        };
        o.iter().any(|(k, v)| {
            k.eq_ignore_ascii_case("hook_event_name")
                && matches!(v.as_str(), Some("PostToolUse" | "InstructionsLoaded"))
        })
    })
    .unwrap_or(false)
}

/// Runs `adapter`, which gets `err_out`. A panic is exit 2, the one non-zero
/// exit that blocks the call for Claude and Hermes; except when the adapter
/// has marked the event `advisory`, which has nothing to block: exit 0.
fn blocking_on_panic(
    err_out: &mut dyn Write,
    advisory: &std::cell::Cell<bool>,
    adapter: impl FnOnce(&mut dyn Write) -> i32,
) -> i32 {
    match catch_unwind(AssertUnwindSafe(|| adapter(&mut *err_out))) {
        Ok(code) => code,
        Err(_) if advisory.get() => 0,
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

/// Records an `InstructionsLoaded` file. Never fails and never panics out.
fn record_instructions(opt: &Options, in0: &ClaudeInput) {
    if let Some(dir) = &opt.instructions_dir {
        let _ = catch_unwind(AssertUnwindSafe(|| {
            let _ = crate::instructions::record(dir, &in0.session_id, &in0.file_path);
        }));
    }
}

/// The text of the files recorded for the session; empty on any failure.
fn claude_instructions(opt: &Options, session_id: &str) -> String {
    let Some(dir) = &opt.instructions_dir else {
        return String::new();
    };
    catch_unwind(AssertUnwindSafe(|| {
        crate::instructions::collect(dir, session_id)
    }))
    .unwrap_or_default()
}

/// Sub-agent report review: `additionalContext` for the parent agent when the
/// report is flagged or could not be reviewed; nothing otherwise. A panic in
/// the review counts as a failed review. Never blocks.
fn post_tool_use(out: &mut dyn Write, opt: &Options, in0: &ClaudeInput, review: Reviewer) {
    if !matches!(in0.tool_name.as_str(), "Agent" | "Task")
        || (in0.permission_mode == "auto" && !opt.review_in_auto)
    {
        return;
    }
    let ran = catch_unwind(AssertUnwindSafe(|| {
        let report = handback_report(opt, in0)?;
        Some(review(&report))
    }));
    let warning = match ran {
        Ok(None) => return,
        Ok(Some(r)) => r.warning(),
        Err(_) => Review::Failed("internal error".into()).warning(),
    };
    if let Some(ctx) = warning
        && let Ok(b) = json_text::to_string(&ClaudePostOutput {
            hook_specific_output: ClaudePostContext {
                hook_event_name: "PostToolUse",
                additional_context: &ctx,
            },
        })
    {
        let _ = out.write_all(
            format!(
                "{b}
"
            )
            .as_bytes(),
        );
    }
}

/// The report to review; None when there is nothing to review.
fn handback_report(opt: &Options, in0: &ClaudeInput) -> Option<SubagentReport> {
    let response = in0.tool_response.as_deref().map(RawValue::get)?;
    let report = handback::report_text(response);
    if report.trim().is_empty() || response.trim() == "null" {
        return None;
    }
    let input: serde_json::Value = in0
        .tool_input
        .as_deref()
        .and_then(|r| serde_json::from_str(r.get()).ok())
        .unwrap_or_default();
    let field = |k: &str| {
        input
            .get(k)
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_owned()
    };
    let mut ctx = Request::default();
    // An unreadable context file must not let the report go to any backend.
    let context_ok = apply_context(&mut ctx, opt).is_ok();
    let calls = if in0.transcript_path.is_empty() {
        Vec::new()
    } else {
        handback::agent_id(response)
            .map(|id| handback::read_subagent_calls(&in0.transcript_path, &id))
            .unwrap_or_default()
    };
    let mut r = SubagentReport {
        harness: "claude".into(),
        session_id: in0.session_id.clone(),
        tool_use_id: in0.tool_use_id.clone(),
        cwd: in0.cwd.clone(),
        unattended: opt.unattended || in0.permission_mode == "dontAsk",
        tool_name: in0.tool_name.clone(),
        tool_input: in0.tool_input.clone(),
        subagent_type: field("subagent_type"),
        prompt: field("prompt"),
        report,
        calls,
        transcript: (!in0.transcript_path.is_empty()).then(|| Transcript {
            path: in0.transcript_path.clone(),
            format: "claude-jsonl".into(),
            messages: Vec::new(),
        }),
        context: ctx.context,
    };
    if !context_ok {
        // Marks the report so the engine refuses to send it anywhere.
        r.context
            .insert("data_class".into(), "context-file-unreadable".into());
    }
    Some(r)
}

#[derive(Serialize)]
struct ClaudePostOutput<'a> {
    #[serde(rename = "hookSpecificOutput")]
    hook_specific_output: ClaudePostContext<'a>,
}

#[derive(Serialize)]
struct ClaudePostContext<'a> {
    #[serde(rename = "hookEventName")]
    hook_event_name: &'a str,
    #[serde(rename = "additionalContext")]
    additional_context: &'a str,
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
    let advisory = std::cell::Cell::new(false);
    blocking_on_panic(err_out, &advisory, |e| {
        claude_inner(input, &mut *out, e, opt, d, None, &advisory)
    })
}

/// [`claude`] that also reviews sub-agent reports with `review`.
pub fn claude_reviewing(
    input: &mut dyn Read,
    out: &mut dyn Write,
    err_out: &mut dyn Write,
    opt: &Options,
    d: Decider,
    review: Reviewer,
) -> i32 {
    let advisory = std::cell::Cell::new(false);
    blocking_on_panic(err_out, &advisory, |e| {
        claude_inner(input, &mut *out, e, opt, d, Some(review), &advisory)
    })
}

fn claude_inner(
    input: &mut dyn Read,
    out: &mut dyn Write,
    err_out: &mut dyn Write,
    opt: &Options,
    d: Decider,
    review: Option<Reviewer>,
    advisory: &std::cell::Cell<bool>,
) -> i32 {
    let mut req = new_request("claude");
    let (mut in0, mut err) = match read_input(input) {
        Ok(body) => {
            advisory.set(is_advisory_event(&body));
            let (v, e) = decode_partial(&body, CLAUDE_FIELDS);
            (v, e.map(|e| format!("payload: {e}")))
        }
        Err(e) => (ClaudeInput::default(), Some(e)),
    };
    if err.is_none() && in0.hook_event_name.is_empty() {
        err = Some("missing hook_event_name".to_owned());
    }
    // Set before any fallback, so a malformed payload in dontAsk still denies.
    req.unattended = opt.unattended || in0.permission_mode == "dontAsk";
    // Asynchronous, no decision control: record and say nothing, whatever fails.
    if in0.hook_event_name == "InstructionsLoaded" {
        record_instructions(opt, &in0);
        return 0;
    }
    // After the call: advisory, so it can never block and never prints an error.
    if in0.hook_event_name == "PostToolUse" {
        if err.is_none()
            && let Some(review) = review
        {
            post_tool_use(out, opt, &in0, review);
        }
        return 0;
    }
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
        req.instructions = claude_instructions(opt, &in0.session_id);
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
    let written = json_text::to_string(&ClaudeOutput {
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

const HERMES_FIELDS: &[&str] = &[
    "hook_event_name",
    "tool_name",
    "tool_input",
    "session_id",
    "cwd",
];

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
    blocking_on_panic(err_out, &std::cell::Cell::new(false), |e| {
        hermes_inner(input, &mut *out, e, opt, d)
    })
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
    let (in0, mut err) = parse_partial::<HermesInput>(input, HERMES_FIELDS);
    if err.is_none() && in0.hook_event_name.is_empty() {
        err = Some("missing hook_event_name".to_owned());
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
    let written = json_text::to_string(o)
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

// Strict: a mistyped `unattended` must not be dropped silently.
const GENERIC_FIELDS: &[&str] = &[
    "harness",
    "tool",
    "input",
    "cwd",
    "session_id",
    "project_dir",
    "context",
    "unattended",
];

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
    let v = match read_input(input)
        .and_then(|body| parse_object::<GenericInput>(&body, GENERIC_FIELDS))
    {
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

    let Ok(b) = json_text::to_string(&v) else {
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
            ctx.starts_with("SECURITY WARNING from callguard: ")
                && ctx.contains("it asks for curl"),
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
        let ls =
            r#""hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"ls"}"#;
        let (out, err, code) =
            run_claude(&format!("{{{ls},\"cwd\":7}}"), &Options::default(), &allow);
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
}
