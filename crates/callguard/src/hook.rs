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
mod tests;
