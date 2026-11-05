//! Builds the reasoning-blind prompt for the LLM layer, calls a backend and
//! validates its answer.
//!
//! Every JSON line of the user prompt goes through [`crate::json_text`], so `<`,
//! `>` and `&` are escaped: no value can close the `<transcript>` tag
//! or start a line with markup.

use std::collections::{BTreeMap, HashMap};
use std::sync::LazyLock;
use std::time::Instant;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use serde_json::value::RawValue;

use crate::backend::{Backend, BackendError, ClassifyRequest};
use crate::hostmeta::{GitStatus, RepoVisibility};
use crate::json_text;
use crate::schema::Decision;
pub(crate) use crate::schema::Note;
use crate::serde_util::{nullable, raw_some};
use crate::transcript::{self, TRUNC_MARKER};

/// The system prompt template; one copy.
const PROMPT_FILE: &str = include_str!("../assets/prompt.md");

/// The only decisions the judge may return.
pub(crate) const LABELS: [&str; 3] = ["allow", "ask", "deny"];

/// The JSON schema the backend must force the answer into. The reason comes
/// first so the model reasons before it decides.
pub(crate) const SCHEMA: &str = concat!(
    r#"{"type":"object","properties":{"#,
    r#""reason":{"type":"string"},"#,
    r#""rule":{"type":"string"},"#,
    r#""decision":{"type":"string","enum":["allow","ask","deny"]},"#,
    r#""confidence":{"type":"number"}},"#,
    r#""required":["decision","confidence","rule","reason"],"additionalProperties":false}"#
);

const MAX_STRING_BYTES: usize = 8 << 10;
const MAX_INPUT_BYTES: usize = 16 << 10;
const MAX_FACT_STRING: usize = 2 << 10;
const MAX_FACTS_BYTES: usize = 8 << 10;
const MAX_GIT_FILES: usize = 30;
const MAX_GIT_FILE_LEN: usize = 512;
/// The judge reads at most the last 8 KiB of the host's instructions.
const MAX_INSTRUCTIONS_BYTES: usize = 8 << 10;
/// Shared by all notes on one tool call.
const MAX_NOTE_CHARS: usize = 2000;
const INSTRUCTIONS_CUT_MARKER: &str = "[earlier instructions cut]…";
pub(crate) const MAX_REASON_RUNES: usize = 500;
const MAX_RULE_RUNES: usize = 64;

/// Why the judge gave no usable verdict. The caller turns every error into a
/// fallback verdict; the judge never returns allow on error.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub(crate) enum JudgeError {
    /// The backend answered, but not with a usable verdict.
    #[error("judge: invalid backend output: {0}")]
    InvalidOutput(String),
    #[error("judge: encoding input: {0}")]
    Encoding(String),
    #[error("{0}")]
    Backend(#[from] BackendError),
}

/// What the judge may see. Assistant text appears only as the referent of a
/// later user message, and tool results never appear. Serialized, it is the
/// structured `input` sent to non-generative backends.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub(crate) struct Input {
    #[serde(
        skip_serializing_if = "String::is_empty",
        deserialize_with = "nullable"
    )]
    pub harness: String,
    #[serde(deserialize_with = "nullable")]
    pub tool: String,
    #[serde(deserialize_with = "nullable")]
    pub kind: String,
    #[serde(
        rename = "input",
        skip_serializing_if = "Option::is_none",
        deserialize_with = "raw_some"
    )]
    pub tool_input: Option<Box<RawValue>>,
    #[serde(
        skip_serializing_if = "String::is_empty",
        deserialize_with = "nullable"
    )]
    pub cwd: String,
    #[serde(
        skip_serializing_if = "String::is_empty",
        deserialize_with = "nullable"
    )]
    pub project_dir: String,
    #[serde(
        skip_serializing_if = "BTreeMap::is_empty",
        deserialize_with = "nullable"
    )]
    pub context: BTreeMap<String, String>,
    #[serde(
        skip_serializing_if = "crate::serde_util::is_false",
        deserialize_with = "nullable"
    )]
    pub unattended: bool,
    #[serde(skip_serializing_if = "Vec::is_empty", deserialize_with = "nullable")]
    pub transcript: Vec<transcript::Message>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub git_status: Option<GitStatus>,
    #[serde(skip_serializing_if = "Vec::is_empty", deserialize_with = "nullable")]
    pub repo_visibility: Vec<RepoVisibility>,
    /// `schema::Facts` as JSON. Its strings are untrusted data.
    #[serde(skip_serializing_if = "Option::is_none", deserialize_with = "raw_some")]
    pub facts: Option<Box<RawValue>>,
    /// Host-supplied instruction text. Unverified: it never establishes user
    /// intent or consent.
    #[serde(
        skip_serializing_if = "String::is_empty",
        deserialize_with = "nullable"
    )]
    pub instructions: String,
    /// Host annotations on earlier tool results, by tool call id. Unverified.
    #[serde(skip_serializing_if = "Vec::is_empty", deserialize_with = "nullable")]
    pub notes: Vec<Note>,
}

/// The policy's prose slots and threshold.
#[derive(Debug, Clone, Default)]
pub(crate) struct Config {
    pub environment: Vec<String>,
    pub block: Vec<String>,
    pub allow_exceptions: Vec<String>,
    pub min_confidence: f64,
}

/// A validated judge answer. An allow below `min_confidence` is already an ask.
/// `input_cut` is true if the judge saw the tool input cut short (see
/// [`cap_input`]).
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct JudgeResult {
    pub decision: Decision,
    pub confidence: f64,
    pub rule: String,
    pub reason: String,
    pub input_cut: bool,
    pub input_tokens: i64,
    pub output_tokens: i64,
}

/// Asks `b` about `input`. Any error (transport, timeout, invalid label or
/// confidence, unparseable output) is returned; it never returns an allow on
/// error.
pub fn judge(
    b: &dyn Backend,
    cfg: &Config,
    mut input: Input,
    deadline: Instant,
) -> Result<JudgeResult, JudgeError> {
    let (tool_input, input_cut) = cap_input(input.tool_input.take());
    input.tool_input = tool_input;
    input.facts = cap_facts(input.facts.take());
    input.git_status = input.git_status.take().map(cap_git_status);
    input.instructions = cap_instructions(&input.instructions);
    input.notes = cap_notes(std::mem::take(&mut input.notes), &input.transcript);
    let structured = json_text::to_string(&input)
        .ok()
        .and_then(|s| RawValue::from_string(s).ok())
        .ok_or_else(|| JudgeError::Encoding("cannot serialize the input".into()))?;
    let req = ClassifyRequest {
        system: system_prompt(cfg),
        prompt: user_prompt(&input),
        labels: LABELS.iter().map(|s| (*s).to_owned()).collect(),
        schema: RawValue::from_string(SCHEMA.to_owned()).ok(),
        input: Some(structured),
    };
    let res = b.classify(&req, deadline)?;
    let Some(decision) = Decision::parse(&res.label) else {
        return Err(JudgeError::InvalidOutput(format!(
            "label {:?}",
            clip_runes(&res.label, 32)
        )));
    };
    if res.confidence.is_nan() || !(0.0..=1.0).contains(&res.confidence) {
        return Err(JudgeError::InvalidOutput(format!(
            "confidence {}",
            res.confidence
        )));
    }
    let mut out = JudgeResult {
        decision,
        confidence: res.confidence,
        rule: clip_runes(&res.rule, MAX_RULE_RUNES),
        reason: clip_runes(&res.reason, MAX_REASON_RUNES),
        input_cut,
        input_tokens: res.input_tokens,
        output_tokens: res.output_tokens,
    };
    // A HARD rule cannot be cleared by a human prompt. Unknown rule ids are
    // kept as the model wrote them.
    if out.decision == Decision::Ask && is_hard(&out.rule) {
        out.decision = Decision::Deny;
    }
    if out.decision == Decision::Allow && out.confidence < cfg.min_confidence {
        out.decision = Decision::Ask;
    }
    Ok(out)
}

/// `s` trimmed and cut to `n` characters.
pub(crate) fn clip_runes(s: &str, n: usize) -> String {
    let s = s.trim();
    s.char_indices()
        .nth(n)
        .map_or_else(|| s.to_owned(), |(i, _)| s[..i].to_owned())
}

/// Keeps the last 8 KiB, cut on a character boundary: the files closest to the
/// work come last, so they win.
fn cap_instructions(text: &str) -> String {
    let t = text.trim();
    if t.len() <= MAX_INSTRUCTIONS_BYTES {
        return t.to_owned();
    }
    let start = t.ceil_char_boundary(t.len() - MAX_INSTRUCTIONS_BYTES);
    format!("{INSTRUCTIONS_CUT_MARKER}{}", &t[start..])
}

/// Drops notes for calls the judge does not see, and keeps at most 2,000
/// characters per call across its notes, in order.
fn cap_notes(notes: Vec<Note>, shown: &[transcript::Message]) -> Vec<Note> {
    let mut left: HashMap<String, usize> = HashMap::new();
    let mut out = Vec::new();
    for n in notes {
        if n.text.trim().is_empty()
            || !shown
                .iter()
                .any(|m| m.role == transcript::ROLE_TOOL_CALL && m.id == n.tool_use_id)
        {
            continue;
        }
        let room = left.entry(n.tool_use_id.clone()).or_insert(MAX_NOTE_CHARS);
        if *room == 0 {
            continue;
        }
        let text = match n.text.char_indices().nth(*room) {
            Some((i, _)) => format!("{}{TRUNC_MARKER}", &n.text[..i]),
            None => n.text.clone(),
        };
        *room -= n.text.chars().count().min(*room);
        out.push(Note { text, ..n });
    }
    out
}

/// Keeps at most 30 files, each at most 512 bytes.
fn cap_git_status(mut g: GitStatus) -> GitStatus {
    if g.files.len() > MAX_GIT_FILES {
        g.files.truncate(MAX_GIT_FILES);
        g.files_truncated = true;
    }
    for f in &mut g.files {
        *f = cut_string(f, MAX_GIT_FILE_LEN);
    }
    g
}

/// Limits each facts string to 2 KiB and the document to 8 KiB.
fn cap_facts(raw: Option<Box<RawValue>>) -> Option<Box<RawValue>> {
    let raw = raw?;
    if !non_empty_object(raw.get()) {
        return None;
    }
    cap_json(Some(raw), MAX_FACT_STRING, MAX_FACTS_BYTES).0
}

/// Limits each string in `raw` to 8 KiB and the whole document to 16 KiB,
/// marking cuts with a "…[truncated]" suffix. If shrinking the strings is not
/// enough, the document becomes one truncated string. The flag says whether
/// anything was cut.
fn cap_input(raw: Option<Box<RawValue>>) -> (Option<Box<RawValue>>, bool) {
    cap_json(raw, MAX_STRING_BYTES, MAX_INPUT_BYTES)
}

pub(crate) fn cap_json(
    raw: Option<Box<RawValue>>,
    max_string: usize,
    max_total: usize,
) -> (Option<Box<RawValue>>, bool) {
    let Some(raw) = raw else {
        return (None, false);
    };
    let text = raw.get();
    let mut cut = true;
    let out = match serde_json::from_str::<Value>(text) {
        Err(_) => cap_raw(text, max_total),
        Ok(v) => {
            // Keep the original key order when nothing needs shrinking.
            let compact = json_text::compact(text);
            if compact.len() <= max_total && !has_long_string(&v, max_string) {
                cut = false;
                compact
            } else {
                let mut limit = max_string;
                let mut shrunk = None;
                while limit >= 128 {
                    if let Ok(out) = json_text::to_string(&shrink(&v, limit))
                        && out.len() <= max_total
                    {
                        shrunk = Some(out);
                        break;
                    }
                    limit /= 2;
                }
                shrunk.unwrap_or_else(|| cap_raw(text, max_total))
            }
        }
    };
    (RawValue::from_string(out).ok(), cut)
}

fn has_long_string(v: &Value, limit: usize) -> bool {
    match v {
        Value::String(s) => s.len() > limit,
        Value::Array(a) => a.iter().any(|e| has_long_string(e, limit)),
        Value::Object(o) => o
            .iter()
            .any(|(k, e)| k.len() > limit || has_long_string(e, limit)),
        _ => false,
    }
}

fn cap_raw(raw: &str, max_total: usize) -> String {
    json_text::to_string(&cut_string(raw, max_total / 2)).unwrap_or_else(|_| "\"\"".into())
}

fn shrink(v: &Value, limit: usize) -> Value {
    match v {
        Value::String(s) => Value::String(cut_string(s, limit)),
        Value::Array(a) => Value::Array(a.iter().map(|e| shrink(e, limit)).collect()),
        Value::Object(o) => Value::Object(
            o.iter()
                .map(|(k, e)| (cut_string(k, limit), shrink(e, limit)))
                .collect(),
        ),
        other => other.clone(),
    }
}

/// Cuts `s` to `limit` bytes on a character boundary and marks the cut.
pub(crate) fn cut_string(s: &str, limit: usize) -> String {
    if s.len() <= limit {
        return s.to_owned();
    }
    format!("{}{TRUNC_MARKER}", &s[..s.floor_char_boundary(limit)])
}

fn non_empty_object(raw: &str) -> bool {
    let t = raw.trim();
    !(t.is_empty() || t == "null" || t == "{}")
}

// Slot markers in prompt.md.
const SLOT_ENVIRONMENT: &str = "<!-- slot:environment -->";
const SLOT_BLOCK: &str = "<!-- slot:block -->";
const SLOT_ALLOW: &str = "<!-- slot:allow -->";

/// A prompt file without its leading provenance comment.
pub(crate) fn strip_provenance(file: &str) -> &str {
    let s = file.trim();
    match s.strip_prefix("<!--").and_then(|r| r.split_once("-->")) {
        Some((_, rest)) => rest.trim(),
        None => s,
    }
}

/// The rendered system prompt: prompt.md without its provenance comment, with
/// the policy slots filled in. It has no timestamps or per-call data, so
/// backends can cache it.
pub(crate) fn system_prompt(cfg: &Config) -> String {
    let s = strip_provenance(PROMPT_FILE);
    let env = if cfg.environment.is_empty() {
        "No additional environment entries.".to_owned()
    } else {
        format!(
            "Additional environment entries from policy:\n{}",
            bullets(&cfg.environment, "")
        )
    };
    let block: Vec<String> = cfg
        .block
        .iter()
        .enumerate()
        .map(|(i, t)| format!("`policy-block-{}` **Policy block**: {t}", i + 1))
        .collect();
    let allow = if cfg.allow_exceptions.is_empty() {
        "No additional exceptions.".to_owned()
    } else {
        bullets(&cfg.allow_exceptions, "**Policy exception**: ")
    };
    let slots = [
        (SLOT_ENVIRONMENT, env),
        (SLOT_BLOCK, bullets(&block, "")),
        (SLOT_ALLOW, allow),
    ];
    // One pass: replacement text is never rescanned, so
    // a policy string that contains a marker stays as written.
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some((at, marker, text)) = slots
        .iter()
        .filter_map(|(m, t)| rest.find(m).map(|i| (i, *m, t)))
        .min_by_key(|(i, _, _)| *i)
    {
        out.push_str(&rest[..at]);
        out.push_str(text);
        rest = &rest[at + marker.len()..];
    }
    out.push_str(rest);
    out
}

fn bullets(items: &[String], prefix: &str) -> String {
    items
        .iter()
        .map(|it| format!("- {prefix}{it}"))
        .collect::<Vec<_>>()
        .join("\n")
}

#[derive(Serialize)]
struct SessionInfo<'a> {
    #[serde(skip_serializing_if = "str::is_empty")]
    harness: &'a str,
    #[serde(skip_serializing_if = "str::is_empty")]
    cwd: &'a str,
    #[serde(skip_serializing_if = "str::is_empty")]
    project_dir: &'a str,
    #[serde(skip_serializing_if = "crate::serde_util::is_false")]
    unattended: bool,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    context: &'a BTreeMap<String, String>,
}

#[derive(Serialize)]
struct CallLine<'a> {
    id: &'a str,
    tool: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    input: Option<&'a RawValue>,
}

#[derive(Serialize)]
struct NoteLine<'a> {
    id: &'a str,
    text: &'a str,
}

#[derive(Serialize)]
struct OutcomeLine<'a> {
    outcome: &'a str,
    id: &'a str,
}

#[derive(Serialize)]
struct ActionLine<'a> {
    tool: &'a str,
    kind: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    input: Option<&'a RawValue>,
}

/// `{key: value}` as one escaped JSON line. Raw values keep their key order.
pub(crate) fn line<T: Serialize + ?Sized>(key: &str, v: &T) -> String {
    let mut s = String::from("{");
    s.push_str(&serde_json::to_string(key).unwrap_or_else(|_| "\"\"".into()));
    s.push(':');
    // Cannot fail for the types used here; never leave a hole.
    s.push_str(
        &serde_json::to_string(v)
            .unwrap_or_else(|_| r#"{"meta":{"error":"unencodable line"}}"#.into()),
    );
    s.push('}');
    json_text::escape(&s)
}

/// `{"meta":{key: value}}` as one escaped JSON line.
fn meta_line<T: Serialize + ?Sized>(key: &str, v: &T) -> String {
    // `line` escapes already.
    format!("{{\"meta\":{}}}", line(key, v))
}

/// The lines every prompt starts with: session info, host instructions, the
/// transcript with its notes.
pub(crate) fn history_lines(input: &Input) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut push = |l: String| out.push(l);

    let session = SessionInfo {
        harness: &input.harness,
        cwd: &input.cwd,
        project_dir: &input.project_dir,
        unattended: input.unattended,
        context: &input.context,
    };
    if !input.harness.is_empty()
        || !input.cwd.is_empty()
        || !input.project_dir.is_empty()
        || input.unattended
        || !input.context.is_empty()
    {
        push(meta_line("session", &session));
    }
    if !input.instructions.is_empty() {
        push(meta_line("hostInstructions", &input.instructions));
    }
    let mut ids: HashMap<&str, String> = HashMap::new();
    let mut calls = 0;
    for m in &input.transcript {
        match m.role.as_str() {
            transcript::ROLE_USER => push(line("user", &m.text)),
            transcript::ROLE_ASSISTANT => push(line("assistant", &m.text)),
            transcript::ROLE_TOOL_CALL => {
                calls += 1;
                let id = format!("c{calls}");
                if !m.id.is_empty() {
                    ids.insert(&m.id, id.clone());
                }
                push(line(
                    "call",
                    &CallLine {
                        id: &id,
                        tool: &m.tool,
                        input: m.input.as_deref(),
                    },
                ));
                for n in input.notes.iter().filter(|n| n.tool_use_id == m.id) {
                    push(meta_line(
                        "hostNote",
                        &NoteLine {
                            id: &id,
                            text: &n.text,
                        },
                    ));
                }
            }
            transcript::ROLE_OUTCOME => {
                if let Some(id) = ids.get(m.id.as_str())
                    && transcript::valid_outcome(&m.outcome)
                {
                    push(
                        json_text::to_string(&OutcomeLine {
                            outcome: &m.outcome,
                            id,
                        })
                        .unwrap_or_default(),
                    );
                }
            }
            _ => {}
        }
    }
    out
}

/// The rendered user message: session info, transcript, the pending call.
/// Every line is one escaped JSON object, so `<`, `>` and `&` are escaped and
/// newlines inside strings stay inside their string: no value can start a
/// line or close the tag.
pub(crate) fn user_prompt(input: &Input) -> String {
    let mut b = String::from("<transcript>\n");
    let mut push = |l: String| {
        b.push_str(&l);
        b.push('\n');
    };
    for l in history_lines(input) {
        push(l);
    }
    if let Some(g) = &input.git_status {
        push(meta_line("gitStatus", g));
    }
    for rv in &input.repo_visibility {
        push(meta_line("repoVisibility", rv));
    }
    if let Some(f) = input.facts.as_deref()
        && non_empty_object(f.get())
    {
        push(meta_line("nah", f));
    }
    push(line(
        "action",
        &ActionLine {
            tool: &input.tool,
            kind: &input.kind,
            input: input.tool_input.as_deref(),
        },
    ));
    b.push_str("</transcript>\nDecide the action on the last line.");
    b
}

/// The rule ids the prompt defines; true marks a HARD rule. The dynamic ids
/// policy-block-N are HARD too, see [`is_hard`]. prompt.md and this table must
/// list the same ids.
pub(crate) fn rule_ids() -> &'static BTreeMap<&'static str, bool> {
    static IDS: LazyLock<BTreeMap<&'static str, bool>> = LazyLock::new(|| {
        let hard = ["data-exfiltration"];
        let soft = [
            "git-destructive",
            "code-leaks-when-run",
            "code-from-external",
            "data-store-mass-delete",
            "production-deploy",
            "remote-shell-writes",
            "sensitive-remote-exec",
            "production-reads",
            "blind-apply",
            "protected-iac-apply",
            "logging-audit-tampering",
            "permission-grant",
            "account-standing-rule-changes",
            "tls-auth-weaken",
            "secret-store-writes",
            "dns-domain-cert-changes",
            "security-weaken",
            "security-test-removal",
            "safety-bypass-flag",
            "create-unsafe-agents",
            "interfere-with-workloads",
            "shared-cluster-mutation",
            "ci-bypass",
            "modify-shared-resources",
            "irreversible-local-destruction",
            "unverifiable-deletion-target",
            "shared-scratch-sweep",
            "irreversible-deletion",
            "unverifiable-deletion-scope",
            "create-rce-surface",
            "expose-local-services",
            "external-ingress-tunnel",
            "credential-leakage",
            "credential-materialization",
            "credential-exploration",
            "pii-data-handling",
            "exfil-scouting",
            "traffic-redirection",
            "remote-repoint",
            "out-of-place-publication",
            "sensitive-source-provenance",
            "excess-sensitive-detail",
            "containment-escape",
            "create-public-surface",
            "public-data-sharing-upload",
            "untrusted-code-integration",
            "package-registry-bypass",
            "unauthorized-persistence",
            "self-modification",
            "instruction-poisoning",
            "guard-bypass",
            "session-transcript-tampering",
            "unrequested-commit",
            "external-system-writes",
            "merge-without-review",
            "self-approval",
            "chatops-trigger",
            "feature-flag-writes",
            "node-lifecycle",
            "cluster-wide-workload",
            "real-world-transactions",
            "third-party-attack",
            "unverifiable-payload",
            "user-boundary",
            "rejected-retry",
        ];
        hard.iter()
            .map(|id| (*id, true))
            .chain(soft.iter().map(|id| (*id, false)))
            .collect()
    });
    &IDS
}

/// Whether `rule` is a HARD rule (a hard prompt rule or `policy-block-N`).
pub(crate) fn is_hard(rule: &str) -> bool {
    rule_ids().get(rule) == Some(&true)
        || rule
            .strip_prefix("policy-block-")
            .is_some_and(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()))
}

#[cfg(test)]
mod tests;
