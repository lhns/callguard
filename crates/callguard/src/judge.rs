//! Builds the reasoning-blind prompt for the LLM layer, calls a backend and
//! validates its answer (internal/judge). Stub (worker B).
#![allow(unused_variables, dead_code)]

use std::collections::BTreeMap;
use std::time::Instant;

use serde::Serialize;
use serde_json::value::RawValue;

use crate::backend::{Backend, BackendError};
use crate::hostmeta::{GitStatus, RepoVisibility};
use crate::transcript;

/// The system prompt template; one copy, shared with the Go tree until Phase 5.
const PROMPT_FILE: &str = include_str!("../../../internal/judge/prompt.md");

/// The only decisions the judge may return.
pub const LABELS: [&str; 3] = ["allow", "ask", "deny"];

/// The JSON schema the backend must force the answer into. The reason comes
/// first so the model reasons before it decides.
pub const SCHEMA: &str = concat!(
    r#"{"type":"object","properties":{"#,
    r#""reason":{"type":"string"},"#,
    r#""rule":{"type":"string"},"#,
    r#""decision":{"type":"string","enum":["allow","ask","deny"]},"#,
    r#""confidence":{"type":"number"}},"#,
    r#""required":["decision","confidence","rule","reason"],"additionalProperties":false}"#
);

/// Why the judge gave no usable verdict. The caller turns every error into a
/// fallback verdict; the judge never returns allow on error.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum JudgeError {
    /// The backend answered, but not with a usable verdict (Go: `ErrInvalidOutput`).
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
#[derive(Debug, Clone, Default, Serialize)]
pub struct Input {
    #[serde(skip_serializing_if = "String::is_empty")]
    pub harness: String,
    pub tool: String,
    pub kind: String,
    #[serde(rename = "input", skip_serializing_if = "Option::is_none")]
    pub tool_input: Option<Box<RawValue>>,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub cwd: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub project_dir: String,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub context: BTreeMap<String, String>,
    #[serde(skip_serializing_if = "crate::serde_util::is_false")]
    pub unattended: bool,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub transcript: Vec<transcript::Message>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub git_status: Option<GitStatus>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub repo_visibility: Vec<RepoVisibility>,
    /// `schema::Facts` as JSON. Its strings are untrusted data.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub facts: Option<Box<RawValue>>,
}

/// The policy's prose slots and threshold.
#[derive(Debug, Clone, Default)]
pub struct Config {
    pub environment: Vec<String>,
    pub block: Vec<String>,
    pub allow_exceptions: Vec<String>,
    pub min_confidence: f64,
}

/// A validated judge answer. `decision` is "allow", "ask" or "deny". `demoted`
/// is true if `min_confidence` demoted an allow to ask.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct JudgeResult {
    pub decision: String,
    pub confidence: f64,
    pub rule: String,
    pub reason: String,
    pub demoted: bool,
    pub input_tokens: i64,
    pub output_tokens: i64,
}

/// Asks `b` about `input`. Any error (transport, timeout, invalid label or
/// confidence, unparseable output) is returned; it never returns an allow on
/// error. Go's `Judge` (named `judge` here, in module `judge`).
pub fn judge(
    b: &dyn Backend,
    cfg: &Config,
    input: Input,
    deadline: Instant,
) -> Result<JudgeResult, JudgeError> {
    todo!("port judge.Judge")
}

/// The rendered system prompt: prompt.md without its provenance comment, with
/// the policy slots filled in.
pub fn system_prompt(cfg: &Config) -> String {
    todo!("port judge.SystemPrompt")
}

/// The rendered user message: session info, transcript, the pending call.
pub fn user_prompt(input: &Input) -> String {
    todo!("port judge.UserPrompt")
}

/// The rule ids the prompt defines; true marks a HARD rule. The dynamic ids
/// policy-block-N are HARD too, see [`is_hard`].
pub fn rule_ids() -> &'static BTreeMap<&'static str, bool> {
    todo!("port judge.RuleIDs")
}

/// Whether `rule` is a HARD rule (a hard prompt rule or `policy-block-N`).
pub fn is_hard(rule: &str) -> bool {
    todo!("port judge.IsHard")
}
