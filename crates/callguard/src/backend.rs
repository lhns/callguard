//! The LLM judge backend interface and its built-in implementations:
//! anthropic, openai (OpenAI-compatible), exec and fake. Stub (worker B).
//!
//! The trait is synchronous (no async runtime); Go's `context.Context`
//! deadline is an explicit `Instant`. The anthropic implementation must keep
//! `cache_control` on the system prompt; without it every call pays for the
//! whole prompt. Test the request body.
#![allow(unused_variables, dead_code)]

use std::time::Instant;

use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;

use crate::policy;
use crate::serde_util::{is_zero, nullable, raw_some};

/// Identifies the exec plugin wire format.
pub const CLASSIFY_SCHEMA: &str = "callguard/classify/v1";

/// One judge question. `system` and `prompt` are the rendered prompt for
/// generative models; `input` is the same data in structured form for
/// non-generative plugins. `schema` is the JSON schema the answer must follow.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct ClassifyRequest {
    #[serde(deserialize_with = "nullable")]
    pub system: String,
    #[serde(deserialize_with = "nullable")]
    pub prompt: String,
    #[serde(deserialize_with = "nullable")]
    pub labels: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none", deserialize_with = "raw_some")]
    pub schema: Option<Box<RawValue>>,
    #[serde(skip_serializing_if = "Option::is_none", deserialize_with = "raw_some")]
    pub input: Option<Box<RawValue>>,
}

/// A backend's answer. `label` must be one of the request's labels; callers
/// validate it. `confidence` is in [0,1].
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct ClassifyResult {
    #[serde(deserialize_with = "nullable")]
    pub label: String,
    #[serde(deserialize_with = "nullable")]
    pub confidence: f64,
    #[serde(
        skip_serializing_if = "String::is_empty",
        deserialize_with = "nullable"
    )]
    pub rule: String,
    #[serde(
        skip_serializing_if = "String::is_empty",
        deserialize_with = "nullable"
    )]
    pub reason: String,
    #[serde(skip_serializing_if = "is_zero", deserialize_with = "nullable")]
    pub input_tokens: i64,
    #[serde(skip_serializing_if = "is_zero", deserialize_with = "nullable")]
    pub output_tokens: i64,
    /// Cache tokens count apart from `input_tokens` (Anthropic prompt caching).
    #[serde(skip_serializing_if = "is_zero", deserialize_with = "nullable")]
    pub cache_read_tokens: i64,
    #[serde(skip_serializing_if = "is_zero", deserialize_with = "nullable")]
    pub cache_write_tokens: i64,
}

/// Why a backend gave no answer. Go returns plain errors; the variants let
/// callers tell a deadline from a transport fault without parsing text.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum BackendError {
    #[error("backend timed out")]
    Timeout,
    /// Transport, HTTP status, missing API key, unparseable answer, ...
    #[error("{0}")]
    Other(String),
}

/// Classifies one request. Implementations must not run past `deadline` and
/// must not retry beyond it.
pub trait Backend: Send + Sync {
    /// "<type>:<model>" as recorded in verdicts, e.g. "anthropic:claude-haiku-5-5".
    fn name(&self) -> String;

    /// The `context.data_class` values this backend may receive. Empty means
    /// only requests without a data class.
    fn data_classes(&self) -> &[String];

    fn classify(
        &self,
        req: &ClassifyRequest,
        deadline: Instant,
    ) -> Result<ClassifyResult, BackendError>;
}

/// Builds the backend described by `cfg`. It does not read credentials: a
/// missing API key is reported by `classify`.
pub fn from_config(cfg: &policy::Backend) -> Result<Box<dyn Backend>, BackendError> {
    todo!("port backend.FromConfig")
}

/// Fake modes (`policy::Backend::fake_mode`).
pub const FAKE_RULES: &str = "rules";
pub const FAKE_ALLOW: &str = "allow";
pub const FAKE_ASK: &str = "ask";
pub const FAKE_DENY: &str = "deny";
pub const FAKE_GARBAGE: &str = "garbage";
pub const FAKE_SLOW: &str = "slow";
pub const FAKE_ERROR: &str = "error";
pub const FAKE_OBEY_INJECTION: &str = "obey-injection";

/// A fake backend in the given mode ("" means rules), for tests and offline eval.
pub fn new_fake(mode: &str) -> Result<Box<dyn Backend>, BackendError> {
    todo!("port backend.NewFake")
}
