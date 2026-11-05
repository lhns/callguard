//! The LLM judge backend interface and its built-in implementations:
//! anthropic, openai (OpenAI-compatible), exec and fake.
//!
//! The trait is synchronous (no async runtime); the deadline is an explicit
//! `Instant`. The anthropic implementation keeps
//! `cache_control` on the system prompt; without it every call pays for the
//! whole prompt.

use std::io::{Read, Write};
use std::process::{Command, Stdio};

use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use serde_json::value::RawValue;

use crate::child::{kill, read_in_background, wait_until};
use crate::json_text;
use crate::policy;
use crate::serde_util::{is_zero, nullable, raw_some};

/// Identifies the exec plugin wire format.
pub(crate) const CLASSIFY_SCHEMA: &str = "callguard/classify/v1";

/// One judge question. `system` and `prompt` are the rendered prompt for
/// generative models; `input` is the same data in structured form for
/// non-generative plugins. `schema` is the JSON schema the answer must follow.
#[derive(Debug, Clone, Default)]
pub struct ClassifyRequest {
    pub system: String,
    pub prompt: String,
    pub labels: Vec<String>,
    pub schema: Option<Box<RawValue>>,
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

/// Why a backend gave no answer. The variants let
/// callers tell a deadline from a transport fault without parsing text.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum BackendError {
    #[error("backend timed out")]
    Timeout,
    /// Transport, HTTP status, missing API key, unparseable answer, ...
    #[error("{0}")]
    Other(String),
}

fn other(msg: impl Into<String>) -> BackendError {
    BackendError::Other(msg.into())
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
    if cfg.model.ends_with("-latest") {
        return Err(other(format!(
            "backend model {:?}: use an exact model id, not a -latest alias",
            cfg.model
        )));
    }
    match cfg.r#type.as_str() {
        "anthropic" => Ok(Box::new(Anthropic::new(cfg)?)),
        "openai" => Ok(Box::new(OpenAi::new(cfg)?)),
        "exec" => Ok(Box::new(ExecBackend::new(cfg)?)),
        "fake" => Ok(Box::new(Fake::new(cfg)?)),
        "" => Err(other("backend type is empty")),
        t => Err(other(format!("unknown backend type {t:?}"))),
    }
}

const DEFAULT_MAX_TOKENS: i64 = 1024;
const MAX_ERR_BODY: usize = 200;
const MAX_RESPONSE_BYTES: u64 = 1 << 20;

fn max_tokens(cfg: &policy::Backend) -> i64 {
    if cfg.max_tokens > 0 {
        cfg.max_tokens
    } else {
        DEFAULT_MAX_TOKENS
    }
}

/// The first `n` bytes of `s`, cut on a character boundary.
fn clip(s: &str, n: usize) -> &str {
    &s[..s.floor_char_boundary(n)]
}

mod http;
use http::*;
mod anthropic;
use anthropic::*;
mod openai;
use openai::*;
mod exec;
use exec::*;
mod fake;
pub use fake::*;
mod verdict;
use verdict::parse_verdict_json;

#[cfg(test)]
mod tests;
