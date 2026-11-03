//! The decision log: one JSON line per decision (internal/declog). Stub
//! (worker C).
#![allow(unused_variables, dead_code)]

use std::io;
use std::sync::Mutex;

use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;

use crate::serde_util::{is_false, is_zero, nullable, raw_some};

/// How much of the log's end the deny-streak reader looks at.
pub const TAIL_BYTES: u64 = 1 << 20;

/// One log line. It never holds transcript text. `reason` is empty for llm
/// verdicts unless input logging is on, because it can quote arguments.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Entry {
    #[serde(deserialize_with = "nullable")]
    pub ts: String,
    #[serde(deserialize_with = "nullable")]
    pub id: String,
    #[serde(
        skip_serializing_if = "String::is_empty",
        deserialize_with = "nullable"
    )]
    pub session_id: String,
    #[serde(
        skip_serializing_if = "String::is_empty",
        deserialize_with = "nullable"
    )]
    pub tool_use_id: String,
    #[serde(
        skip_serializing_if = "String::is_empty",
        deserialize_with = "nullable"
    )]
    pub harness: String,
    #[serde(deserialize_with = "nullable")]
    pub tool: String,
    #[serde(deserialize_with = "nullable")]
    pub kind: String,
    #[serde(deserialize_with = "nullable")]
    pub input_sha256: String,
    #[serde(deserialize_with = "nullable")]
    pub decision: String,
    #[serde(deserialize_with = "nullable")]
    pub enforced: bool,
    #[serde(deserialize_with = "nullable")]
    pub layer: String,
    #[serde(
        skip_serializing_if = "String::is_empty",
        deserialize_with = "nullable"
    )]
    pub rule: String,
    #[serde(deserialize_with = "nullable")]
    pub confidence: f64,
    #[serde(
        skip_serializing_if = "String::is_empty",
        deserialize_with = "nullable"
    )]
    pub backend: String,
    #[serde(
        skip_serializing_if = "String::is_empty",
        deserialize_with = "nullable"
    )]
    pub policy_rev: String,
    #[serde(deserialize_with = "nullable")]
    pub latency_ms: i64,
    #[serde(skip_serializing_if = "is_false", deserialize_with = "nullable")]
    pub unattended: bool,
    #[serde(skip_serializing_if = "is_zero", deserialize_with = "nullable")]
    pub input_tokens: i64,
    #[serde(skip_serializing_if = "is_zero", deserialize_with = "nullable")]
    pub output_tokens: i64,
    /// An llm deny turned into ask by the deny streak.
    #[serde(skip_serializing_if = "is_false", deserialize_with = "nullable")]
    pub escalated: bool,
    /// Verdicts of layers in shadow mode that did not end the pipeline.
    #[serde(skip_serializing_if = "Vec::is_empty", deserialize_with = "nullable")]
    pub shadow: Vec<ShadowVerdict>,
    #[serde(
        skip_serializing_if = "String::is_empty",
        deserialize_with = "nullable"
    )]
    pub reason: String,
    #[serde(skip_serializing_if = "Option::is_none", deserialize_with = "raw_some")]
    pub input: Option<Box<RawValue>>,
}

/// What a layer in shadow mode would have decided. It has no reason text:
/// that can quote arguments.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct ShadowVerdict {
    #[serde(deserialize_with = "nullable")]
    pub layer: String,
    #[serde(deserialize_with = "nullable")]
    pub decision: String,
    #[serde(
        skip_serializing_if = "String::is_empty",
        deserialize_with = "nullable"
    )]
    pub rule: String,
}

/// `<state dir>/callguard/decisions.jsonl`.
pub fn default_path() -> String {
    todo!("port declog.DefaultPath")
}

/// Appends entries to one file. Safe for concurrent use.
#[derive(Debug)]
pub struct Logger {
    path: String,
    lock: Mutex<()>,
}

impl Logger {
    /// The file and its directory are created on the first append (dir 0700,
    /// file 0600).
    pub fn new(path: &str) -> Logger {
        Logger {
            path: path.to_owned(),
            lock: Mutex::new(()),
        }
    }

    pub fn path(&self) -> &str {
        &self.path
    }

    /// Writes `e` as one line, in a single write.
    pub fn append(&self, e: &Entry) -> io::Result<()> {
        todo!("port Logger.Append")
    }
}

/// The entries of `session_id` within the last [`TAIL_BYTES`] of the file,
/// oldest first. A missing file is no entries. Unparseable lines are skipped.
pub fn read_tail(path: &str, session_id: &str) -> io::Result<Vec<Entry>> {
    todo!("port declog.ReadTail")
}

/// Counts the session's enforced llm-layer denies: those in a row at the end
/// of the llm-layer history (consecutive) and all of them (total). Entries of
/// other layers neither count nor break the run, and neither do escalated
/// denies.
pub fn llm_denies(entries: &[Entry]) -> (usize, usize) {
    todo!("port declog.LLMDenies")
}
