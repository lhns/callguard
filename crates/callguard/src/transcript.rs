//! The reasoning-blind view of a conversation: user text, the assistant text a
//! user reply referred to, tool calls and their outcome labels (design
//! section 7, ADR 0005). Tool output never gets here. Stub (worker B).
#![allow(unused_variables, dead_code)]

use std::collections::HashSet;
use std::io;

use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;

use crate::serde_util::{nullable, raw_some};

/// Roles of a [`Message`].
pub const ROLE_USER: &str = "user";
pub const ROLE_ASSISTANT: &str = "assistant";
pub const ROLE_TOOL_CALL: &str = "tool_call";
pub const ROLE_OUTCOME: &str = "outcome";
/// Internal marker, never rendered.
pub const ROLE_THIRD_PARTY: &str = "third_party";

/// Outcomes of a tool call, derived from the harness's status and the start of
/// its error text, never from tool output.
pub const OUTCOME_OK: &str = "ok";
pub const OUTCOME_ERROR: &str = "error";
pub const OUTCOME_INTERRUPTED: &str = "interrupted";
pub const OUTCOME_REJECTED_BY_USER: &str = "rejected-by-user";
pub const OUTCOME_BLOCKED_BY_PERMISSIONS: &str = "blocked-by-permissions";
pub const OUTCOME_BLOCKED_BY_CLASSIFIER: &str = "blocked-by-classifier";
pub const OUTCOME_BLOCKED_BY_CALLGUARD: &str = "blocked-by-callguard";
pub const OUTCOME_CLASSIFIER_UNAVAILABLE: &str = "classifier-unavailable";

/// One kept entry. "user" and "assistant" carry `text`; "tool_call" carries
/// `tool`, `input` and `id`; "outcome" carries the `id` of its call and an
/// `outcome`, never any tool output; "third_party" marks text from someone
/// other than the user and carries nothing.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Message {
    #[serde(deserialize_with = "nullable")]
    pub role: String,
    #[serde(
        skip_serializing_if = "String::is_empty",
        deserialize_with = "nullable"
    )]
    pub text: String,
    #[serde(
        skip_serializing_if = "String::is_empty",
        deserialize_with = "nullable"
    )]
    pub tool: String,
    #[serde(skip_serializing_if = "Option::is_none", deserialize_with = "raw_some")]
    pub input: Option<Box<RawValue>>,
    #[serde(
        skip_serializing_if = "String::is_empty",
        deserialize_with = "nullable"
    )]
    pub id: String,
    #[serde(
        skip_serializing_if = "String::is_empty",
        deserialize_with = "nullable"
    )]
    pub outcome: String,
}

/// Whether `s` is a known outcome value.
pub fn valid_outcome(s: &str) -> bool {
    todo!("port transcript.ValidOutcome")
}

/// Reads the last 2 MiB of a Claude Code JSONL transcript. Unparseable lines
/// are skipped; a file with nothing usable yields an empty vector. Thinking and
/// tool_result content are dropped; a tool_result only yields an outcome label.
pub fn read_claude_jsonl(
    path: &str,
    max_messages: usize,
    max_bytes: usize,
) -> io::Result<Vec<Message>> {
    todo!("port transcript.ReadClaudeJSONL")
}

/// Keeps assistant text only as the referent of a following user reply.
pub fn referents(msgs: Vec<Message>) -> Vec<Message> {
    todo!("port transcript.Referents")
}

/// Marks the tool calls whose ids are in `ids` as blocked by callguard.
pub fn mark_blocked(msgs: Vec<Message>, ids: &HashSet<String>) -> Vec<Message> {
    todo!("port transcript.MarkBlocked")
}

/// Keeps the newest messages within both limits.
pub fn limit(msgs: Vec<Message>, max_messages: usize, max_bytes: usize) -> Vec<Message> {
    todo!("port transcript.Limit")
}
