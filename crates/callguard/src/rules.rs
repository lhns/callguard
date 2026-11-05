//! Maps tool calls to kinds, extracts paths and commands from their input, and
//! evaluates the built-in and policy rules.
//!
//! Every regex here and in a policy is RE2. [`compile_regex`] makes the
//! `regex` crate read it that way, because the two differ where it
//! matters for a guard: RE2's `\b`, `\s`, `\w` and `\d` are ASCII-only, the
//! `regex` crate's are Unicode.

use std::collections::BTreeMap;
use std::sync::LazyLock;

use ::regex::Regex;
use serde_json::Value;
use serde_json::value::RawValue;

use crate::permissions::prog_name;
use crate::policy::{self, quote_string};
use crate::schema::Decision;

/// Tool kinds (design section 4).
pub(crate) const KIND_SHELL: &str = "shell";
pub(crate) const KIND_READ: &str = "read";
pub(crate) const KIND_WRITE: &str = "write";
pub(crate) const KIND_FETCH: &str = "fetch";
pub(crate) const KIND_AGENT: &str = "agent";
pub(crate) const KIND_MCP: &str = "mcp";
pub(crate) const KIND_OTHER: &str = "other";

/// A rule could not be built (bad regex or glob). The text names the rule.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct RulesError(pub String);

/// The kind of the tool called `tool`. Names are case-sensitive and do not
/// collide across harnesses, so one table serves all of them (a request from
/// an unknown harness still maps sensibly).
pub(crate) fn kind_of(tool: &str) -> &'static str {
    match tool {
        // Claude Code
        "Bash" | "PowerShell" => KIND_SHELL,
        "Read" | "Glob" | "Grep" | "LS" => KIND_READ,
        "Write" | "Edit" | "MultiEdit" | "NotebookEdit" => KIND_WRITE,
        "WebFetch" | "WebSearch" => KIND_FETCH,
        "Task" | "Agent" => KIND_AGENT,
        // opencode
        "bash" => KIND_SHELL,
        "read" | "glob" | "grep" | "list" => KIND_READ,
        "write" | "edit" | "patch" => KIND_WRITE,
        "webfetch" | "websearch" => KIND_FETCH,
        "task" => KIND_AGENT,
        // pi (bash, read, write, edit above)
        "find" | "ls" => KIND_READ,
        "multi-edit" => KIND_WRITE,
        // Hermes
        "terminal" | "execute_code" | "process" => KIND_SHELL,
        "read_file" | "search_files" => KIND_READ,
        "write_file" => KIND_WRITE,
        "web_search" | "web_extract" => KIND_FETCH,
        t if t.len() > 5 && t.starts_with("mcp__") => KIND_MCP,
        _ => KIND_OTHER,
    }
}

mod regex;
pub(crate) use regex::*;
mod env;
pub use env::*;
mod call;
pub use call::*;
mod builtin;
pub use builtin::*;
mod critical;
pub(crate) use critical::find as critical_target;
mod set;
pub use set::*;

#[cfg(test)]
mod tests;
