//! Maps tool calls to kinds, extracts paths and commands from their input, and
//! evaluates the built-in and policy rules (internal/rules). Stub (worker A).
#![allow(unused_variables, dead_code)]

use std::collections::BTreeMap;

use regex::Regex;
use serde_json::value::RawValue;

use crate::policy;

/// Tool kinds (design section 4).
pub const KIND_SHELL: &str = "shell";
pub const KIND_READ: &str = "read";
pub const KIND_WRITE: &str = "write";
pub const KIND_FETCH: &str = "fetch";
pub const KIND_AGENT: &str = "agent";
pub const KIND_MCP: &str = "mcp";
pub const KIND_OTHER: &str = "other";

/// A rule could not be built (bad regex or glob). The text names the rule.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct RulesError(pub String);

/// The kind of the tool called `tool`.
pub fn kind_of(tool: &str) -> &'static str {
    todo!("port rules.KindOf")
}

/// What path handling needs from the host. Symlinks are never resolved.
#[derive(Debug, Clone, Default)]
pub struct Env {
    /// User home directory, "" if unknown.
    pub home: String,
    /// Backslash separators, drive letters, case-insensitive paths.
    pub windows: bool,
    /// Case-insensitive paths on other hosts (macOS default file systems).
    pub fold_case: bool,
}

impl Env {
    /// Describes the running host.
    pub fn host() -> Env {
        todo!("port rules.DefaultEnv")
    }

    /// An absolute, slash-normalized path for `p` relative to `cwd`.
    pub fn normalize(&self, p: &str, cwd: &str) -> String {
        todo!("port Env.Normalize")
    }

    /// Whether `p` is `dir` or inside it.
    pub fn in_dir(&self, p: &str, dir: &str) -> bool {
        todo!("port Env.InDir")
    }

    /// Compiles a glob (`**`, `*`, `?`) to an anchored regex on normalized paths.
    pub fn compile_glob(&self, glob: &str) -> Result<Regex, RulesError> {
        todo!("port Env.CompileGlob")
    }
}

/// The raw material for a [`Call`].
#[derive(Debug, Clone, Default)]
pub struct CallInput {
    pub harness: String,
    pub tool: String,
    pub input: Option<Box<RawValue>>,
    pub cwd: String,
    pub project_dir: String,
    pub context: BTreeMap<String, String>,
    pub unattended: bool,
}

/// A tool call prepared for matching.
#[derive(Debug, Clone, Default)]
pub struct Call {
    pub harness: String,
    pub tool: String,
    pub kind: String,
    /// Shell command text, "" if none.
    pub command: String,
    pub url: String,
    /// Normalized absolute path, "" if none.
    pub path: String,
    pub in_project: bool,
    /// Top-level input fields; non-strings JSON-encoded.
    pub fields: BTreeMap<String, String>,
    /// Compact input JSON plus every string leaf, for the "*" field.
    pub whole: String,
    pub context: BTreeMap<String, String>,
    pub unattended: bool,
    pub cwd: String,
    pub project_dir: String,
}

impl Call {
    /// Extracts command, URL and path from the tool input.
    pub fn new(input: CallInput, env: &Env) -> Call {
        todo!("port rules.NewCall")
    }
}

/// A built-in rule that fired. `decision` is "deny" or "ask".
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hit {
    pub id: String,
    pub decision: String,
    pub reason: String,
}

/// Whether `command` removes root, home, a drive root or `.git`, or passes
/// `--no-preserve-root`, at a command position.
pub fn rm_root(command: &str) -> bool {
    todo!("port rules.RmRoot")
}

/// The always-on layer 0.
#[derive(Debug)]
pub struct Builtin {
    env: Env,
    disabled: Vec<String>,
    protected: Vec<Regex>,
    extra: Vec<String>,
}

impl Builtin {
    /// Compiles the built-in rules, minus the `disabled` ids. `extra` are
    /// further files for the self-protection rules (such as an explicit policy
    /// file).
    pub fn new(env: Env, disabled: &[String], extra: &[String]) -> Result<Builtin, RulesError> {
        todo!("port rules.NewBuiltin")
    }

    pub fn check(&self, c: &Call) -> Option<Hit> {
        todo!("port Builtin.Check")
    }
}

/// A compiled, ordered list of policy rules.
#[derive(Debug)]
pub struct Set {
    rules: Vec<policy::Rule>,
}

impl Set {
    /// Validates and compiles rules. The error names the offending rule.
    pub fn compile(rules: &[policy::Rule], env: &Env) -> Result<Set, RulesError> {
        todo!("port rules.Compile")
    }

    /// The matching rule that wins: deny over ask over allow, then list order.
    /// (Go: `Set.Match`; `match` is a keyword.)
    pub fn match_call(&self, call: &Call) -> Option<policy::Rule> {
        todo!("port Set.Match")
    }
}
