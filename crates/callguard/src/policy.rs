//! callguard's policy file format (policy_version 1) and its layered,
//! tighten-only merge (docs/design.md section 5, ADR 0003). Types are ported
//! in full; functions are stubs (worker A).
//!
//! Go's unset-vs-zero distinction (pointers, nil slices) is kept with
//! `Option`. Go `int` fields are `i64`, so `Validate` can still report
//! negative values. Paths stay `String`, with "" meaning "default", as in Go.
//! The default-rule regex constants (`PipeToShellRE` ... `SecretExfilRE`) are
//! not copied yet; worker A ports them with `default_rules`.
#![allow(unused_variables)]

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::serde_util::{is_false, is_zero, nullable};

/// The only supported policy_version.
pub const VERSION: i64 = 1;

pub const MODE_ENFORCE: &str = "enforce";
pub const MODE_SHADOW: &str = "shadow";

pub const LAYER_SYSTEM: &str = "system";
pub const LAYER_USER: &str = "user";
pub const LAYER_PROJECT: &str = "project";

/// The ids of the built-in layer's rules (`rules`). Only the system layer can
/// list them in `disable_builtin`.
pub const BUILTIN_IDS: &[&str] = &[
    "rm-root",
    "disk-wipe",
    "fork-bomb",
    "self-protect-write",
    "self-protect-shell",
];

/// Directories whose contents the default write rule does not auto-allow:
/// they carry hooks, policy and VCS state.
pub const PROTECTED_DIRS: &[&str] = &[
    "**/.git/**",
    "**/.claude/**",
    "**/.callguard/**",
    "**/.opencode/**",
    "**/.pi/**",
    "**/.hermes/**",
];

/// One policy file, or the merged result of all layers. Option fields
/// distinguish "not set" from zero values so that layers can be merged.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Policy {
    #[serde(deserialize_with = "nullable")]
    pub policy_version: i64,
    #[serde(skip_serializing_if = "is_false", deserialize_with = "nullable")]
    pub r#final: bool,
    /// enforce (default) | shadow.
    #[serde(
        skip_serializing_if = "String::is_empty",
        deserialize_with = "nullable"
    )]
    pub mode: String,
    /// Include built-in default rules (default true).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub defaults: Option<bool>,
    #[serde(skip_serializing_if = "Vec::is_empty", deserialize_with = "nullable")]
    pub disable_builtin: Vec<String>,
    /// deny (default) | ask.
    #[serde(
        skip_serializing_if = "String::is_empty",
        deserialize_with = "nullable"
    )]
    pub unattended_ask: String,
    #[serde(skip_serializing_if = "Vec::is_empty", deserialize_with = "nullable")]
    pub rules: Vec<Rule>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nah: Option<Nah>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub llm: Option<Llm>,
    #[serde(
        skip_serializing_if = "BTreeMap::is_empty",
        deserialize_with = "nullable"
    )]
    pub backends: BTreeMap<String, Backend>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deny_streak: Option<DenyStreak>,
    /// Default 8000.
    #[serde(skip_serializing_if = "is_zero", deserialize_with = "nullable")]
    pub deadline_ms: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub log: Option<Log>,
}

/// One policy rule. `decision` is deny, ask or allow.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Rule {
    #[serde(deserialize_with = "nullable")]
    pub id: String,
    #[serde(
        skip_serializing_if = "String::is_empty",
        deserialize_with = "nullable"
    )]
    pub description: String,
    #[serde(deserialize_with = "nullable")]
    pub decision: String,
    #[serde(rename = "match", deserialize_with = "nullable")]
    pub r#match: Match,
}

/// Match conditions are ANDed; list values are ORed. Regexes are RE2.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Match {
    #[serde(skip_serializing_if = "Vec::is_empty", deserialize_with = "nullable")]
    pub tool: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty", deserialize_with = "nullable")]
    pub kind: Vec<String>,
    #[serde(
        skip_serializing_if = "String::is_empty",
        deserialize_with = "nullable"
    )]
    pub command: String,
    #[serde(
        skip_serializing_if = "String::is_empty",
        deserialize_with = "nullable"
    )]
    pub url: String,
    #[serde(
        skip_serializing_if = "BTreeMap::is_empty",
        deserialize_with = "nullable"
    )]
    pub field: BTreeMap<String, String>,
    #[serde(skip_serializing_if = "Vec::is_empty", deserialize_with = "nullable")]
    pub path: Vec<String>,
    /// The path must match none of these globs.
    #[serde(skip_serializing_if = "Vec::is_empty", deserialize_with = "nullable")]
    pub not_path: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub in_project: Option<bool>,
    #[serde(
        skip_serializing_if = "BTreeMap::is_empty",
        deserialize_with = "nullable"
    )]
    pub context: BTreeMap<String, Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unattended: Option<bool>,
    #[serde(skip_serializing_if = "Vec::is_empty", deserialize_with = "nullable")]
    pub harness: Vec<String>,
}

impl Match {
    /// Whether `self` has no condition at all (an invalid rule).
    pub fn is_empty(&self) -> bool {
        todo!("port Match.IsEmpty")
    }
}

/// Configures the nah layer (ADR 0004). The Go fields `path`, `require` and
/// `mode` are kept for reading old files; Phase 2 decides which survive (the
/// plan refuses `path`, `require` and `engine`).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Nah {
    #[serde(deserialize_with = "nullable")]
    pub enabled: bool,
    /// Default "nah".
    #[serde(
        skip_serializing_if = "String::is_empty",
        deserialize_with = "nullable"
    )]
    pub path: String,
    #[serde(skip_serializing_if = "is_false", deserialize_with = "nullable")]
    pub require: bool,
    /// Default 2000.
    #[serde(skip_serializing_if = "is_zero", deserialize_with = "nullable")]
    pub timeout_ms: i64,
    #[serde(
        skip_serializing_if = "String::is_empty",
        deserialize_with = "nullable"
    )]
    pub mode: String,
}

/// Configures the judge layer.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Llm {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
    #[serde(
        skip_serializing_if = "String::is_empty",
        deserialize_with = "nullable"
    )]
    pub mode: String,
    #[serde(
        skip_serializing_if = "String::is_empty",
        deserialize_with = "nullable"
    )]
    pub backend: String,
    /// Default 3000.
    #[serde(skip_serializing_if = "is_zero", deserialize_with = "nullable")]
    pub timeout_ms: i64,
    /// Default 0.7.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min_confidence: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transcript: Option<TranscriptLimits>,
    #[serde(skip_serializing_if = "Vec::is_empty", deserialize_with = "nullable")]
    pub environment: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty", deserialize_with = "nullable")]
    pub block: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty", deserialize_with = "nullable")]
    pub allow_exceptions: Vec<String>,
}

/// Limits for the judge's view of the conversation (Go: `policy.Transcript`).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct TranscriptLimits {
    /// Default 20.
    #[serde(skip_serializing_if = "is_zero", deserialize_with = "nullable")]
    pub max_messages: i64,
    /// Default 24000.
    #[serde(skip_serializing_if = "is_zero", deserialize_with = "nullable")]
    pub max_bytes: i64,
}

/// Configures one LLM backend. `type` is anthropic, openai, exec or fake.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Backend {
    #[serde(rename = "type", deserialize_with = "nullable")]
    pub r#type: String,
    #[serde(
        skip_serializing_if = "String::is_empty",
        deserialize_with = "nullable"
    )]
    pub model: String,
    #[serde(
        skip_serializing_if = "String::is_empty",
        deserialize_with = "nullable"
    )]
    pub base_url: String,
    #[serde(
        skip_serializing_if = "String::is_empty",
        deserialize_with = "nullable"
    )]
    pub api_key_env: String,
    #[serde(skip_serializing_if = "Vec::is_empty", deserialize_with = "nullable")]
    pub command: Vec<String>,
    #[serde(skip_serializing_if = "is_zero", deserialize_with = "nullable")]
    pub max_tokens: i64,
    #[serde(skip_serializing_if = "Vec::is_empty", deserialize_with = "nullable")]
    pub data_classes: Vec<String>,
    /// Fake backend behaviour, for tests and offline eval: "rules" (default,
    /// a deterministic heuristic), "allow", "ask", "deny", "garbage", "slow",
    /// "error", "obey-injection".
    #[serde(
        skip_serializing_if = "String::is_empty",
        deserialize_with = "nullable"
    )]
    pub fake_mode: String,
}

/// Mirrors auto mode's 3-in-a-row / 20-total fallback.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct DenyStreak {
    #[serde(skip_serializing_if = "is_zero", deserialize_with = "nullable")]
    pub consecutive: i64,
    #[serde(skip_serializing_if = "is_zero", deserialize_with = "nullable")]
    pub total: i64,
}

/// Configures the decision log.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Log {
    #[serde(
        skip_serializing_if = "String::is_empty",
        deserialize_with = "nullable"
    )]
    pub path: String,
    #[serde(skip_serializing_if = "is_false", deserialize_with = "nullable")]
    pub include_input: bool,
    #[serde(skip_serializing_if = "is_false", deserialize_with = "nullable")]
    pub disabled: bool,
}

impl Policy {
    /// Whether the LLM layer is on (default true).
    pub fn llm_enabled(&self) -> bool {
        todo!("port Policy.LLMEnabled")
    }
}

/// One parsed policy file.
#[derive(Debug, Clone, Default)]
pub struct File {
    pub path: String,
    pub layer: String,
    pub policy: Policy,
    /// Unknown keys, as dotted paths.
    pub unknown: Vec<String>,
    /// Structural problems (see [`validate`]).
    pub problems: Vec<String>,
}

/// Selects the policy files. "-" in `user_config_dir` skips the user layer.
#[derive(Debug, Clone, Default)]
pub struct LoadOptions {
    pub system_policy: String,
    pub project_dir: String,
    pub user_config_dir: String,
}

/// The merged policy and how it came about.
#[derive(Debug, Clone, Default)]
pub struct Loaded {
    pub policy: Policy,
    /// Files actually read, lowest authority first.
    pub files: Vec<File>,
    /// Unknown keys and dropped (loosening) settings.
    pub warnings: Vec<String>,
}

impl Loaded {
    /// The structural problems of all files, each prefixed with its path.
    pub fn problems(&self) -> Vec<String> {
        todo!("port Loaded.Problems")
    }
}

/// A policy file could not be read or parsed (I/O, JSON, wrong version).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct PolicyError(pub String);

/// The platform default system policy path.
pub fn system_path() -> String {
    todo!("port policy.SystemPath")
}

/// The user policy file path under `config_dir` ("" = the user config dir).
pub fn user_path(config_dir: &str) -> String {
    todo!("port policy.UserPath")
}

/// Parses one policy file. Fails on I/O errors, JSON errors and a wrong
/// policy_version; other findings are recorded in the `File`.
pub fn read_file(path: &str, layer: &str) -> Result<File, PolicyError> {
    todo!("port policy.ReadFile")
}

/// Reads the system, user and project files and merges them over [`default`].
pub fn load(o: &LoadOptions) -> Result<Loaded, PolicyError> {
    todo!("port policy.Load")
}

/// Unknown keys of a policy file, as dotted paths.
pub fn unknown_keys(data: &[u8]) -> Vec<String> {
    todo!("port policy.UnknownKeys")
}

/// Structural problems of `p`. Regexes and globs are checked by
/// `rules::Set::compile`. With `merged`, cross-references (llm.backend) are
/// checked too.
pub fn validate(p: &Policy, merged: bool) -> Vec<String> {
    todo!("port policy.Validate")
}

/// "sha256:<hex>" of the canonical JSON of `p`.
pub fn rev(p: &Policy) -> String {
    todo!("port policy.Rev")
}

/// Applies the system layer over `base` with full authority. A rule whose id is
/// already present replaces that rule; others are appended.
pub fn merge_system(base: &Policy, sys: &Policy) -> Policy {
    todo!("port policy.MergeSystem")
}

/// Applies a user or project layer: it may add deny/ask rules, append
/// `llm.block` and raise `llm.min_confidence`; everything else is dropped, each
/// drop reported as a warning naming `src` and the key.
pub fn merge_tighten(base: &Policy, layer: &Policy, src: &str) -> (Policy, Vec<String>) {
    todo!("port policy.MergeTighten")
}

/// The built-in policy: the default rules plus the default of every setting.
pub fn default() -> Policy {
    todo!("port policy.Default")
}

/// Fills every unset setting with its default. Does not add rules.
pub fn with_defaults(p: Policy) -> Policy {
    todo!("port policy.WithDefaults")
}

/// The default rules.
pub fn default_rules() -> Vec<Rule> {
    todo!("port policy.DefaultRules")
}
