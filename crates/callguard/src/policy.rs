//! callguard's policy file format (policy_version 1) and its layered,
//! tighten-only merge (docs/design.md section 5, ADR 0003).
//!
//! Unset is told from zero with `Option`. Integer fields are `i64`, so
//! `validate` can still report negative values. Paths stay `String`, with ""
//! meaning "default". Policy regexes are RE2; `rules::compile_regex` makes the
//! `regex` crate read them that way.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize, Serializer};
use serde_json::Value;
use serde_json::value::RawValue;
use sha2::{Digest, Sha256};

use crate::permissions;
use crate::serde_util::{is_false, is_zero, nullable};

/// The only supported policy_version.
pub const VERSION: i64 = 1;

pub(crate) const MODE_ENFORCE: &str = "enforce";
pub(crate) const MODE_SHADOW: &str = "shadow";

pub(crate) const LAYER_SYSTEM: &str = "system";
pub(crate) const LAYER_USER: &str = "user";
pub const LAYER_PROJECT: &str = "project";

/// The ids of the built-in layer's rules (`rules`). Only the system layer can
/// list them in `disable_builtin`.
pub(crate) const BUILTIN_IDS: &[&str] = &[
    "rm-root",
    "disk-wipe",
    "fork-bomb",
    "self-protect-write",
    "self-protect-shell",
];

/// Directories whose contents the default write rule does not auto-allow:
/// they carry hooks, policy and VCS state.
pub(crate) const PROTECTED_DIRS: &[&str] = &[
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
    /// Rules in Claude Code's syntax (`Bash(git push:*)`, `Read(~/.ssh/**)`).
    /// Left out of the serialization when empty, so a policy without them
    /// keeps its `policy_rev`.
    #[serde(
        skip_serializing_if = "Permissions::is_empty",
        deserialize_with = "nullable"
    )]
    pub permissions: Permissions,
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

/// Permission rules in Claude Code's syntax, by decision (see `permissions`).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Permissions {
    #[serde(skip_serializing_if = "Vec::is_empty", deserialize_with = "nullable")]
    pub deny: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty", deserialize_with = "nullable")]
    pub ask: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty", deserialize_with = "nullable")]
    pub allow: Vec<String>,
}

impl Permissions {
    pub fn is_empty(&self) -> bool {
        self.deny.is_empty() && self.ask.is_empty() && self.allow.is_empty()
    }
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
        self.tool.is_empty()
            && self.kind.is_empty()
            && self.command.is_empty()
            && self.url.is_empty()
            && self.field.is_empty()
            && self.path.is_empty()
            && self.not_path.is_empty()
            && self.in_project.is_none()
            && self.context.is_empty()
            && self.unattended.is_none()
            && self.harness.is_empty()
    }
}

/// Configures the nah layer. nah is linked into callguard and on by default.
/// `path`, `require` and `engine` belong to an earlier design: they still parse so
/// that [`validate`] can refuse them by name.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Nah {
    /// Default true; `false` is for debugging.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
    /// Refused.
    #[serde(
        skip_serializing_if = "String::is_empty",
        deserialize_with = "nullable"
    )]
    pub path: String,
    /// Refused.
    #[serde(skip_serializing_if = "is_false", deserialize_with = "nullable")]
    pub require: bool,
    /// Refused.
    #[serde(
        skip_serializing_if = "String::is_empty",
        deserialize_with = "nullable"
    )]
    pub engine: String,
    /// The hard deadline for the nah process. Default 10000: walking `/` takes
    /// 6 to 9 s on Windows, and a kill before that loses the block.
    #[serde(skip_serializing_if = "is_zero", deserialize_with = "nullable")]
    pub timeout_ms: i64,
    #[serde(
        skip_serializing_if = "String::is_empty",
        deserialize_with = "nullable"
    )]
    pub mode: String,
    /// nah's own analysis budget. Default 2000, kept by the load run
    /// (`git show 145fe3e:docs/rust-phase0.md`); it must not exceed
    /// `timeout_ms`, the hard kill.
    #[serde(skip_serializing_if = "is_zero", deserialize_with = "nullable")]
    pub budget_ms: i64,
    /// Shipped nah guards by name: `true` turns a default-off guard on. Every
    /// default-off guard is otherwise passed to nah as explicitly off, so a
    /// repo's `.nah/project.toml` cannot enable one. User and project layers
    /// can only enable.
    #[serde(
        skip_serializing_if = "BTreeMap::is_empty",
        deserialize_with = "nullable"
    )]
    pub guards: BTreeMap<String, bool>,
}

impl Nah {
    /// Whether the layer runs (default true).
    pub(crate) fn is_enabled(&self) -> bool {
        self.enabled.unwrap_or(true)
    }
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
    #[serde(skip_serializing_if = "Option::is_none", serialize_with = "opt_float")]
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

/// Limits for the judge's view of the conversation.
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
    pub(crate) fn llm_enabled(&self) -> bool {
        self.llm.as_ref().is_none_or(|l| l.enabled.unwrap_or(true))
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

/// Where the user layer and the trust record live.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum UserConfig {
    /// The platform's user config directory.
    #[default]
    Default,
    /// No user layer (and no trust record).
    None,
    /// This directory (tests).
    Dir(String),
}

/// Selects the policy files.
#[derive(Debug, Clone, Default)]
pub struct LoadOptions {
    /// System layer file; None means the platform default. A missing default
    /// file is not an error; a missing explicit file is.
    pub system_policy: Option<String>,
    pub project_dir: String,
    pub user_config_dir: UserConfig,
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
        self.files
            .iter()
            .flat_map(|f| f.problems.iter().map(move |p| format!("{}: {p}", f.path)))
            .collect()
    }
}

/// A policy file could not be read or parsed (I/O, JSON, wrong version).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct PolicyError(pub String);

/// The user's home directory (`USERPROFILE` on Windows, `HOME` elsewhere), None if unknown.
pub fn home_dir() -> Option<String> {
    let key = if cfg!(windows) { "USERPROFILE" } else { "HOME" };
    std::env::var(key).ok().filter(|h| !h.is_empty())
}

/// The per-user config directory, None if unknown.
fn user_config_dir() -> Option<String> {
    let env = |k: &str| std::env::var(k).ok().filter(|v| !v.is_empty());
    if cfg!(windows) {
        env("AppData")
    } else if cfg!(target_os = "macos") {
        env("HOME").map(|h| format!("{h}/Library/Application Support"))
    } else {
        match env("XDG_CONFIG_HOME") {
            Some(d) if Path::new(&d).is_absolute() => Some(d),
            Some(_) => None,
            None => env("HOME").map(|h| format!("{h}/.config")),
        }
    }
}

fn path_string(p: PathBuf) -> String {
    p.to_string_lossy().into_owned()
}

/// The platform default system policy path.
pub(crate) fn system_path() -> String {
    if cfg!(windows) {
        let pd = std::env::var("ProgramData")
            .ok()
            .filter(|p| !p.is_empty())
            .unwrap_or_else(|| r"C:\ProgramData".into());
        path_string(Path::new(&pd).join("callguard").join("policy.json"))
    } else {
        "/etc/callguard/policy.json".into()
    }
}

/// The user policy file path, None when the layer is skipped or the
/// directory is unknown.
pub(crate) fn user_path(config: &UserConfig) -> Option<String> {
    let dir = match config {
        UserConfig::None => return None,
        UserConfig::Default => user_config_dir()?,
        UserConfig::Dir(d) => d.clone(),
    };
    Some(path_string(
        Path::new(&dir).join("callguard").join("policy.json"),
    ))
}

/// A read failure; `not_found` is a missing file.
struct ReadFail {
    not_found: bool,
    err: PolicyError,
}

fn read_file_inner(path: &str, layer: &str) -> Result<File, ReadFail> {
    let fail = |not_found, msg: String| ReadFail {
        not_found,
        err: PolicyError(msg),
    };
    // A FIFO would block the read until something writes to it, past the
    // deadline; so would any file that is not a plain one. (A missing path
    // falls through to the read, which reports it.)
    if std::fs::metadata(path).is_ok_and(|m| !m.is_file()) {
        return Err(fail(false, format!("{path}: not a regular file")));
    }
    let mut data = std::fs::read(path).map_err(|e| {
        fail(
            e.kind() == std::io::ErrorKind::NotFound,
            format!("open {path}: {e}"),
        )
    })?;
    if data.starts_with(b"\xef\xbb\xbf") {
        data.drain(..3);
    }
    // A derived Deserialize would also take an array as a list of field values.
    crate::serde_util::require_object(&data).map_err(|e| fail(false, format!("{path}: {e}")))?;
    let parse = |d: &[u8]| serde_json::from_slice::<Policy>(d);
    let mut policy = parse(&data).map_err(|e| fail(false, format!("{path}: {e}")))?;
    // Policies have always matched keys case-insensitively, so "Rules"
    // still reaches `rules` (while `unknown` below still reports it). Rewrite
    // such keys and parse again; otherwise a deny rule would be dropped.
    if let Ok(mut raw) = serde_json::from_slice::<Value>(&data)
        && fold_keys(&mut raw, Ty::Obj(Obj::Policy))
    {
        let folded = serde_json::to_vec(&raw).expect("a Value serializes");
        policy = parse(&folded).map_err(|e| fail(false, format!("{path}: {e}")))?;
    }
    if policy.policy_version != VERSION {
        return Err(fail(
            false,
            format!(
                "{path}: unsupported policy_version {} (want {VERSION})",
                policy.policy_version
            ),
        ));
    }
    let problems = validate(&policy, false);
    Ok(File {
        path: path.to_owned(),
        layer: layer.to_owned(),
        policy,
        unknown: unknown_keys(&data),
        problems,
    })
}

/// Parses one policy file. Fails on I/O errors, JSON errors and a wrong
/// policy_version; other findings are recorded in the `File`.
pub fn read_file(path: &str, layer: &str) -> Result<File, PolicyError> {
    read_file_inner(path, layer).map_err(|f| f.err)
}

/// Reads one layer into `out`. A missing file is skipped unless `must_exist`.
fn apply(
    out: &mut Loaded,
    path: &str,
    layer: &str,
    must_exist: bool,
    o: &LoadOptions,
) -> Result<(), PolicyError> {
    let f = match read_file_inner(path, layer) {
        Ok(f) => f,
        Err(e) if e.not_found && !must_exist => return Ok(()),
        Err(e) => return Err(e.err),
    };
    for k in &f.unknown {
        out.warnings
            .push(format!("{path}: unknown key {} ignored", quote_string(k)));
    }
    // Allow rules that would loosen the guard too far are dropped here, per
    // layer, before the merge (the file itself stays as written).
    let mut layer_policy = f.policy.clone();
    let allow = &f.policy.permissions.allow;
    // A project's allow rules count only once the user has trusted them.
    let trusted = if layer == LAYER_PROJECT && !allow.is_empty() {
        match crate::trust::check_for_load(&o.user_config_dir, &o.project_dir, allow) {
            Ok(()) => true,
            Err(w) => {
                out.warnings.push(format!("{path}: {w}"));
                false
            }
        }
    } else {
        true
    };
    let (kept, dropped) = if trusted {
        permissions::vet_allow_list(allow, layer, path)
    } else {
        (Vec::new(), Vec::new())
    };
    layer_policy.permissions.allow = kept;
    out.warnings.extend(dropped);
    // llm.block goes into the judge's prompt; text written by a repo must not.
    if layer == LAYER_PROJECT
        && let Some(l) = layer_policy.llm.as_mut()
        && !l.block.is_empty()
    {
        l.block.clear();
        out.warnings.push(format!(
            "{path}: llm.block ignored: it goes into the judge's prompt, so a project file may not set it"
        ));
    }
    if layer == LAYER_SYSTEM {
        out.policy = merge_system(&out.policy, &layer_policy);
    } else {
        let (p, w) = merge_tighten(&out.policy, &layer_policy, path);
        out.policy = p;
        out.warnings.extend(w);
    }
    out.files.push(f);
    Ok(())
}

/// Reads the system, user and project files and merges them over [`default`].
pub fn load(o: &LoadOptions) -> Result<Loaded, PolicyError> {
    let mut out = Loaded {
        policy: default(),
        ..Default::default()
    };
    let explicit = o.system_policy.is_some();
    let sys_path = o.system_policy.clone().unwrap_or_else(system_path);
    apply(&mut out, &sys_path, LAYER_SYSTEM, explicit, o)?;
    if out.policy.r#final {
        return Ok(out);
    }
    if let Some(user) = user_path(&o.user_config_dir) {
        apply(&mut out, &user, LAYER_USER, false, o)?;
    }
    if !o.project_dir.is_empty() {
        let p = path_string(
            Path::new(&o.project_dir)
                .join(".callguard")
                .join("policy.json"),
        );
        apply(&mut out, &p, LAYER_PROJECT, false, o)?;
    }
    Ok(out)
}

/// The type of a JSON value in the policy schema, for [`unknown_keys`].
#[derive(Clone, Copy)]
enum Ty {
    Leaf,
    Obj(Obj),
    List(Obj),
    Map(Obj),
}

#[derive(Clone, Copy)]
enum Obj {
    Policy,
    Rule,
    Match,
    Permissions,
    Nah,
    Llm,
    Transcript,
    Backend,
    DenyStreak,
    Log,
}

/// The JSON keys of each struct (its serde names), with their types.
fn schema_fields(o: Obj) -> &'static [(&'static str, Ty)] {
    use Ty::{Leaf, List, Map, Obj as O};
    match o {
        Obj::Policy => &[
            ("policy_version", Leaf),
            ("final", Leaf),
            ("mode", Leaf),
            ("defaults", Leaf),
            ("disable_builtin", Leaf),
            ("unattended_ask", Leaf),
            ("rules", List(Obj::Rule)),
            ("permissions", O(Obj::Permissions)),
            ("nah", O(Obj::Nah)),
            ("llm", O(Obj::Llm)),
            ("backends", Map(Obj::Backend)),
            ("deny_streak", O(Obj::DenyStreak)),
            ("deadline_ms", Leaf),
            ("log", O(Obj::Log)),
        ],
        Obj::Rule => &[
            ("id", Leaf),
            ("description", Leaf),
            ("decision", Leaf),
            ("match", O(Obj::Match)),
        ],
        Obj::Match => &[
            ("tool", Leaf),
            ("kind", Leaf),
            ("command", Leaf),
            ("url", Leaf),
            ("field", Leaf),
            ("path", Leaf),
            ("not_path", Leaf),
            ("in_project", Leaf),
            ("context", Leaf),
            ("unattended", Leaf),
            ("harness", Leaf),
        ],
        Obj::Permissions => &[("deny", Leaf), ("ask", Leaf), ("allow", Leaf)],
        Obj::Nah => &[
            ("enabled", Leaf),
            ("path", Leaf),
            ("require", Leaf),
            ("engine", Leaf),
            ("timeout_ms", Leaf),
            ("mode", Leaf),
            ("budget_ms", Leaf),
            ("guards", Leaf),
        ],
        Obj::Llm => &[
            ("enabled", Leaf),
            ("mode", Leaf),
            ("backend", Leaf),
            ("timeout_ms", Leaf),
            ("min_confidence", Leaf),
            ("transcript", O(Obj::Transcript)),
            ("environment", Leaf),
            ("block", Leaf),
            ("allow_exceptions", Leaf),
        ],
        Obj::Transcript => &[("max_messages", Leaf), ("max_bytes", Leaf)],
        Obj::Backend => &[
            ("type", Leaf),
            ("model", Leaf),
            ("base_url", Leaf),
            ("api_key_env", Leaf),
            ("command", Leaf),
            ("max_tokens", Leaf),
            ("data_classes", Leaf),
            ("fake_mode", Leaf),
        ],
        Obj::DenyStreak => &[("consecutive", Leaf), ("total", Leaf)],
        Obj::Log => &[("path", Leaf), ("include_input", Leaf), ("disabled", Leaf)],
    }
}

/// Renames keys that match a struct field only case-insensitively (an exact
/// key wins). Returns whether anything changed.
fn fold_keys(raw: &mut Value, ty: Ty) -> bool {
    let mut changed = false;
    match (ty, raw) {
        (Ty::Obj(o), Value::Object(m)) => {
            let known = schema_fields(o);
            for key in m.keys().cloned().collect::<Vec<_>>() {
                let field = match known.iter().find(|(name, _)| *name == key) {
                    Some(f) => *f,
                    None => match known
                        .iter()
                        .find(|(name, _)| name.eq_ignore_ascii_case(&key))
                    {
                        Some(f) if !m.contains_key(f.0) => {
                            let v = m.remove(&key).expect("key exists");
                            m.insert(f.0.to_owned(), v);
                            changed = true;
                            *f
                        }
                        _ => continue,
                    },
                };
                if let Some(v) = m.get_mut(field.0) {
                    changed |= fold_keys(v, field.1);
                }
            }
        }
        (Ty::List(o), Value::Array(a)) => {
            for el in a {
                changed |= fold_keys(el, Ty::Obj(o));
            }
        }
        (Ty::Map(o), Value::Object(m)) => {
            for v in m.values_mut() {
                changed |= fold_keys(v, Ty::Obj(o));
            }
        }
        _ => {}
    }
    changed
}

fn walk_unknown(raw: &Value, ty: Ty, path: &str, out: &mut Vec<String>) {
    match ty {
        Ty::Leaf => {}
        Ty::Obj(o) => {
            let Some(m) = raw.as_object() else { return };
            let known = schema_fields(o);
            // serde_json's map is sorted (no preserve_order), so is the output.
            for k in m.keys() {
                let p = if path.is_empty() {
                    k.clone()
                } else {
                    format!("{path}.{k}")
                };
                match known.iter().find(|(name, _)| name == k) {
                    Some((_, ft)) => walk_unknown(&m[k], *ft, &p, out),
                    None => out.push(p),
                }
            }
        }
        Ty::List(o) => {
            let Some(arr) = raw.as_array() else { return };
            for (i, el) in arr.iter().enumerate() {
                walk_unknown(el, Ty::Obj(o), &format!("{path}[{i}]"), out);
            }
        }
        Ty::Map(o) => {
            let Some(m) = raw.as_object() else { return };
            for (k, v) in m {
                walk_unknown(v, Ty::Obj(o), &format!("{path}.{k}"), out);
            }
        }
    }
}

/// Unknown keys of a policy file, as dotted paths ("rules[0].match.foo"),
/// sorted within each object.
pub(crate) fn unknown_keys(data: &[u8]) -> Vec<String> {
    let Ok(raw) = serde_json::from_slice::<Value>(data) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    walk_unknown(&raw, Ty::Obj(Obj::Policy), "", &mut out);
    out
}

/// A string in double quotes with C-style escapes, for messages: one stable
/// spelling that shows control characters.
pub(crate) fn quote_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\x07' => out.push_str("\\a"),
            '\x08' => out.push_str("\\b"),
            '\x0c' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\x0b' => out.push_str("\\v"),
            c if (c as u32) < 0x20 || c == '\x7f' => out.push_str(&format!("\\x{:02x}", c as u32)),
            c if c.is_control() => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// Structural problems of `p`. Regexes and globs are checked by
/// `rules::Set::compile`. With `merged`, cross-references (llm.backend) are
/// checked too.
pub fn validate(p: &Policy, merged: bool) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let one_of = |v: &str, ok: &[&str]| v.is_empty() || ok.contains(&v);
    if !one_of(&p.mode, &[MODE_ENFORCE, MODE_SHADOW]) {
        out.push(format!(
            "mode {} must be enforce or shadow",
            quote_string(&p.mode)
        ));
    }
    if !one_of(&p.unattended_ask, &["deny", "ask"]) {
        out.push(format!(
            "unattended_ask {} must be deny or ask",
            quote_string(&p.unattended_ask)
        ));
    }
    if p.deadline_ms < 0 {
        out.push("deadline_ms must not be negative".into());
    }
    for id in &p.disable_builtin {
        if !BUILTIN_IDS.contains(&id.as_str()) {
            out.push(format!(
                "disable_builtin: unknown built-in rule {}",
                quote_string(id)
            ));
        }
    }
    // A deny or ask rule that cannot be read would silently never fire.
    for (list, key) in [(&p.permissions.deny, "deny"), (&p.permissions.ask, "ask")] {
        for (i, r) in list.iter().enumerate() {
            if let Err(e) = permissions::parse(r) {
                out.push(format!("permissions.{key}[{i}] {}: {e}", quote_string(r)));
            }
        }
    }
    for (i, r) in p.rules.iter().enumerate() {
        let mut name = format!("rules[{i}]");
        if !r.id.is_empty() {
            name.push_str(&format!(" ({})", r.id));
        }
        if r.id.is_empty() {
            out.push(format!("{name}: missing id"));
        }
        if !["allow", "ask", "deny"].contains(&r.decision.as_str()) {
            out.push(format!(
                "{name}: decision {} must be allow, ask or deny",
                quote_string(&r.decision)
            ));
        }
        if r.r#match.is_empty() {
            out.push(format!("{name}: rule has no match conditions"));
        }
    }
    if let Some(n) = &p.nah {
        if !one_of(&n.mode, &[MODE_ENFORCE, MODE_SHADOW]) {
            out.push(format!(
                "nah.mode {} must be enforce or shadow",
                quote_string(&n.mode)
            ));
        }
        if n.timeout_ms < 0 {
            out.push("nah.timeout_ms must not be negative".into());
        }
        if n.budget_ms < 0 {
            out.push("nah.budget_ms must not be negative".into());
        }
        if n.budget_ms > 0 && n.timeout_ms > 0 && n.budget_ms > n.timeout_ms {
            out.push(format!(
                "nah.budget_ms {} must not exceed nah.timeout_ms {}",
                n.budget_ms, n.timeout_ms
            ));
        }
        for (field, set) in [
            ("path", !n.path.is_empty()),
            ("require", n.require),
            ("engine", !n.engine.is_empty()),
        ] {
            if set {
                out.push(format!(
                    "nah.{field} is no longer supported: nah is built into callguard; remove it"
                ));
            }
        }
    }
    if let Some(l) = &p.llm {
        if !one_of(&l.mode, &[MODE_ENFORCE, MODE_SHADOW]) {
            out.push(format!(
                "llm.mode {} must be enforce or shadow",
                quote_string(&l.mode)
            ));
        }
        if l.min_confidence.is_some_and(|c| !(0.0..=1.0).contains(&c)) {
            out.push("llm.min_confidence must be in [0,1]".into());
        }
        if l.timeout_ms < 0 {
            out.push("llm.timeout_ms must not be negative".into());
        }
        if merged
            && p.llm_enabled()
            && !l.backend.is_empty()
            && !p.backends.contains_key(&l.backend)
        {
            out.push(format!(
                "llm.backend {} is not defined in backends",
                quote_string(&l.backend)
            ));
        }
    }
    for (k, b) in &p.backends {
        match b.r#type.as_str() {
            "anthropic" | "openai" | "fake" => {}
            "exec" => {
                if b.command.is_empty() {
                    out.push(format!("backends.{k}: exec backend needs command"));
                }
            }
            t => out.push(format!(
                "backends.{k}: unknown type {} (anthropic, openai, exec, fake)",
                quote_string(t)
            )),
        }
        if b.model.ends_with("-latest") {
            out.push(format!(
                "backends.{k}: model {} is a moving alias; use an exact model id",
                quote_string(&b.model)
            ));
        }
    }
    if let Some(d) = &p.deny_streak
        && (d.consecutive < 0 || d.total < 0)
    {
        out.push("deny_streak values must not be negative".into());
    }
    out
}

/// A float as JSON writes it in policy_rev ('f' form, 'e' form below 1e-6 or
/// from 1e21, no fraction for whole numbers, "e-7" not "e-07").
pub(crate) fn format_f64(v: f64) -> String {
    let abs = v.abs();
    if v == 0.0 {
        return "0".into();
    }
    if !(1e-6..1e21).contains(&abs) {
        let s = format!("{v:e}"); // "5e-7", "1.2345e21"
        let (mantissa, exp) = s.split_once('e').unwrap_or((&s, "0"));
        let exp: i32 = exp.parse().unwrap_or(0);
        return if exp < 0 {
            format!("{mantissa}e-{}", -exp)
        } else {
            format!("{mantissa}e+{exp:02}")
        };
    }
    format!("{v}")
}

/// Serializes `v` as `format_f64` writes it.
pub(crate) fn f64_raw<S: Serializer>(v: f64, s: S) -> Result<S::Ok, S::Error> {
    match RawValue::from_string(format_f64(v)) {
        Ok(raw) => raw.serialize(s),
        Err(_) => s.serialize_f64(v), // NaN or infinity
    }
}

fn opt_float<S: Serializer>(v: &Option<f64>, s: S) -> Result<S::Ok, S::Error> {
    match v {
        Some(f) => f64_raw(*f, s),
        None => s.serialize_none(),
    }
}

/// The canonical bytes of `p`: fields in declaration order, maps sorted,
/// HTML-escaped (see `json_text`).
fn canonical_json(p: &Policy) -> String {
    crate::json_text::to_string(p).unwrap_or_default()
}

/// "sha256:<hex>" of the canonical JSON of `p`. Its form is frozen: it
/// goes into Switchboard's logs, and `testdata/rev` pins it.
pub fn rev(p: &Policy) -> String {
    format!(
        "sha256:{}",
        hex::encode(Sha256::digest(canonical_json(p).as_bytes()))
    )
}

/// Replaces the rule with the same id in place, else appends.
fn upsert_rule(rules: &mut Vec<Rule>, r: &Rule) {
    match rules.iter_mut().find(|x| x.id == r.id) {
        Some(slot) => *slot = r.clone(),
        None => rules.push(r.clone()),
    }
}

/// Applies the system layer over `base` with full authority. A rule whose id is
/// already present replaces that rule; others are appended.
pub(crate) fn merge_system(base: &Policy, sys: &Policy) -> Policy {
    let mut out = base.clone();
    if sys.r#final {
        out.r#final = true;
    }
    if !sys.mode.is_empty() {
        out.mode = sys.mode.clone();
    }
    if let Some(d) = sys.defaults {
        out.defaults = Some(d);
        if !d {
            out.rules.clear(); // base holds only the default rules at this point
        }
    }
    out.disable_builtin = [base.disable_builtin.clone(), sys.disable_builtin.clone()].concat();
    if !sys.unattended_ask.is_empty() {
        out.unattended_ask = sys.unattended_ask.clone();
    }
    if sys.deadline_ms > 0 {
        out.deadline_ms = sys.deadline_ms;
    }
    for r in &sys.rules {
        upsert_rule(&mut out.rules, r);
    }
    append_permissions(&mut out.permissions, &sys.permissions);
    if let Some(sn) = &sys.nah {
        let mut n = base.nah.clone().unwrap_or_default();
        if sn.enabled.is_some() {
            n.enabled = sn.enabled;
        }
        n.guards.extend(sn.guards.clone());
        if sn.timeout_ms > 0 {
            n.timeout_ms = sn.timeout_ms;
        }
        if sn.budget_ms > 0 {
            n.budget_ms = sn.budget_ms;
        } else {
            // A short hard deadline alone must not leave the default budget
            // above it, which would make the policy invalid.
            n.budget_ms = n.budget_ms.min(n.timeout_ms);
        }
        if !sn.mode.is_empty() {
            n.mode = sn.mode.clone();
        }
        out.nah = Some(n);
    }
    if let Some(sl) = &sys.llm {
        out.llm = Some(merge_llm(base.llm.clone().unwrap_or_default(), sl));
    }
    if !sys.backends.is_empty() {
        out.backends = base.backends.clone();
        out.backends.extend(sys.backends.clone());
    }
    if let Some(d) = &sys.deny_streak {
        out.deny_streak = Some(d.clone());
    }
    if let Some(l) = &sys.log {
        out.log = Some(l.clone());
    }
    out
}

/// Adds the rules of `src` after those already in `dst`, skipping repeats.
/// Allow rules arrive vetted (see `permissions::vet_allow_list`).
fn append_permissions(dst: &mut Permissions, src: &Permissions) {
    for (to, from) in [
        (&mut dst.deny, &src.deny),
        (&mut dst.ask, &src.ask),
        (&mut dst.allow, &src.allow),
    ] {
        for r in from {
            if !to.contains(r) {
                to.push(r.clone());
            }
        }
    }
}

fn merge_llm(mut b: Llm, s: &Llm) -> Llm {
    if s.enabled.is_some() {
        b.enabled = s.enabled;
    }
    if !s.mode.is_empty() {
        b.mode = s.mode.clone();
    }
    if !s.backend.is_empty() {
        b.backend = s.backend.clone();
    }
    if s.timeout_ms > 0 {
        b.timeout_ms = s.timeout_ms;
    }
    if s.min_confidence.is_some() {
        b.min_confidence = s.min_confidence;
    }
    if let Some(st) = &s.transcript {
        let mut t = b.transcript.clone().unwrap_or_default();
        if st.max_messages > 0 {
            t.max_messages = st.max_messages;
        }
        if st.max_bytes > 0 {
            t.max_bytes = st.max_bytes;
        }
        b.transcript = Some(t);
    }
    // Absent, `null` and `[]` all mean "not set" (a written-out policy omits
    // empty lists), and an explicit empty list never loosened anything.
    if !s.environment.is_empty() {
        b.environment = s.environment.clone();
    }
    b.block.extend(s.block.iter().cloned());
    if !s.allow_exceptions.is_empty() {
        b.allow_exceptions = s.allow_exceptions.clone();
    }
    b
}

/// Applies a user or project layer: it may add deny/ask rules, append
/// `llm.block` and raise `llm.min_confidence`; everything else is dropped, each
/// drop reported as a warning naming `src` and the key.
pub(crate) fn merge_tighten(base: &Policy, layer: &Policy, src: &str) -> (Policy, Vec<String>) {
    const ONLY: &str =
        "this layer can only add deny/ask rules, append llm.block and raise llm.min_confidence";
    let mut warns: Vec<String> = Vec::new();
    let mut dropped = |key: &str, why: &str| warns.push(format!("{src}: {key} ignored: {why}"));
    let mut out = base.clone();
    if layer.r#final {
        dropped("final", ONLY);
    }
    if !layer.mode.is_empty() {
        dropped("mode", ONLY);
    }
    if layer.defaults.is_some() {
        dropped("defaults", ONLY);
    }
    if !layer.disable_builtin.is_empty() {
        dropped("disable_builtin", ONLY);
    }
    if !layer.unattended_ask.is_empty() {
        dropped("unattended_ask", ONLY);
    }
    if let Some(n) = &layer.nah {
        // Guards can only be switched on: that tightens nah.
        let mut cp = out.nah.take().unwrap_or_default();
        for (name, on) in &n.guards {
            if *on {
                cp.guards.insert(name.clone(), true);
            } else {
                dropped(
                    &format!("nah.guards.{name}"),
                    "a guard can only be switched on from this layer",
                );
            }
        }
        out.nah = Some(cp);
        if n.enabled.is_some() {
            dropped("nah.enabled", ONLY);
        }
        if n.timeout_ms != 0 {
            dropped("nah.timeout_ms", ONLY);
        }
        if n.budget_ms != 0 {
            dropped("nah.budget_ms", ONLY);
        }
        if !n.mode.is_empty() {
            dropped("nah.mode", ONLY);
        }
    }
    if !layer.backends.is_empty() {
        dropped("backends", ONLY);
    }
    if layer.deny_streak.is_some() {
        dropped("deny_streak", ONLY);
    }
    if layer.deadline_ms != 0 {
        dropped("deadline_ms", ONLY);
    }
    if layer.log.is_some() {
        dropped("log", ONLY);
    }
    for r in &layer.rules {
        if r.decision == "allow" {
            dropped(
                &format!("rules.{}", r.id),
                "allow rules are not accepted from this layer",
            );
            continue;
        }
        out.rules.push(r.clone()); // never replaces a lower layer's rule by id
    }
    append_permissions(&mut out.permissions, &layer.permissions);
    if let Some(l) = &layer.llm {
        let mut cp = base.llm.clone().unwrap_or_default();
        if l.enabled.is_some() {
            dropped("llm.enabled", ONLY);
        }
        if !l.mode.is_empty() {
            dropped("llm.mode", ONLY);
        }
        if !l.backend.is_empty() {
            dropped("llm.backend", ONLY);
        }
        if l.timeout_ms != 0 {
            dropped("llm.timeout_ms", ONLY);
        }
        if l.transcript.is_some() {
            dropped("llm.transcript", ONLY);
        }
        if !l.environment.is_empty() {
            dropped("llm.environment", ONLY);
        }
        if !l.allow_exceptions.is_empty() {
            dropped("llm.allow_exceptions", ONLY);
        }
        cp.block.extend(l.block.iter().cloned());
        if let Some(c) = l.min_confidence {
            if c > cp.min_confidence.unwrap_or(0.0) {
                cp.min_confidence = Some(c);
            } else {
                dropped("llm.min_confidence", "may only be raised");
            }
        }
        out.llm = Some(cp);
    }
    (out, warns)
}

/// The whole call's deadline. It has to fit nah's hard deadline and the judge
/// after it, yet stay under the 12 s timeout of the opencode and pi plugins,
/// which block the call when it passes.
pub(crate) const DEFAULT_DEADLINE_MS: i64 = 11_000;

/// The hard deadline for the nah process (see [`Nah::timeout_ms`]).
pub(crate) const DEFAULT_NAH_TIMEOUT_MS: i64 = 10_000;

/// nah's analysis budget (kept by the load run, `git show 145fe3e:docs/rust-phase0.md`).
pub const DEFAULT_NAH_BUDGET_MS: i64 = 2_000;

/// The confidence the judge needs for an allow to stand.
pub(crate) const DEFAULT_MIN_CONFIDENCE: f64 = 0.7;

/// The built-in policy: the default rules plus the default of every setting.
pub fn default() -> Policy {
    with_defaults(Policy {
        policy_version: VERSION,
        rules: default_rules(),
        ..Default::default()
    })
}

/// Fills every unset setting with its default. Does not add rules.
pub(crate) fn with_defaults(mut p: Policy) -> Policy {
    if p.policy_version == 0 {
        p.policy_version = VERSION;
    }
    if p.mode.is_empty() {
        p.mode = MODE_ENFORCE.into();
    }
    if p.unattended_ask.is_empty() {
        p.unattended_ask = "deny".into();
    }
    if p.deadline_ms == 0 {
        p.deadline_ms = DEFAULT_DEADLINE_MS;
    }
    let mut nah = p.nah.take().unwrap_or_default();
    if nah.enabled.is_none() {
        nah.enabled = Some(true);
    }
    if nah.timeout_ms == 0 {
        nah.timeout_ms = DEFAULT_NAH_TIMEOUT_MS;
    }
    if nah.budget_ms == 0 {
        nah.budget_ms = DEFAULT_NAH_BUDGET_MS.min(nah.timeout_ms);
    }
    if nah.mode.is_empty() {
        nah.mode = MODE_ENFORCE.into();
    }
    p.nah = Some(nah);

    let mut llm = p.llm.take().unwrap_or_default();
    if llm.enabled.is_none() {
        llm.enabled = Some(true);
    }
    if llm.mode.is_empty() {
        llm.mode = MODE_SHADOW.into();
    }
    if llm.backend.is_empty() {
        llm.backend = "anthropic".into();
    }
    if llm.timeout_ms == 0 {
        llm.timeout_ms = 3000;
    }
    if llm.min_confidence.is_none() {
        llm.min_confidence = Some(DEFAULT_MIN_CONFIDENCE);
    }
    let mut tr = llm.transcript.take().unwrap_or_default();
    if tr.max_messages == 0 {
        tr.max_messages = crate::transcript::DEFAULT_MESSAGES as i64;
    }
    if tr.max_bytes == 0 {
        tr.max_bytes = crate::transcript::DEFAULT_BYTES as i64;
    }
    llm.transcript = Some(tr);
    p.llm = Some(llm);

    p.backends
        .entry("anthropic".into())
        .or_insert_with(|| Backend {
            r#type: "anthropic".into(),
            model: "claude-haiku-5-5".into(),
            api_key_env: "ANTHROPIC_API_KEY".into(),
            base_url: "https://api.anthropic.com".into(),
            data_classes: vec!["open".into(), "private".into()],
            ..Default::default()
        });
    p
}

fn strings(v: &[&str]) -> Vec<String> {
    v.iter().map(|s| (*s).to_owned()).collect()
}

/// The default rules (design section 4, "Default rules").
pub(crate) fn default_rules() -> Vec<Rule> {
    let secret_paths = strings(&[
        "**/.ssh/**",
        "**/.aws/**",
        "**/.env",
        "**/.env.*",
        "**/*.pem",
        "**/id_rsa*",
        "**/id_ed25519*",
        "**/.netrc",
    ]);
    let sh = || strings(&["shell"]);
    let rule = |id: &str, decision: &str, description: &str, m: Match| Rule {
        id: id.into(),
        description: description.into(),
        decision: decision.into(),
        r#match: m,
    };
    let shell_cmd = |command: &str| Match {
        kind: sh(),
        command: command.into(),
        ..Default::default()
    };
    vec![
        rule(
            "read-in-project",
            "allow",
            "reads inside the project need no review",
            Match {
                kind: strings(&["read"]),
                in_project: Some(true),
                ..Default::default()
            },
        ),
        rule(
            "write-in-project",
            "allow",
            "writes inside the project (outside protected directories) need no review",
            Match {
                kind: strings(&["write"]),
                in_project: Some(true),
                not_path: strings(PROTECTED_DIRS),
                ..Default::default()
            },
        ),
        rule(
            "secret-read",
            "ask",
            "reads a common secret location",
            Match {
                kind: strings(&["read"]),
                path: secret_paths,
                ..Default::default()
            },
        ),
        rule(
            "secret-read-shell",
            "ask",
            "shell command touches a common secret location",
            shell_cmd(r"\.ssh[\\/]id_|\.aws[\\/]credentials|\.netrc"),
        ),
        rule(
            "secret-exfil",
            "deny",
            "sends a common secret location over the network",
            shell_cmd(SECRET_EXFIL_RE),
        ),
        rule(
            "pipe-to-shell",
            "deny",
            "downloads and runs remote code without review (pipe to a shell or interpreter)",
            shell_cmd(PIPE_TO_SHELL_RE),
        ),
        rule(
            "ssh-remote-destructive",
            "ask",
            "runs a destructive command on a remote host over ssh",
            shell_cmd(SSH_REMOTE_DESTRUCTIVE_RE),
        ),
        rule(
            "scp-home-secret",
            "deny",
            "copies a secret directory (.ssh, .aws, .gnupg) to a remote host",
            shell_cmd(SCP_HOME_SECRET_RE),
        ),
        rule(
            "git-force-push",
            "ask",
            "force push rewrites shared history",
            shell_cmd(GIT_FORCE_PUSH_RE),
        ),
        rule(
            "git-discard",
            "ask",
            "discards uncommitted work",
            shell_cmd(GIT_DISCARD_RE),
        ),
        rule(
            "infra-destroy",
            "ask",
            "destroys infrastructure or remote resources",
            shell_cmd(INFRA_DESTROY_RE),
        ),
        rule(
            "package-publish",
            "ask",
            "publishes a package to a public registry",
            shell_cmd(PACKAGE_PUBLISH_RE),
        ),
        rule(
            "sudo",
            "ask",
            "runs a command with elevated privileges",
            shell_cmd(SUDO_RE),
        ),
        rule(
            "classifier-injection",
            "ask",
            "tool input contains instruction-like text aimed at a classifier",
            Match {
                field: BTreeMap::from([("*".to_owned(), INJECTION_RE.to_owned())]),
                ..Default::default()
            },
        ),
    ]
}

// Command patterns of the default rules (RE2 syntax, compiled with
// `rules::compile_regex`). Best effort, not a parser.

macro_rules! net_tools_re {
    () => {
        "curl|wget|scp|rsync|sftp|ftp|nc|ncat|socat|iwr|invoke-webrequest|invoke-restmethod"
    };
}
macro_rules! secret_shell_re {
    () => {
        r"(?:\.ssh[\\/]id_|\.aws[\\/]credentials|\.netrc|\.env\b|\.pem\b)"
    };
}

pub(crate) const PIPE_TO_SHELL_RE: &str = concat!(
    r#"(?i)\b(?:curl|wget|iwr|irm|invoke-webrequest|invoke-restmethod)\b[^|]*(?:\|[^|][^|]*)*?\|\s*(?:(?:sudo|doas|env)(?:\s+-\S+)*\s+)?(?:\S*/)?(?:sh|bash|zsh|dash|python3?|perl|ruby|node|iex|invoke-expression)\b"#,
    r#"|(?i)\b(?:sh|bash|zsh|dash)\s+(?:-c\s+)?["']?\$\(\s*(?:curl|wget)\b"#,
    r"|(?i)\b(?:sh|bash|zsh|dash)\s+<\(\s*(?:curl|wget)\b"
);
pub(crate) const GIT_FORCE_PUSH_RE: &str = r"\bgit\b[^;&|\n]*\bpush\b[^;&|\n]*(?:\s--force(?:-with-lease)?\b|\s-[a-zA-Z]*f[a-zA-Z]*(?:\s|$)|\s\+\S)";
pub(crate) const GIT_DISCARD_RE: &str = r"\bgit\b[^;&|\n]*(?:\breset\b[^;&|\n]*\s--hard\b|\bclean\b[^;&|\n]*\s(?:-[a-zA-Z]*f[a-zA-Z]*|--force)\b|\bcheckout\s+(?:--\s+)?\.(?:\s|$)|\bcheckout\b[^;&|\n]*\s--\s+\.|\brestore\b[^;&|\n]*\s\.(?:\s|$))";
pub(crate) const INFRA_DESTROY_RE: &str = r"\b(?:terraform|tofu|pulumi|cdk|terragrunt)\b[^;&|\n]*\bdestroy\b|\bkubectl\b[^;&|\n]*\bdelete\b|\bgh\s+repo\s+delete\b";
pub(crate) const PACKAGE_PUBLISH_RE: &str = r"\b(?:npm|pnpm|yarn)\s+(?:[^;&|\n]*\s)?publish(?:\s|$)|\bcargo\s+publish(?:\s|$)|\btwine\s+upload\b|\bgem\s+push\b";
pub(crate) const SUDO_RE: &str = r"(?:^|[^\w.-])(?:sudo|doas)\s+\S";
/// `ssh` with a destructive verb in the remote command: the verbs of the
/// `rm-root` and `disk-wipe` checks, power commands, and cluster and
/// infrastructure deletes, Linux and Windows (`ssh`, `autossh`, `ssh.exe`). The
/// verb may carry a path (`/bin/rm`) and `.exe`. It must start a word, so
/// `ssh rm@host ls`, `ssh host ls rmdir.txt` and `--format=rm` do not match;
/// `ssh-add` is not `ssh`. Known limit: a path that ends in a verb
/// (`ssh host cat /tmp/rm`) also asks.
pub(crate) const SSH_REMOTE_DESTRUCTIVE_RE: &str = concat!(
    r#"(?i)(?:^|[\s;&|(`'"/\\])(?:auto)?ssh(?:\.exe)?\s[^;&|\n]*[\s'"`;&|(/\\]+"#,
    r"(?:rm|rmdir|rd|del|erase|remove-item|ri|mkfs(?:\.\w+)?|dd|format(?:\.com)?|shutdown|reboot|poweroff|halt|shred|wipefs|stop-computer|restart-computer",
    r"|find\b[^;&|\n]*\s-delete|kubectl\b[^;&|\n]*\bdelete|(?:terraform|tofu)\b[^;&|\n]*\bdestroy)(?:\.exe)?",
    r#"(?:[\s'"`;&|)]|$)"#
);
/// `scp`, `rsync` or `sftp` of a whole secret directory (`~/.aws`, `~/.ssh/`,
/// `$HOME/.gnupg/*`) with a remote target after it: `host:`, `user@h:` (any
/// host length) or `[::1]:`. `secret-exfil` names files (`.aws/credentials`,
/// `id_rsa`), not directories. A `-i ~/.ssh/key` identity file is not a
/// directory, and a bare one-letter `h:` is taken for a drive. Known limit:
/// the regex has no lookbehind, so `--exclude .ssh` and `--exclude ~/.aws`
/// (with a space) are denied like a copy; `--exclude=.ssh` is not.
pub(crate) const SCP_HOME_SECRET_RE: &str = concat!(
    r#"(?i)\b(?:scp|rsync|sftp)(?:\.exe)?\s[^;&|\n]*[\s'"]"#,
    r"(?:~|\$home|\$\{home\}|%userprofile%|\$env:userprofile|[a-z]:[\\/]users[\\/][^\\/\s'\x22]+|/(?:home|users)/[^/\s'\x22]+|/root)?",
    r#"[\\/]?\.(?:ssh|aws|gnupg)(?:[\\/]\*?)?['"]?\s"#,
    r"[^;&|\n]*?(?:[\w.-]{2,}|@[\w.-]+|\]):"
);

/// Separators include _ - . so file names like IGNORE_PREVIOUS_INSTRUCTIONS match.
pub(crate) const INJECTION_RE: &str = concat!(
    r"(?i)ignore[\s_.-]+(?:(?:all|any)[\s_.-]+)?(?:previous|prior)[\s_.-]+instructions",
    r"|you[\s_.-]+are[\s_.-]+(?:now[\s_.-]+)?(?:(?:a|the)[\s_.-]+)?(?:security[\s_.-]+)?classifier",
    r"|(?:label|classify|mark|rate)[\s_.-]+(?:this|it|the)(?:[\s_.-]+call)?[\s_.-]+(?:as[\s_.-]+)?(?:allow|safe|benign)",
    r"|callguard\W+(?:allow|approve)|callguard-data"
);
/// A network tool and a common secret location in one command.
pub(crate) const SECRET_EXFIL_RE: &str = concat!(
    r"(?i)\b(?:",
    net_tools_re!(),
    r")\b[^;&\n]*",
    secret_shell_re!(),
    r"|(?i)",
    secret_shell_re!(),
    r"[^;&\n]*\b(?:",
    net_tools_re!(),
    r")\b"
);

#[cfg(test)]
mod tests;
