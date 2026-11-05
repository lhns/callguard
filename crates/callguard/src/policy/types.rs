use super::*;

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
    "rm-critical",
    "disk-wipe",
    "fork-bomb",
    "self-protect-write",
    "self-protect-shell",
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
    /// Directories besides the project that count as inside it, in Claude's
    /// key. Absolute (or `~/...`); the project layer's need `callguard trust`.
    #[serde(
        rename = "additionalDirectories",
        skip_serializing_if = "Vec::is_empty",
        deserialize_with = "nullable"
    )]
    pub additional_directories: Vec<String>,
}

impl Permissions {
    pub fn is_empty(&self) -> bool {
        self.deny.is_empty()
            && self.ask.is_empty()
            && self.allow.is_empty()
            && self.additional_directories.is_empty()
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
    /// The URL's host is one of these (exact, lower case, no wildcard). Allow
    /// needs every URL of the call to be plain (`https://host/...`); deny and
    /// ask match any host a trick could mean (`https://host@evil.com/`).
    #[serde(skip_serializing_if = "Vec::is_empty", deserialize_with = "nullable")]
    pub host: Vec<String>,
    /// Whether the shell call is made only of read-only commands on files
    /// inside the project (see `permissions::read_only`). Needs nah's parse.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub read_only: Option<bool>,
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
            && self.host.is_empty()
            && self.read_only.is_none()
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
pub(super) fn canonical_json(p: &Policy) -> String {
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
