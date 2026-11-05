use super::*;

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
    user_file(config, "policy.json")
}

/// The user backends file path, None when the layer is skipped or the
/// directory is unknown. Only this directory is ever searched for it.
pub(crate) fn backends_path(config: &UserConfig) -> Option<String> {
    user_file(config, BACKENDS_FILE)
}

fn user_file(config: &UserConfig, name: &str) -> Option<String> {
    let dir = match config {
        UserConfig::None => return None,
        UserConfig::Default => user_config_dir()?,
        UserConfig::Dir(d) => d.clone(),
    };
    Some(path_string(Path::new(&dir).join("callguard").join(name)))
}

/// A JSON error as text. serde_json quotes the offending value of a wrong
/// type ("invalid type: string \"sk-...\""), and a value may be a key.
fn json_error(e: &serde_json::Error) -> String {
    let msg = e.to_string();
    match msg.find(", expected ") {
        Some(i) if msg.starts_with("invalid ") => format!("wrong type or value{}", &msg[i..]),
        _ => msg,
    }
}

/// A read failure; `not_found` is a missing file.
struct ReadFail {
    not_found: bool,
    err: PolicyError,
}

fn fail(not_found: bool, msg: String) -> ReadFail {
    ReadFail {
        not_found,
        err: PolicyError(msg),
    }
}

/// The bytes of a JSON object file, without a byte order mark.
fn read_json_object(path: &str) -> Result<Vec<u8>, ReadFail> {
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
    Ok(data)
}

fn read_file_inner(path: &str, layer: &str) -> Result<File, ReadFail> {
    let data = read_json_object(path)?;
    let parse = |d: &[u8]| serde_json::from_slice::<Policy>(d);
    let mut policy =
        parse(&data).map_err(|e| fail(false, format!("{path}: {}", json_error(&e))))?;
    // Policies have always matched keys case-insensitively, so "Rules"
    // still reaches `rules` (while `unknown` below still reports it). Rewrite
    // such keys and parse again; otherwise a deny rule would be dropped.
    if let Ok(mut raw) = serde_json::from_slice::<Value>(&data)
        && fold_keys(&mut raw, Ty::Obj(Obj::Policy))
    {
        let folded = serde_json::to_vec(&raw).expect("a Value serializes");
        policy = parse(&folded).map_err(|e| fail(false, format!("{path}: {}", json_error(&e))))?;
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
    // `!` rules join the rules before them in this layer's list now: after the
    // merge nothing says which layer wrote a rule.
    for (key, list) in [
        ("deny", &mut layer_policy.permissions.deny),
        ("ask", &mut layer_policy.permissions.ask),
    ] {
        let (joined, warns) = permissions::attach_carveouts(list, key, path);
        *list = joined;
        out.warnings.extend(warns);
    }
    let allow = &f.policy.permissions.allow;
    let dirs = &f.policy.permissions.additional_directories;
    // A project's allow rules and additional directories count only once the
    // user has trusted them.
    let trusted = if layer == LAYER_PROJECT && !(allow.is_empty() && dirs.is_empty()) {
        match crate::trust::check_for_load(&o.user_config_dir, &o.project_dir, allow, dirs) {
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
    let (dirs_kept, dir_warns) = if trusted {
        permissions::vet_dir_list(&crate::rules::Env::host(), dirs, path)
    } else {
        (Vec::new(), Vec::new())
    };
    layer_policy.permissions.additional_directories = dirs_kept;
    out.warnings.extend(dir_warns);
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
    if layer == LAYER_PROJECT
        && let Some(l) = layer_policy.llm.as_mut()
        && l.instructions.take().is_some()
    {
        out.warnings.push(format!(
            "{path}: llm.instructions ignored: only the system and user policies may set it"
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
    apply_backends(&mut out, o)?;
    Ok(out)
}

/// The template's key value. A backend whose `api_key` is still this has no key.
pub const PLACEHOLDER_KEY: &str = "PASTE-KEY-HERE";

const BACKENDS_TEMPLATE: &str = r#"{
  "default": "anthropic",
  "backends": {
    "anthropic": {
      "type": "anthropic",
      "model": "claude-haiku-5-5",
      "api_key": "PASTE-KEY-HERE",
      "data_classes": ["open", "private"]
    },
    "local": {
      "type": "openai",
      "model": "qwen3",
      "base_url": "http://localhost:8080/v1",
      "api_key": "PASTE-KEY-HERE",
      "data_classes": ["open", "private"]
    }
  }
}
"#;

/// Writes the template backends file to the user's config directory and
/// returns its path. Never overwrites. On Unix the file is 0600 in a 0700
/// directory; on Windows it inherits the per-user ACL of `%APPDATA%`.
pub fn init_backends_file(config: &UserConfig) -> Result<String, PolicyError> {
    use std::io::Write;
    let path = backends_path(config)
        .ok_or_else(|| PolicyError("the user config directory is unknown".into()))?;
    let dir = Path::new(&path).parent().expect("a file has a parent");
    let err = |what: &str, e: std::io::Error| PolicyError(format!("{what} {path}: {e}"));
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)
            .map_err(|e| err("create the directory of", e))?;
    }
    #[cfg(not(unix))]
    std::fs::create_dir_all(dir).map_err(|e| err("create the directory of", e))?;
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(&path).map_err(|e| {
        if e.kind() == std::io::ErrorKind::AlreadyExists {
            PolicyError(format!("{path} already exists; not overwriting it"))
        } else {
            err("create", e)
        }
    })?;
    f.write_all(BACKENDS_TEMPLATE.as_bytes())
        .map_err(|e| err("write", e))?;
    Ok(path)
}

/// The user's backends file: `default` and `backends`. It is read last and
/// only from the user's own config directory.
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct BackendsFile {
    #[serde(deserialize_with = "nullable")]
    default: String,
    #[serde(deserialize_with = "nullable")]
    backends: BTreeMap<String, Backend>,
}

fn read_backends_inner(path: &str) -> Result<(File, BackendsFile), ReadFail> {
    let data = read_json_object(path)?;
    let parse = |d: &[u8]| serde_json::from_slice::<BackendsFile>(d);
    let bad = |e: serde_json::Error| fail(false, format!("{path}: {}", json_error(&e)));
    let mut parsed = parse(&data).map_err(bad)?;
    if let Ok(mut raw) = serde_json::from_slice::<Value>(&data)
        && fold_keys(&mut raw, Ty::Obj(Obj::BackendsFile))
    {
        let folded = serde_json::to_vec(&raw).expect("a Value serializes");
        parsed = parse(&folded).map_err(bad)?;
    }
    let as_policy = Policy {
        policy_version: VERSION,
        backends: parsed.backends.clone(),
        ..Default::default()
    };
    let file = File {
        path: path.to_owned(),
        layer: LAYER_USER_BACKENDS.to_owned(),
        problems: validate(&as_policy, false),
        policy: as_policy,
        unknown: unknown_keys_of(&data, Obj::BackendsFile),
    };
    Ok((file, parsed))
}

/// Puts the user's backends file over the merged policy: each backend named
/// there replaces the whole entry of that name, and `default` becomes
/// `llm.backend` unless the system layer chose one. A failure to read it is an
/// error like any policy file's (the fail-safe path), a missing file is not.
fn apply_backends(out: &mut Loaded, o: &LoadOptions) -> Result<(), PolicyError> {
    let Some(path) = backends_path(&o.user_config_dir) else {
        return Ok(());
    };
    let (mut file, parsed) = match read_backends_inner(&path) {
        Ok(x) => x,
        Err(e) if e.not_found => return Ok(()),
        Err(e) => return Err(e.err),
    };
    for k in &file.unknown {
        out.warnings
            .push(format!("{path}: unknown key {} ignored", quote_string(k)));
    }
    out.policy.backends.extend(parsed.backends);
    if !parsed.default.is_empty() {
        let system_chose = out.files.iter().any(|f| {
            f.layer == LAYER_SYSTEM && f.policy.llm.as_ref().is_some_and(|l| !l.backend.is_empty())
        });
        match out.policy.llm.as_mut() {
            Some(_) if system_chose => out.warnings.push(format!(
                "{path}: default ignored: the system policy sets llm.backend"
            )),
            Some(l) => {
                if !out.policy.backends.contains_key(&parsed.default) {
                    file.problems.push(format!(
                        "default {} is not defined in backends",
                        quote_string(&parsed.default)
                    ));
                }
                l.backend = parsed.default;
            }
            None => {}
        }
    }
    out.files.push(file);
    Ok(())
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
    BackendsFile,
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
            ("host", Leaf),
            ("read_only", Leaf),
            ("context", Leaf),
            ("unattended", Leaf),
            ("harness", Leaf),
        ],
        Obj::Permissions => &[
            ("deny", Leaf),
            ("ask", Leaf),
            ("allow", Leaf),
            ("additionalDirectories", Leaf),
        ],
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
            ("instructions", Leaf),
            ("timeout_ms", Leaf),
            ("min_confidence", Leaf),
            ("transcript", O(Obj::Transcript)),
            ("environment", Leaf),
            ("block", Leaf),
            ("allow_exceptions", Leaf),
        ],
        Obj::Transcript => &[("max_messages", Leaf), ("max_bytes", Leaf)],
        Obj::BackendsFile => &[("default", Leaf), ("backends", Map(Obj::Backend))],
        Obj::Backend => &[
            ("type", Leaf),
            ("model", Leaf),
            ("base_url", Leaf),
            ("api_key_env", Leaf),
            ("api_key", Leaf),
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
    unknown_keys_of(data, Obj::Policy)
}

fn unknown_keys_of(data: &[u8], root: Obj) -> Vec<String> {
    let Ok(raw) = serde_json::from_slice::<Value>(data) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    walk_unknown(&raw, Ty::Obj(root), "", &mut out);
    out
}
