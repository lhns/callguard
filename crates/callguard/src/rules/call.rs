use super::*;

/// Every string in a JSON value, objects in key order.
fn collect_strings(v: &Value, out: &mut Vec<String>) {
    match v {
        Value::String(s) => out.push(s.clone()),
        Value::Array(a) => a.iter().for_each(|e| collect_strings(e, out)),
        // serde_json's map is sorted by key.
        Value::Object(m) => m.values().for_each(|e| collect_strings(e, out)),
        _ => {}
    }
}

// --- Calls ------------------------------------------------------------------

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
    /// Normalized directories that count as inside the project besides it.
    pub additional_dirs: Vec<String>,
}

/// A tool call prepared for matching.
#[derive(Debug, Clone, Default)]
pub struct Call {
    pub harness: String,
    pub tool: String,
    pub kind: String,
    /// Shell command text, "" if none. Line continuations are joined with a
    /// space.
    pub command: String,
    /// The command with line continuations joined with nothing, as a POSIX
    /// shell reads `r\<NL>m`; None if it equals `command`. Deny and ask look
    /// at both spellings, allow needs both to match (see [`Call::commands`]).
    pub command_joined: Option<String>,
    /// The distinct values of the command field as the host sent them, before
    /// line continuations are joined. Allow rules need exactly one.
    pub raw_commands: Vec<String>,
    /// The distinct non-empty strings of the `url` field (any letter case) and
    /// of a `urls` list, in field-name order. Other list entries are ignored.
    pub urls: Vec<String>,
    /// Normalized absolute path, if the call names one.
    pub path: Option<String>,
    /// The distinct path values as the host wrote them (all path-like keys,
    /// any letter case); a read tool without one gets the working directory.
    pub raw_paths: Vec<String>,
    pub in_project: bool,
    /// `path` with links and junctions resolved; None if it cannot be
    /// resolved, and then no allow rule may match on the path. Deny and ask
    /// match the lexical or the resolved path, allow needs both.
    pub real_path: Option<String>,
    /// Whether `real_path` is inside the resolved project directory.
    pub real_in_project: bool,
    /// The project directory is the home directory or a file system root, so
    /// it does not count as a project: `in_project` and `real_in_project` stay
    /// false.
    pub project_ignored: bool,
    /// A read tool's `pattern` or `glob` can name files outside `path`
    /// (see [`pattern_escapes`]): no allow rule may match on the path.
    pub pattern_escapes: bool,
    /// Where such patterns start: the directory part of each literal prefix,
    /// as written and resolved, with whether it is in the project. Deny and
    /// ask see these like `path`.
    pub pattern_paths: Vec<(String, bool)>,
    /// Top-level input fields; non-strings JSON-encoded.
    pub fields: BTreeMap<String, String>,
    /// The top-level fields that are a string, number or bool, by their
    /// literal JSON text (a string unquoted). Null, objects and arrays are
    /// left out: no parameter rule matches them.
    pub scalars: BTreeMap<String, String>,
    /// Compact input JSON plus every string leaf, for the "*" field.
    pub whole: String,
    pub context: BTreeMap<String, String>,
    pub unattended: bool,
    pub cwd: String,
    pub project_dir: String,
    /// The directories that count as inside the project.
    pub(crate) roots: Roots,
}

/// The directories that count as inside the project, each as normalized and
/// as resolved (None if it cannot be).
#[derive(Debug, Clone, Default)]
pub(crate) struct Roots {
    dirs: Vec<(String, Option<String>)>,
}

impl Roots {
    /// The roots for `project_dir` and the additional directories, and whether
    /// the project was left out because it is the home directory or a file
    /// system root, which say nothing about a project.
    fn new(env: &Env, project_dir: &str, cwd: &str, additional: &[String]) -> (Roots, bool) {
        let mut roots = Roots::default();
        let mut ignored = false;
        if !project_dir.is_empty() {
            let dir = env.normalize(project_dir, cwd);
            let real = env.real(&dir);
            if env.is_broad_dir(&dir, real.as_deref()) {
                ignored = true;
            } else {
                roots.dirs.push((dir, real));
            }
        }
        for d in additional {
            let dir = env.clean_names(&env.normalize(d, ""));
            let real = env.real(&dir);
            if !env.is_broad_dir(&dir, real.as_deref()) {
                roots.dirs.push((dir, real));
            }
        }
        (roots, ignored)
    }

    /// Whether the normalized path `p` is in a root, by its name.
    pub(crate) fn contains(&self, env: &Env, p: &str) -> bool {
        self.dirs.iter().any(|(d, _)| env.in_dir(p, d))
    }

    /// Whether the resolved path `p` is in a root, by where the root is.
    pub(crate) fn contains_real(&self, env: &Env, p: &str) -> bool {
        self.dirs
            .iter()
            .any(|(_, r)| r.as_ref().is_some_and(|r| env.in_dir(p, r)))
    }
}

const PATH_KEYS: [&str; 4] = ["file_path", "path", "notebook_path", "filePath"];

/// The fields of a read tool that hold a glob or pattern for files.
const PATTERN_KEYS: [&str; 2] = ["pattern", "glob"];

/// Whether the glob `v` can reach outside the directory it is searched in. Each
/// `{a,b}` alternative counts as a start, so `*.{ts,tsx}` stays inside and
/// `{a,/etc}/*` does not.
fn pattern_escapes(v: &str) -> bool {
    v.contains("..")
        || v.split(['{', ',']).any(|start| {
            let b = start.as_bytes();
            start.starts_with(['/', '\\', '~'])
                || (b.len() >= 2 && b[1] == b':' && b[0].is_ascii_alphabetic())
        })
}

/// Whether a read tool's `pattern` is a regex over file text, which names no
/// file. Hermes's `search_files` matches file names when `target` says so.
fn pattern_is_text(tool: &str, fields: &BTreeMap<String, String>) -> bool {
    match tool {
        "Grep" | "grep" => true,
        "search_files" => !field_values(fields, "target").iter().any(|t| t == "files"),
        _ => false,
    }
}

/// The directory a glob starts in: its literal prefix up to the last slash,
/// or all of it when it has no wildcard. None if it names nothing but
/// entries of the directory it is searched in.
fn pattern_dir(env: &Env, v: &str) -> Option<String> {
    let v = env.slash(v);
    let Some(cut) = v.find(['*', '?', '[', '{']) else {
        return (v.contains('/') || v == "~").then_some(v);
    };
    match v[..cut].rfind('/')? {
        0 => Some("/".to_owned()),
        i => Some(v[..i].to_owned()),
    }
}

/// Joins shell (backslash) and PowerShell (backtick) line continuations with
/// `sep`, so a command split over lines is matched as one line. A space reads
/// `a \<NL>b` right; nothing reads `r\<NL>m` as a shell does.
fn join_continuations(s: &str, sep: &str) -> String {
    const PAIRS: [&str; 4] = ["\\\r\n", "\\\n", "`\r\n", "`\n"];
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    'outer: while !rest.is_empty() {
        for p in PAIRS {
            if let Some(tail) = rest.strip_prefix(p) {
                out.push_str(sep);
                rest = tail;
                continue 'outer;
            }
        }
        let c = rest.chars().next().unwrap_or(' ');
        out.push(c);
        rest = &rest[c.len_utf8()..];
    }
    out
}

/// The distinct non-empty values of `key` in any letter case: the exact
/// spelling first, then the others in sorted key order.
fn field_values(fields: &BTreeMap<String, String>, key: &str) -> Vec<String> {
    let others = fields
        .keys()
        .filter(|k| k.as_str() != key && k.eq_ignore_ascii_case(key));
    let mut values: Vec<String> = Vec::new();
    for k in std::iter::once(&key.to_owned()).chain(others) {
        if let Some(v) = fields.get(k).filter(|v| !v.is_empty())
            && !values.contains(v)
        {
            values.push(v.clone());
        }
    }
    values
}

/// The URLs in the `url` and `urls` fields (see [`Call::urls`]).
fn urls_of(fields: &BTreeMap<String, String>) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut add = |u: String| {
        if !u.is_empty() && !out.contains(&u) {
            out.push(u);
        }
    };
    for (k, v) in fields {
        let k = k.to_ascii_lowercase();
        if k != "url" && k != "urls" {
            continue;
        }
        match serde_json::from_str::<Vec<Value>>(v) {
            Ok(list) => list
                .into_iter()
                .filter_map(|u| match u {
                    Value::String(s) => Some(s),
                    _ => None,
                })
                .for_each(&mut add),
            Err(_) => add(v.clone()),
        }
    }
    out
}

impl Call {
    /// The spellings of the command a shell may read: line continuations
    /// joined with a space, and with nothing if that differs.
    pub fn commands(&self) -> impl Iterator<Item = &str> {
        std::iter::once(self.command.as_str()).chain(self.command_joined.as_deref())
    }

    /// The path as written and as resolved, for deny and ask checks.
    pub(super) fn paths(&self) -> impl Iterator<Item = &str> {
        self.path
            .as_deref()
            .into_iter()
            .chain(self.real_path.as_deref())
    }

    /// Reads the `pattern` and `glob` fields of a read tool into
    /// `pattern_escapes` and `pattern_paths`.
    fn add_patterns(&mut self, env: &Env, roots: &Roots) {
        let text = pattern_is_text(&self.tool, &self.fields);
        for key in PATTERN_KEYS {
            if text && key == "pattern" {
                continue;
            }
            for v in field_values(&self.fields, key) {
                self.pattern_escapes |= pattern_escapes(&v);
                let Some(dir) = pattern_dir(env, &v) else {
                    continue;
                };
                let lexical =
                    env.clean_names(&env.normalize(&dir, self.path.as_deref().unwrap_or_default()));
                let real = env.real(&lexical);
                for (p, is_real) in [(Some(lexical), false), (real, true)] {
                    let Some(p) = p else { continue };
                    let inside = if is_real {
                        roots.contains_real(env, &p)
                    } else {
                        roots.contains(env, &p)
                    };
                    if !self.pattern_paths.iter().any(|(q, _)| *q == p) {
                        self.pattern_paths.push((p, inside));
                    }
                }
            }
        }
    }

    /// Extracts command, URL and path from the tool input.
    pub fn new(input: CallInput, env: &Env) -> Call {
        let kind = kind_of(&input.tool);
        let mut c = Call {
            harness: input.harness,
            tool: input.tool.clone(),
            kind: kind.to_owned(),
            context: input.context,
            unattended: input.unattended,
            cwd: input.cwd.clone(),
            project_dir: input.project_dir.clone(),
            ..Default::default()
        };
        if let Some(raw) = &input.input {
            let text = sanitize_surrogates(raw.get());
            // Not an object: no fields.
            if let Ok(Some(obj)) =
                serde_json::from_str::<Option<BTreeMap<String, Box<RawValue>>>>(&text)
            {
                for (k, v) in obj {
                    let value = match serde_json::from_str::<Option<String>>(v.get()) {
                        Ok(s) => s.unwrap_or_default(),
                        Err(_) => v.get().to_owned(),
                    };
                    match serde_json::from_str::<Value>(v.get()) {
                        Ok(Value::Number(_) | Value::Bool(_)) => {
                            c.scalars.insert(k.clone(), v.get().to_owned());
                        }
                        Ok(Value::String(_)) => {
                            c.scalars.insert(k.clone(), value.clone());
                        }
                        _ => {}
                    }
                    c.fields.insert(k, value);
                }
            }
            c.whole = crate::json_text::compact(raw.get());
            let mut leaves = Vec::new();
            if let Ok(v) = serde_json::from_str::<Value>(&text) {
                collect_strings(&v, &mut leaves);
            }
            if !leaves.is_empty() {
                c.whole.push('\n');
                c.whole.push_str(&leaves.join("\n"));
            }
        }
        if kind == KIND_SHELL {
            // Every spelling counts: we can't know which one the harness reads.
            c.raw_commands = field_values(&c.fields, "command");
            if input.tool == "execute_code" {
                for code in field_values(&c.fields, "code") {
                    if !c.raw_commands.contains(&code) {
                        c.raw_commands.push(code);
                    }
                }
            }
            let all = c.raw_commands.join("\n");
            c.command = join_continuations(&all, " ");
            let joined = join_continuations(&all, "");
            if joined != c.command {
                c.command_joined = Some(joined);
            }
        }
        c.urls = urls_of(&c.fields);
        for k in PATH_KEYS {
            for v in field_values(&c.fields, k) {
                if !c.raw_paths.contains(&v) {
                    c.raw_paths.push(v);
                }
            }
        }
        if c.raw_paths.is_empty() && kind == KIND_READ && !input.cwd.is_empty() {
            c.raw_paths.push(input.cwd.clone()); // Glob, Grep and LS default to the working directory
        }
        let raw_path = c.raw_paths.first().cloned().unwrap_or_default();
        let (roots, ignored) =
            Roots::new(env, &input.project_dir, &input.cwd, &input.additional_dirs);
        c.project_ignored = ignored;
        if !raw_path.is_empty() {
            let path = env.clean_names(&env.normalize(&raw_path, &input.cwd));
            let resolvable = !env.drive_relative(&raw_path);
            c.real_path = env.real(&path).filter(|_| resolvable);
            if resolvable {
                c.in_project = roots.contains(env, &path);
                c.real_in_project = c
                    .real_path
                    .as_deref()
                    .is_some_and(|p| roots.contains_real(env, p));
            }
            c.path = Some(path).filter(|p| !p.is_empty());
        }
        if kind == KIND_READ {
            c.add_patterns(env, &roots);
        }
        c.roots = roots;
        c
    }
}
