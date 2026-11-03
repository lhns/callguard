//! Maps tool calls to kinds, extracts paths and commands from their input, and
//! evaluates the built-in and policy rules (internal/rules).
//!
//! Every regex here and in a policy is Go RE2. [`compile_regex`] makes the
//! `regex` crate read it the way Go does, because the two differ where it
//! matters for a guard: Go's `\b`, `\s`, `\w` and `\d` are ASCII-only, the
//! `regex` crate's are Unicode.

use std::collections::BTreeMap;
use std::sync::LazyLock;

use regex::Regex;
use serde_json::Value;
use serde_json::value::RawValue;

use crate::policy::{self, go_quote};

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

/// The kind of the tool called `tool`. Names are case-sensitive and do not
/// collide across harnesses, so one table serves all of them (a request from
/// an unknown harness still maps sensibly).
pub fn kind_of(tool: &str) -> &'static str {
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

// --- Go regex semantics ---------------------------------------------------

/// `\s` in RE2: `[\t\n\f\r ]`.
const GO_SPACE: &str = r"\t\n\f\r ";

/// Whether `chars[i..]` starts a repetition `{n}`, `{n,}` or `{n,m}`; returns
/// its length. RE2 reads any other `{` as a literal, the `regex` crate fails.
fn repeat_len(chars: &[char], i: usize) -> Option<usize> {
    let mut j = i + 1;
    let digits = |j: &mut usize| {
        let start = *j;
        while chars.get(*j).is_some_and(char::is_ascii_digit) {
            *j += 1;
        }
        *j > start
    };
    if !digits(&mut j) {
        return None;
    }
    if chars.get(j) == Some(&',') {
        j += 1;
        digits(&mut j);
    }
    (chars.get(j) == Some(&'}')).then(|| j + 1 - i)
}

/// Rewrites a Go RE2 pattern into the `regex` crate's syntax with the same
/// meaning: ASCII `\b \B \s \S \w \W \d \D`, `\Q..\E`, literal `\<` `\>`,
/// literal `{` and `&&` `~~` inside classes.
fn translate_regex(pat: &str) -> String {
    let chars: Vec<char> = pat.chars().collect();
    let mut out = String::with_capacity(pat.len() + 16);
    let mut in_class = false;
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        i += 1;
        if c == '\\' {
            let Some(&e) = chars.get(i) else {
                out.push('\\'); // the regex crate reports the trailing backslash
                break;
            };
            i += 1;
            match e {
                'b' if !in_class => out.push_str(r"(?-u:\b)"),
                'B' if !in_class => out.push_str(r"(?-u:\B)"),
                's' if in_class => out.push_str(GO_SPACE),
                's' => out.push_str(&format!("[{GO_SPACE}]")),
                'S' => out.push_str(&format!("[^{GO_SPACE}]")),
                'd' if in_class => out.push_str("0-9"),
                'd' => out.push_str("[0-9]"),
                'D' => out.push_str("[^0-9]"),
                'w' if in_class => out.push_str("0-9A-Za-z_"),
                'w' => out.push_str("[0-9A-Za-z_]"),
                'W' => out.push_str("[^0-9A-Za-z_]"),
                '<' | '>' => out.push(e),
                'Q' => {
                    while i < chars.len() {
                        if chars[i] == '\\' && chars.get(i + 1) == Some(&'E') {
                            i += 2;
                            break;
                        }
                        out.push_str(&regex::escape(&chars[i].to_string()));
                        i += 1;
                    }
                }
                'p' | 'P' | 'x' if chars.get(i) == Some(&'{') => {
                    out.push('\\');
                    out.push(e);
                    while i < chars.len() {
                        out.push(chars[i]);
                        i += 1;
                        if chars[i - 1] == '}' {
                            break;
                        }
                    }
                }
                _ => {
                    out.push('\\');
                    out.push(e);
                }
            }
            continue;
        }
        if in_class {
            match c {
                ']' => {
                    in_class = false;
                    out.push(']');
                }
                '[' if chars.get(i) == Some(&':') => {
                    // A POSIX class [:alpha:] is copied whole.
                    let rest: String = chars[i..].iter().collect();
                    if let Some(end) = rest.find(":]") {
                        out.push('[');
                        out.push_str(&rest[..end + 2]);
                        i += rest[..end + 2].chars().count();
                    } else {
                        out.push_str(r"\[");
                    }
                }
                '[' => out.push_str(r"\["),
                '&' => out.push_str(r"\&"),
                '~' => out.push_str(r"\~"),
                _ => out.push(c),
            }
            continue;
        }
        match c {
            '[' => {
                in_class = true;
                out.push('[');
                if chars.get(i) == Some(&'^') {
                    out.push('^');
                    i += 1;
                }
                if chars.get(i) == Some(&']') {
                    out.push_str(r"\]"); // a leading ] is a literal
                    i += 1;
                }
            }
            '{' => match repeat_len(&chars, i - 1) {
                Some(n) => {
                    out.extend(&chars[i - 1..i - 1 + n]);
                    i = i - 1 + n;
                }
                None => out.push_str(r"\{"),
            },
            _ => out.push(c),
        }
    }
    out
}

/// Compiles a Go RE2 pattern with Go's meaning (see the module comment).
pub fn compile_regex(pat: &str) -> Result<Regex, RulesError> {
    Regex::new(&translate_regex(pat)).map_err(|e| RulesError(e.to_string()))
}

/// For regexes that are part of the program.
fn builtin_regex(pat: &str) -> Regex {
    compile_regex(pat).unwrap_or_else(|e| panic!("built-in regex {pat:?}: {e}"))
}

// --- Go path and JSON semantics ---------------------------------------------

/// Go's `path.Clean`.
fn path_clean(p: &str) -> String {
    if p.is_empty() {
        return ".".into();
    }
    let rooted = p.starts_with('/');
    let mut stack: Vec<&str> = Vec::new();
    for seg in p.split('/') {
        match seg {
            "" | "." => {}
            ".." => match stack.last() {
                Some(&last) if last != ".." => {
                    stack.pop();
                }
                _ if !rooted => stack.push(".."),
                _ => {}
            },
            s => stack.push(s),
        }
    }
    let joined = stack.join("/");
    match (rooted, joined.is_empty()) {
        (true, _) => format!("/{joined}"),
        (false, true) => ".".into(),
        (false, false) => joined,
    }
}

/// Go's `path.Base`.
fn path_base(p: &str) -> &str {
    if p.is_empty() {
        return ".";
    }
    let p = p.trim_end_matches('/');
    if p.is_empty() {
        return "/";
    }
    p.rsplit('/').next().unwrap_or(p)
}

/// Replaces a lone UTF-16 surrogate escape in a JSON string with `\ufffd`, as
/// Go's decoder does. `serde_json` accepts such an escape in a raw value but
/// fails when it decodes the string, and the call would then be matched on its
/// escaped text (where `\n` is not a line break) instead of its content.
pub(crate) fn sanitize_surrogates(json: &str) -> std::borrow::Cow<'_, str> {
    if !json.contains("\\u") {
        return json.into();
    }
    let b = json.as_bytes();
    let hex4 = |at: usize| -> Option<u32> {
        let h = json.get(at..at + 4)?;
        if !h.bytes().all(|c| c.is_ascii_hexdigit()) {
            return None;
        }
        u32::from_str_radix(h, 16).ok()
    };
    let mut out = String::with_capacity(json.len());
    let mut i = 0;
    let mut copied = 0;
    let mut in_string = false;
    while i < b.len() {
        match b[i] {
            b'"' => in_string = !in_string,
            b'\\' if in_string => {
                if b.get(i + 1) == Some(&b'u')
                    && let Some(u) = hex4(i + 2)
                {
                    let pair = (0xD800..0xDC00).contains(&u)
                        && b.get(i + 6) == Some(&b'\\')
                        && b.get(i + 7) == Some(&b'u')
                        && hex4(i + 8).is_some_and(|l| (0xDC00..0xE000).contains(&l));
                    if pair {
                        i += 12;
                    } else if (0xD800..0xE000).contains(&u) {
                        out.push_str(&json[copied..i]);
                        out.push_str("\\ufffd");
                        i += 6;
                        copied = i;
                    } else {
                        i += 6;
                    }
                } else {
                    i += 2; // any other escape
                }
                continue;
            }
            _ => {}
        }
        i += 1;
    }
    out.push_str(&json[copied..]);
    out.into()
}

/// Go's `json.Compact` for valid JSON: drops whitespace outside strings.
fn compact_json(json: &str) -> String {
    let mut out = String::with_capacity(json.len());
    let (mut in_string, mut escaped) = (false, false);
    for c in json.chars() {
        if in_string {
            out.push(c);
            if escaped {
                escaped = false;
            } else if c == '\\' {
                escaped = true;
            } else if c == '"' {
                in_string = false;
            }
        } else if c == '"' {
            in_string = true;
            out.push(c);
        } else if !matches!(c, ' ' | '\t' | '\n' | '\r') {
            out.push(c);
        }
    }
    out
}

/// Every string in a JSON value, objects in key order.
fn collect_strings(v: &Value, out: &mut Vec<String>) {
    match v {
        Value::String(s) => out.push(s.clone()),
        Value::Array(a) => a.iter().for_each(|e| collect_strings(e, out)),
        // serde_json's map is sorted by key, like Go's sort.Strings.
        Value::Object(m) => m.values().for_each(|e| collect_strings(e, out)),
        _ => {}
    }
}

/// The string value of the top-level key `name` of a tool input, with Go's
/// struct-decoding rules: the key matches in any letter case, the last
/// string-valued match wins, other types and null are skipped. A shell
/// command read this way is the one the host runs, so a differently cased key
/// must not hide it.
pub fn input_string_field(input: &str, name: &str) -> String {
    struct Pairs(Vec<(String, Box<RawValue>)>);
    impl<'de> serde::Deserialize<'de> for Pairs {
        fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
            struct V;
            impl<'de> serde::de::Visitor<'de> for V {
                type Value = Pairs;
                fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                    f.write_str("a JSON object")
                }
                fn visit_map<A: serde::de::MapAccess<'de>>(
                    self,
                    mut m: A,
                ) -> Result<Pairs, A::Error> {
                    let mut v = Vec::new();
                    while let Some(kv) = m.next_entry::<String, Box<RawValue>>()? {
                        v.push(kv);
                    }
                    Ok(Pairs(v))
                }
            }
            d.deserialize_map(V)
        }
    }
    let text = sanitize_surrogates(input);
    let Ok(Pairs(pairs)) = serde_json::from_str::<Pairs>(&text) else {
        return String::new();
    };
    let mut found = String::new();
    for (k, v) in pairs {
        if k.eq_ignore_ascii_case(name)
            && let Ok(s) = serde_json::from_str::<String>(v.get())
        {
            found = s;
        }
    }
    found
}

// --- Paths ------------------------------------------------------------------

/// What path handling needs from the host. Symlinks are never resolved: a
/// link inside the project that points outside it counts as inside.
#[derive(Debug, Clone, Default)]
pub struct Env {
    /// User home directory, "" if unknown.
    pub home: String,
    /// Backslash separators, drive letters, case-insensitive paths.
    pub windows: bool,
    /// Case-insensitive paths on other hosts (macOS default file systems).
    pub fold_case: bool,
}

/// Go's `regexp.QuoteMeta`.
fn quote_meta(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if "\\.+*?()|[]{}^$".contains(c) {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

impl Env {
    /// Describes the running host.
    pub fn host() -> Env {
        Env {
            home: policy::home_dir().unwrap_or_default(),
            windows: cfg!(windows),
            fold_case: cfg!(target_os = "macos"),
        }
    }

    fn caseless(&self) -> bool {
        self.windows || self.fold_case
    }

    fn slash(&self, s: &str) -> String {
        if self.windows {
            s.replace('\\', "/")
        } else {
            s.to_owned()
        }
    }

    fn is_abs(&self, s: &str) -> bool {
        let b = s.as_bytes();
        s.starts_with('/')
            || (self.windows
                && b.len() >= 3
                && b[1] == b':'
                && b[2] == b'/'
                && b[0].is_ascii_alphabetic())
    }

    /// An absolute, slash-normalized path for `p` relative to `cwd`: expands
    /// `~`, makes `p` absolute against `cwd` and cleans it. A relative `p` with
    /// no `cwd` stays relative.
    pub fn normalize(&self, p: &str, cwd: &str) -> String {
        let mut p = self.slash(p);
        if !self.home.is_empty() && (p == "~" || p.starts_with("~/")) {
            p = format!("{}{}", self.slash(&self.home), &p[1..]);
        }
        if !self.is_abs(&p) && !cwd.is_empty() {
            p = format!("{}/{p}", self.slash(cwd));
        }
        let mut p = path_clean(&p);
        if self.windows && p.len() == 2 && p.as_bytes()[1] == b':' {
            p.push('/'); // path.Clean("C:/") drops the slash
        }
        p
    }

    fn fold(&self, s: &str) -> String {
        if self.caseless() {
            s.to_lowercase()
        } else {
            s.to_owned()
        }
    }

    /// Whether the normalized path `p` is `dir` or below it.
    pub fn in_dir(&self, p: &str, dir: &str) -> bool {
        if dir.is_empty() {
            return false;
        }
        let p = self.fold(p);
        let dir = self.fold(dir.strip_suffix('/').unwrap_or(dir));
        p == dir || p.starts_with(&format!("{dir}/"))
    }

    /// Compiles a path glob. `*` and `?` stay inside one path segment, `**`
    /// crosses segments, `**/` also matches nothing and a trailing `/**` also
    /// matches the directory itself. A leading `~/` is expanded. The result
    /// matches normalized (slash, absolute) paths.
    pub fn compile_glob(&self, glob: &str) -> Result<Regex, RulesError> {
        let mut g = self.slash(glob);
        if !self.home.is_empty() && g.starts_with("~/") {
            g = format!("{}{}", self.slash(&self.home), &g[1..]);
        }
        let mut b = String::new();
        if self.caseless() {
            b.push_str("(?i)");
        }
        b.push('^');
        let bytes = g.as_bytes();
        let mut i = 0;
        while i < bytes.len() {
            let c = bytes[i];
            if c == b'/' && &g[i..] == "/**" {
                b.push_str("(?:/.*)?");
                i += 3;
            } else if c == b'*' && bytes.get(i + 1) == Some(&b'*') {
                let mut j = i;
                while j < bytes.len() && bytes[j] == b'*' {
                    j += 1;
                }
                if j < bytes.len() && bytes[j] == b'/' && (i == 0 || bytes[i - 1] == b'/') {
                    b.push_str("(?:.*/)?");
                    j += 1;
                } else {
                    b.push_str(".*");
                }
                i = j;
            } else if c == b'*' {
                b.push_str("[^/]*");
                i += 1;
            } else if c == b'?' {
                b.push_str("[^/]");
                i += 1;
            } else if c == b'[' {
                let Some(end) = g[i..].find(']') else {
                    return Err(RulesError(format!("glob {}: unclosed [", go_quote(glob))));
                };
                let class = &g[i + 1..i + end];
                let class = match class.strip_prefix('!') {
                    Some(rest) => format!("^{rest}"),
                    None => class.to_owned(),
                };
                b.push_str(&format!("[{class}]"));
                i += end + 1;
            } else {
                let ch = g[i..].chars().next().unwrap_or('\u{fffd}');
                b.push_str(&quote_meta(&ch.to_string()));
                i += ch.len_utf8();
            }
        }
        b.push('$');
        compile_regex(&b).map_err(|e| RulesError(format!("glob {}: {e}", go_quote(glob))))
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

const PATH_KEYS: [&str; 4] = ["file_path", "path", "notebook_path", "filePath"];

/// Joins shell (backslash) and PowerShell (backtick) line continuations, so a
/// command split over lines is matched as one line.
fn join_continuations(s: &str) -> String {
    const PAIRS: [&str; 4] = ["\\\r\n", "\\\n", "`\r\n", "`\n"];
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    'outer: while !rest.is_empty() {
        for p in PAIRS {
            if let Some(tail) = rest.strip_prefix(p) {
                out.push(' ');
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

impl Call {
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
                    c.fields.insert(k, value);
                }
            }
            c.whole = compact_json(raw.get());
            let mut leaves = Vec::new();
            if let Ok(v) = serde_json::from_str::<Value>(&text) {
                collect_strings(&v, &mut leaves);
            }
            if !leaves.is_empty() {
                c.whole.push('\n');
                c.whole.push_str(&leaves.join("\n"));
            }
        }
        let field = |c: &Call, k: &str| c.fields.get(k).cloned().unwrap_or_default();
        if kind == KIND_SHELL {
            c.command = field(&c, "command");
            if c.command.is_empty() && input.tool == "execute_code" {
                c.command = field(&c, "code");
            }
            c.command = join_continuations(&c.command);
        }
        c.url = field(&c, "url");
        let mut raw_path = PATH_KEYS
            .iter()
            .map(|k| field(&c, k))
            .find(|v| !v.is_empty())
            .unwrap_or_default();
        if raw_path.is_empty() && kind == KIND_READ {
            raw_path = input.cwd.clone(); // Glob, Grep and LS default to the working directory
        }
        if !raw_path.is_empty() {
            c.path = env.normalize(&raw_path, &input.cwd);
            if !input.project_dir.is_empty() {
                c.in_project = env.in_dir(&c.path, &env.normalize(&input.project_dir, &input.cwd));
            }
        }
        c
    }
}

// --- Built-in rules ---------------------------------------------------------

/// A built-in rule that fired. `decision` is "deny" or "ask".
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hit {
    pub id: String,
    pub decision: String,
    pub reason: String,
}

/// The files that carry hook and policy configuration.
const PROTECTED_GLOBS: [&str; 10] = [
    "**/.claude/settings.json",
    "**/.claude/settings.local.json",
    "**/.callguard/**",
    "/etc/callguard/**",
    "**/.hermes/config.yaml",
    "**/.hermes/shell-hooks-allowlist.json",
    "**/.config/opencode/plugins/**",
    "**/.opencode/plugins/**",
    "**/.pi/agent/extensions/**",
    "**/.pi/extensions/**",
];

/// Finds those paths in a slash-normalized command line. A glob in the file
/// name (`.claude/*.json`) counts as naming them.
static PROTECTED_SHELL: LazyLock<Regex> = LazyLock::new(|| {
    builtin_regex(concat!(
        r"(?i)\.claude/(?:settings|[^/\s]*[*?\[])|\.callguard\b|/etc/callguard|programdata/callguard",
        r"|\.hermes/(?:config\.yaml|shell-hooks-allowlist\.json|[^/\s]*[*?\[])|\.config/opencode/plugins|\.opencode/plugins|\.pi/(?:agent/)?extensions"
    ))
});

/// The names of whole-disk and partition block devices.
macro_rules! disk_dev_re {
    () => {
        "(?:sd|hd|vd|xvd|nvme|mmcblk|disk)"
    };
}

static DISK_WIPE: LazyLock<Vec<Regex>> = LazyLock::new(|| {
    vec![
        builtin_regex(
            r"(?m)(?:^|[;&|(])\s*(?:(?:sudo|doas)\b[^;&|\n]*\s)?(?:\S*/)?mkfs(?:\.\w+)?\b",
        ),
        builtin_regex(concat!(r"\bdd\b[^;&|\n]*\bof=/dev/", disk_dev_re!())),
        builtin_regex(concat!(r">\s*/dev/", disk_dev_re!())),
        builtin_regex(r"(?i)(?:^|[;&|])\s*format(?:\.com)?\s+[a-z]:"),
    ]
});

static FORK_BOMB: LazyLock<Regex> =
    LazyLock::new(|| builtin_regex(r":\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:"));

/// Cuts a command line at separators, subshells and command substitutions, so
/// each piece starts at a command position.
static SEGMENT_SPLIT: LazyLock<Regex> = LazyLock::new(|| builtin_regex("[;&|\\n\\r()`]+"));
static RM_DANGER: LazyLock<Regex> = LazyLock::new(|| {
    builtin_regex(
        r"(?i)^(?:/+\*?|~/?\*?|(?:\$home|\$\{home\}|\$env:(?:userprofile|home)|%userprofile%)/?\*?|(?:\./)?\.git/?|[a-z]:/?\*?)$",
    )
});
static UNIX_FLAGS: LazyLock<Regex> = LazyLock::new(|| builtin_regex(r"^-[a-zA-Z]+$")); // -rf, -Rfv
static WIN_FLAG: LazyLock<Regex> = LazyLock::new(|| builtin_regex(r"^/[a-zA-Z]$"));

/// Commands that delete files.
const REMOVERS: [&str; 7] = ["rm", "rmdir", "rd", "del", "erase", "remove-item", "ri"];

/// The wrappers run the rest of their arguments as a command (shells with -c
/// too). Returns the options that take a separate argument, and "#n" says that
/// n positional arguments precede the command; None if `name` is no wrapper.
fn wrapper(name: &str) -> Option<&'static [&'static str]> {
    Some(match name {
        "sudo" => &[
            "-u",
            "-g",
            "-C",
            "-D",
            "-h",
            "-p",
            "-r",
            "-t",
            "-T",
            "-U",
            "--user",
            "--group",
            "--chdir",
            "--chroot",
            "--close-from",
            "--host",
            "--prompt",
            "--role",
            "--type",
            "--command-timeout",
            "--other-user",
        ],
        "doas" => &["-u", "-C"],
        "env" => &["-u", "-C", "-S", "--unset", "--chdir", "--split-string"],
        "nice" => &["-n", "--adjustment"],
        "ionice" => &["-c", "-n", "-p"],
        "timeout" => &["-s", "-k", "--signal", "--kill-after", "#1"],
        "stdbuf" => &["-i", "-o", "-e"],
        "chroot" => &["#1"],
        "xargs" => &["-a", "-d", "-E", "-I", "-L", "-n", "-P", "-s"],
        "exec" => &["-a"],
        "time" => &["-f", "-o"],
        "command" | "nohup" | "setsid" | "busybox" | "sh" | "bash" | "zsh" | "dash" | "{" | "!"
        | "if" | "then" | "else" | "do" => &[],
        _ => return None,
    })
}

/// The lower-case base name of a command word.
fn command_name(tok: &str) -> String {
    let base = path_base(&tok.replace('\\', "/")).to_owned();
    base.strip_suffix(".exe").unwrap_or(&base).to_lowercase()
}

/// The index of the command a wrapper at `toks[i - 1]` runs.
fn skip_wrapper(toks: &[&str], mut i: usize, valued: &[&str]) -> usize {
    let mut positional = valued
        .iter()
        .find_map(|o| o.strip_prefix('#'))
        .and_then(|n| n.parse::<usize>().ok())
        .unwrap_or(0);
    while i < toks.len() {
        let t = toks[i];
        if t == "--" {
            return i + 1;
        } else if t.starts_with('-') && t.len() > 1 {
            i += 1;
            if valued.contains(&t) {
                i += 1; // the option's value
            }
        } else if t.contains('=') {
            i += 1; // env VAR=value
        } else if positional > 0 {
            positional -= 1;
            i += 1;
        } else {
            return i;
        }
    }
    i
}

/// Whether a shell command recursively deletes a root-like target (`/`, `~`,
/// `$HOME`, a drive root, `.git`) or passes `--no-preserve-root`, at a command
/// position: after wrappers such as sudo, timeout or `sh -c`, so text inside
/// an ordinary argument does not fire it.
pub fn rm_root(command: &str) -> bool {
    for seg in SEGMENT_SPLIT.split(command) {
        let unquoted = seg.replace(['"', '\''], "");
        let toks: Vec<&str> = unquoted.split_whitespace().collect();
        let mut i = 0;
        while i < toks.len() {
            if let Some(valued) = wrapper(&command_name(toks[i])) {
                i = skip_wrapper(&toks, i + 1, valued);
                continue;
            }
            if toks[i].contains('=') {
                i += 1; // VAR=value prefix
                continue;
            }
            break;
        }
        if i >= toks.len() {
            continue;
        }
        let name = command_name(toks[i]);
        if !REMOVERS.contains(&name.as_str()) {
            continue;
        }
        let mut recursive = false;
        let mut targets: Vec<String> = Vec::new();
        for t in &toks[i + 1..] {
            let lower = t.to_lowercase();
            if *t == "--no-preserve-root" {
                return true;
            }
            if *t == "--recursive"
                || (t.len() > 1 && "-recurse".starts_with(&lower)) // PowerShell accepts -r, -rec, ...
                || ((name == "rm" || name == "rmdir")
                    && UNIX_FLAGS.is_match(t)
                    && t.contains(['r', 'R']))
            {
                recursive = true;
            } else if t.starts_with('-') {
                // any other option
            } else if WIN_FLAG.is_match(t) && name != "rm" {
                recursive = recursive || lower == "/s";
            } else {
                targets.push(path_clean(&t.replace('\\', "/")));
            }
        }
        if recursive && targets.iter().any(|t| RM_DANGER.is_match(t)) {
            return true;
        }
    }
    false
}

/// The always-on layer 0.
#[derive(Debug)]
pub struct Builtin {
    env: Env,
    disabled: Vec<String>,
    /// Write targets.
    protected: Vec<Regex>,
    /// Extra files as they may appear in a command, folded.
    extra: Vec<String>,
}

impl Builtin {
    /// Compiles the built-in rules, minus the `disabled` ids. `extra` are
    /// further files for the self-protection rules (such as an explicit policy
    /// file).
    pub fn new(env: Env, disabled: &[String], extra: &[String]) -> Result<Builtin, RulesError> {
        let mut globs: Vec<String> = PROTECTED_GLOBS.iter().map(|g| (*g).to_owned()).collect();
        let sys_dir = std::path::Path::new(&policy::system_path())
            .parent()
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_default();
        globs.push(format!("{}/**", env.slash(&sys_dir)));
        let mut protected = Vec::new();
        for g in &globs {
            protected.push(env.compile_glob(g)?);
        }
        let mut folded_extra = Vec::new();
        for p in extra {
            let p = env.slash(p);
            let mut pat = format!("^{}$", quote_meta(&p));
            if env.caseless() {
                pat.insert_str(0, "(?i)");
            }
            protected.push(compile_regex(&pat)?);
            folded_extra.push(env.fold(&p));
            let slashed_home = env.slash(&env.home);
            let home = slashed_home.strip_suffix('/').unwrap_or(&slashed_home);
            if !home.is_empty()
                && env.in_dir(&p, home)
                && p.len() >= home.len()
                && let Some(rest) = p.get(home.len()..)
            {
                folded_extra.push(env.fold(&format!("~{rest}")));
                folded_extra.push(env.fold(&format!("$HOME{rest}")));
            }
        }
        Ok(Builtin {
            env,
            disabled: disabled.to_vec(),
            protected,
            extra: folded_extra,
        })
    }

    /// Whether `text` (a command line or a tool input) names a hook or policy
    /// file.
    fn names_protected(&self, text: &str) -> bool {
        let text = self.env.slash(text);
        if PROTECTED_SHELL.is_match(&text) {
            return true;
        }
        let folded = self.env.fold(&text);
        self.extra.iter().any(|p| folded.contains(p.as_str()))
    }

    /// The first built-in rule that fires for `c`. Hard denies are checked
    /// before the self-protection ask.
    pub fn check(&self, c: &Call) -> Option<Hit> {
        let on = |id: &str| !self.disabled.iter().any(|d| d == id);
        let hit = |id: &str, decision: &str, reason: String| {
            Some(Hit {
                id: id.into(),
                decision: decision.into(),
                reason,
            })
        };
        if c.kind == KIND_WRITE && on("self-protect-write") {
            if !c.path.is_empty() && self.protected.iter().any(|re| re.is_match(&c.path)) {
                return hit(
                    "self-protect-write",
                    "deny",
                    format!(
                        "callguard denies edits to hook and policy files ({}); ask the user to change them",
                        c.path
                    ),
                );
            }
            // Patch tools carry their target paths inside the input.
            if c.path.is_empty() && self.names_protected(&c.whole) {
                return hit(
                    "self-protect-write",
                    "ask",
                    "edit names a hook or policy file; a human should confirm".into(),
                );
            }
        }
        if c.kind == KIND_SHELL && !c.command.is_empty() {
            let cmd = &c.command;
            if on("rm-root") && rm_root(cmd) {
                return hit(
                    "rm-root",
                    "deny",
                    "recursive deletion of a root, home or .git directory".into(),
                );
            }
            if on("disk-wipe") && DISK_WIPE.iter().any(|re| re.is_match(cmd)) {
                return hit(
                    "disk-wipe",
                    "deny",
                    "command formats or overwrites a disk".into(),
                );
            }
            if on("fork-bomb") && FORK_BOMB.is_match(cmd) {
                return hit("fork-bomb", "deny", "fork bomb".into());
            }
            if on("self-protect-shell") && self.names_protected(cmd) {
                return hit(
                    "self-protect-shell",
                    "ask",
                    "command names a hook or policy file; a human should confirm".into(),
                );
            }
        }
        None
    }
}

// --- Policy rules -----------------------------------------------------------

struct Compiled {
    rule: policy::Rule,
    command: Option<Regex>,
    url: Option<Regex>,
    fields: BTreeMap<String, Regex>,
    path: Vec<Regex>,
    not_path: Vec<Regex>,
}

impl Compiled {
    fn matches(&self, call: &Call) -> bool {
        let m = &self.rule.r#match;
        if !m.tool.is_empty() && !m.tool.contains(&call.tool) {
            return false;
        }
        if !m.kind.is_empty() && !m.kind.contains(&call.kind) {
            return false;
        }
        if !m.harness.is_empty() && !m.harness.contains(&call.harness) {
            return false;
        }
        if m.unattended.is_some_and(|u| u != call.unattended) {
            return false;
        }
        for (k, allowed) in &m.context {
            if !call.context.get(k).is_some_and(|v| allowed.contains(v)) {
                return false;
            }
        }
        if let Some(re) = &self.command
            && (call.command.is_empty() || !re.is_match(&call.command))
        {
            return false;
        }
        if let Some(re) = &self.url
            && (call.url.is_empty() || !re.is_match(&call.url))
        {
            return false;
        }
        for (k, re) in &self.fields {
            if k == "*" {
                if !re.is_match(&call.whole) {
                    return false;
                }
            } else if !call.fields.get(k).is_some_and(|v| re.is_match(v)) {
                return false;
            }
        }
        if m.in_project
            .is_some_and(|ip| call.path.is_empty() || ip != call.in_project)
        {
            return false;
        }
        if !self.path.is_empty()
            && (call.path.is_empty() || !self.path.iter().any(|re| re.is_match(&call.path)))
        {
            return false;
        }
        if !call.path.is_empty() && self.not_path.iter().any(|re| re.is_match(&call.path)) {
            return false;
        }
        true
    }
}

/// A compiled, ordered list of policy rules.
pub struct Set {
    rules: Vec<Compiled>,
}

impl std::fmt::Debug for Set {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Set")
            .field("rules", &self.rules.len())
            .finish()
    }
}

fn compile_rule(r: &policy::Rule, env: &Env) -> Result<Compiled, String> {
    if r.id.is_empty() {
        return Err("missing id".into());
    }
    if !["allow", "ask", "deny"].contains(&r.decision.as_str()) {
        return Err(format!(
            "decision {} must be allow, ask or deny",
            go_quote(&r.decision)
        ));
    }
    let m = &r.r#match;
    if m.is_empty() {
        return Err("no match conditions".into());
    }
    let re = |pat: &str, what: String| compile_regex(pat).map_err(|e| format!("{what}: {e}"));
    let mut c = Compiled {
        rule: r.clone(),
        command: None,
        url: None,
        fields: BTreeMap::new(),
        path: Vec::new(),
        not_path: Vec::new(),
    };
    if !m.command.is_empty() {
        c.command = Some(re(&m.command, "match.command".into())?);
    }
    if !m.url.is_empty() {
        c.url = Some(re(&m.url, "match.url".into())?);
    }
    for (k, v) in &m.field {
        c.fields
            .insert(k.clone(), re(v, format!("match.field[{}]", go_quote(k)))?);
    }
    for g in &m.path {
        c.path.push(
            env.compile_glob(g)
                .map_err(|e| format!("match.path: {e}"))?,
        );
    }
    for g in &m.not_path {
        c.not_path.push(
            env.compile_glob(g)
                .map_err(|e| format!("match.not_path: {e}"))?,
        );
    }
    Ok(c)
}

fn rank(decision: &str) -> u8 {
    match decision {
        "allow" => 1,
        "ask" => 2,
        "deny" => 3,
        _ => 0,
    }
}

impl Set {
    /// Validates and compiles rules. The error names the offending rule.
    pub fn compile(rules: &[policy::Rule], env: &Env) -> Result<Set, RulesError> {
        let mut set = Vec::with_capacity(rules.len());
        for r in rules {
            set.push(
                compile_rule(r, env)
                    .map_err(|e| RulesError(format!("rule {}: {e}", go_quote(&r.id))))?,
            );
        }
        Ok(Set { rules: set })
    }

    /// The matching rule that wins: deny over ask over allow, then list order.
    /// (Go: `Set.Match`; `match` is a keyword.)
    pub fn match_call(&self, call: &Call) -> Option<policy::Rule> {
        let mut best: Option<&Compiled> = None;
        for c in &self.rules {
            if !c.matches(call) {
                continue;
            }
            if best.is_none_or(|b| rank(&c.rule.decision) > rank(&b.rule.decision)) {
                best = Some(c);
            }
        }
        best.map(|c| c.rule.clone())
    }
}

#[cfg(test)]
mod tests;
