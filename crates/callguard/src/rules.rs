//! Maps tool calls to kinds, extracts paths and commands from their input, and
//! evaluates the built-in and policy rules.
//!
//! Every regex here and in a policy is RE2. [`compile_regex`] makes the
//! `regex` crate read it that way, because the two differ where it
//! matters for a guard: RE2's `\b`, `\s`, `\w` and `\d` are ASCII-only, the
//! `regex` crate's are Unicode.

use std::collections::BTreeMap;
use std::sync::LazyLock;

use regex::Regex;
use serde_json::Value;
use serde_json::value::RawValue;

use crate::policy::{self, quote_string};

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

// --- RE2 semantics ---------------------------------------------------

/// `\s` in RE2: `[\t\n\f\r ]`.
const RE2_SPACE: &str = r"\t\n\f\r ";

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

/// Rewrites an RE2 pattern into the `regex` crate's syntax with the same
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
                's' if in_class => out.push_str(RE2_SPACE),
                's' => out.push_str(&format!("[{RE2_SPACE}]")),
                'S' => out.push_str(&format!("[^{RE2_SPACE}]")),
                'd' if in_class => out.push_str("0-9"),
                'd' => out.push_str("[0-9]"),
                'D' => out.push_str("[^0-9]"),
                'w' if in_class => out.push_str("0-9A-Za-z_"),
                'w' => out.push_str("[0-9A-Za-z_]"),
                'W' => out.push_str("[^0-9A-Za-z_]"),
                '<' | '>' => out.push(e),
                // RE2: `\0` and `\1`..`\7` followed by an octal digit are octal
                // codes; a lone `\1`..`\9` is a backreference, which RE2 refuses.
                // `\9` is refused by the regex crate for the same reason.
                '1'..='9'
                    if !(e <= '7' && chars.get(i).is_some_and(|d| ('0'..='7').contains(d))) =>
                {
                    out.push_str(r"\9");
                }
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

/// Compiles an RE2 pattern with its RE2 meaning (see the module comment).
pub fn compile_regex(pat: &str) -> Result<Regex, RulesError> {
    // Octal escapes (`\101`) are RE2 syntax. The size limit stays at its
    // default: a repository's policy must not cost compile time.
    regex::RegexBuilder::new(&translate_regex(pat))
        .octal(true)
        .build()
        .map_err(|e| RulesError(e.to_string()))
}

/// For regexes that are part of the program.
fn builtin_regex(pat: &str) -> Regex {
    compile_regex(pat).unwrap_or_else(|e| panic!("built-in regex {pat:?}: {e}"))
}

// --- Path and JSON semantics ---------------------------------------------

/// Lexical path cleaning: `.` and `..` resolved, slashes collapsed.
pub(crate) fn path_clean(p: &str) -> String {
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

/// The last element of a slash path.
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
/// the decoder of earlier versions did. `serde_json` accepts such an escape in a raw value but
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

/// Compacts valid JSON: drops whitespace outside strings.
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
        // serde_json's map is sorted by key.
        Value::Object(m) => m.values().for_each(|e| collect_strings(e, out)),
        _ => {}
    }
}

/// The string value of the top-level key `name` of a tool input, with
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

/// What path handling needs from the host. A call's path is also resolved
/// through symlinks and junctions ([`Env::real`]); see [`Call::real_path`].
#[derive(Debug, Clone, Default)]
pub struct Env {
    /// User home directory, "" if unknown.
    pub home: String,
    /// Backslash separators, drive letters, case-insensitive paths.
    pub windows: bool,
    /// Case-insensitive paths on other hosts (macOS default file systems).
    pub fold_case: bool,
    /// Whether this describes the running host. Only [`Env::host`] sets it;
    /// the file system says nothing about any other `Env` (unit tests with a
    /// made-up host), so [`Env::real`] does not touch the disk for one.
    pub host: bool,
}

/// The longest path that can exist. Windows: 32767 UTF-16 units. Unix: the
/// kernel takes 4096 bytes per path, but `p` is absolute, so it can be a
/// relative path (up to 4096) under a working directory (up to 4096), which is
/// longer than either and still exists.
const MAX_PATH_LEN: usize = if cfg!(windows) { 32767 } else { 8192 };

fn path_too_long(p: &str) -> bool {
    if cfg!(windows) {
        p.encode_utf16().count() > MAX_PATH_LEN
    } else {
        p.len() > MAX_PATH_LEN
    }
}

/// The real location of the normalized path `p`: links and junctions
/// resolved, with the deepest existing ancestor standing in for a file that
/// does not exist yet. Slash form without the Windows `//?/` prefix; None if
/// nothing resolves.
pub(crate) fn resolve_real(p: &str) -> Option<String> {
    // Too long to exist: no system call per component. Deny and ask rules
    // still match the lexical path, and an allow cannot match None.
    if path_too_long(p) {
        return None;
    }
    let mut existing = std::path::Path::new(p).to_path_buf();
    let mut rest = Vec::new();
    let real = loop {
        match std::fs::canonicalize(&existing) {
            Ok(c) => break c,
            Err(_) => {
                // A link whose target is missing is no missing file: refuse.
                if std::fs::symlink_metadata(&existing).is_ok() {
                    return None;
                }
                rest.push(existing.file_name()?.to_owned());
                if !existing.pop() {
                    return None;
                }
            }
        }
    };
    let mut out = real;
    for name in rest.iter().rev() {
        out.push(name);
    }
    let s = out.to_string_lossy();
    // A backslash separates only on Windows; in a Unix file name it is a letter.
    let s = if cfg!(windows) {
        s.replace('\\', "/")
    } else {
        s.into_owned()
    };
    Some(if let Some(unc) = s.strip_prefix("//?/UNC/") {
        format!("//{unc}") // a network share
    } else {
        s.strip_prefix("//?/").unwrap_or(&s).to_owned()
    })
}

/// Escapes regex metacharacters.
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
            host: true,
        }
    }

    pub(crate) fn caseless(&self) -> bool {
        self.windows || self.fold_case
    }

    pub(crate) fn slash(&self, s: &str) -> String {
        if self.windows {
            s.replace('\\', "/")
        } else {
            s.to_owned()
        }
    }

    pub(crate) fn is_abs(&self, s: &str) -> bool {
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

    pub(crate) fn fold(&self, s: &str) -> String {
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

    /// The real location of the normalized path `p`, slash-normalized: links
    /// and junctions resolved, a not-yet-existing tail kept under its longest
    /// existing parent. None if it cannot be resolved (a dangling link, no
    /// existing ancestor). When `self` does not describe the running host (unit
    /// tests with a made-up `Env`) the file system says nothing, and `p` is
    /// its own real location.
    pub fn real(&self, p: &str) -> Option<String> {
        if !self.host {
            return Some(p.to_owned());
        }
        resolve_real(p)
    }

    /// Windows reads `a./b`, `a /b` and `b::$DATA` as `a/b` and `b`: drops
    /// trailing dots and spaces and a `:stream` suffix from each component of
    /// the normalized path `p`. Only on a Windows host; elsewhere those are
    /// different names.
    pub(crate) fn clean_names(&self, p: &str) -> String {
        if !(cfg!(windows) && self.windows) {
            return p.to_owned();
        }
        let segs: Vec<&str> = p.split('/').collect();
        let out: Vec<String> = segs
            .iter()
            .enumerate()
            .map(|(i, seg)| {
                let b = seg.as_bytes();
                let drive = b.len() == 2
                    && b[0].is_ascii_alphabetic()
                    && b[1] == b':'
                    && (i == 0 || (i > 0 && matches!(segs[i - 1], "?" | ".")));
                if drive || matches!(*seg, "" | "." | "..") {
                    return (*seg).to_owned();
                }
                let name = seg.split(':').next().unwrap_or_default();
                name.trim_end_matches(['.', ' ']).to_owned()
            })
            .collect();
        let rooted = p.starts_with('/');
        let cleaned = path_clean(&out.join("/"));
        if rooted && !cleaned.starts_with('/') {
            return format!("/{cleaned}");
        }
        cleaned
    }

    /// Whether the normalized directory `dir` (and its real location) is the
    /// user's home or a file system root, so that "inside it" says nothing.
    fn is_broad_dir(&self, dir: &str, real: Option<&str>) -> bool {
        let trim = |p: &str| {
            if p.len() > 1 {
                p.trim_end_matches('/').to_owned()
            } else {
                p.to_owned()
            }
        };
        let root = |p: &str| {
            let b = p.as_bytes();
            p == "/" || (self.windows && b.len() == 3 && b[1] == b':' && b[2] == b'/')
        };
        let home = (!self.home.is_empty()).then(|| self.normalize(&self.home, ""));
        let real_home = home.as_deref().and_then(|h| self.real(h));
        let homes: Vec<String> = [home, real_home]
            .into_iter()
            .flatten()
            .map(|h| self.fold(&trim(&h)))
            .collect();
        [Some(dir), real]
            .into_iter()
            .flatten()
            .any(|d| root(d) || root(&trim(d)) || homes.contains(&self.fold(&trim(d))))
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
                    return Err(RulesError(format!(
                        "glob {}: unclosed [",
                        quote_string(glob)
                    )));
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
        compile_regex(&b).map_err(|e| RulesError(format!("glob {}: {e}", quote_string(glob))))
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
    /// Shell command text, "" if none. Line continuations are joined with a
    /// space.
    pub command: String,
    /// The command with line continuations joined with nothing, as a POSIX
    /// shell reads `r\<NL>m`; "" if it equals `command`. Deny and ask look at
    /// both spellings, allow needs both to match (see [`Call::commands`]).
    pub command_joined: String,
    /// The distinct values of the command field as the host sent them, before
    /// line continuations are joined. Allow rules need exactly one.
    pub raw_commands: Vec<String>,
    pub url: String,
    /// Normalized absolute path, "" if none.
    pub path: String,
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
    /// Top-level input fields; non-strings JSON-encoded.
    pub fields: BTreeMap<String, String>,
    /// Compact input JSON plus every string leaf, for the "*" field.
    pub whole: String,
    pub context: BTreeMap<String, String>,
    pub unattended: bool,
    pub cwd: String,
    pub project_dir: String,
}

pub(crate) const PATH_KEYS: [&str; 4] = ["file_path", "path", "notebook_path", "filePath"];

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
pub(crate) fn field_values(fields: &BTreeMap<String, String>, key: &str) -> Vec<String> {
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

impl Call {
    /// The spellings of the command a shell may read: line continuations
    /// joined with a space, and with nothing if that differs.
    pub fn commands(&self) -> impl Iterator<Item = &str> {
        std::iter::once(self.command.as_str())
            .chain(Some(self.command_joined.as_str()).filter(|j| !j.is_empty()))
    }

    /// The path as written and as resolved, for deny and ask checks.
    fn paths(&self) -> impl Iterator<Item = &str> {
        Some(self.path.as_str())
            .filter(|p| !p.is_empty())
            .into_iter()
            .chain(self.real_path.as_deref())
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
        if kind == KIND_SHELL {
            // Every spelling counts: we can't know which one the harness reads.
            c.raw_commands = field_values(&c.fields, "command");
            if c.raw_commands.is_empty() && input.tool == "execute_code" {
                c.raw_commands = field_values(&c.fields, "code");
            }
            let all = c.raw_commands.join("\n");
            c.command = join_continuations(&all, " ");
            let joined = join_continuations(&all, "");
            if joined != c.command {
                c.command_joined = joined;
            }
        }
        c.url = field_values(&c.fields, "url")
            .into_iter()
            .next()
            .unwrap_or_default();
        let mut raw_path = PATH_KEYS
            .iter()
            .find_map(|k| field_values(&c.fields, k).into_iter().next())
            .unwrap_or_default();
        if raw_path.is_empty() && kind == KIND_READ {
            raw_path = input.cwd.clone(); // Glob, Grep and LS default to the working directory
        }
        let project = (!input.project_dir.is_empty())
            .then(|| env.normalize(&input.project_dir, &input.cwd))
            .map(|p| {
                let real = env.real(&p);
                (p, real)
            });
        if let Some((p, real)) = &project {
            c.project_ignored = env.is_broad_dir(p, real.as_deref());
        }
        if !raw_path.is_empty() {
            c.path = env.clean_names(&env.normalize(&raw_path, &input.cwd));
            c.real_path = env.real(&c.path);
            if let Some((dir, real_dir)) = project.as_ref().filter(|_| !c.project_ignored) {
                c.in_project = env.in_dir(&c.path, dir);
                c.real_in_project = match (&c.real_path, real_dir) {
                    (Some(p), Some(d)) => env.in_dir(p, d),
                    _ => false,
                };
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
        // A raw Windows disk, however the command writes it: \\.\PhysicalDrive0,
        // \\?\PhysicalDrive0, \\.\Harddisk0, \\.\HarddiskVolume1 (backslashes
        // doubled for a shell too, or slashes).
        builtin_regex(r"(?i)(?:\\+|/+)[.?](?:\\+|/+)(?:physicaldrive|harddisk(?:volume)?)\d"),
        // A raw volume, \\.\C: or \\?\C:, only when the colon ends the path:
        // \\?\C:\Users\x is an ordinary long path.
        builtin_regex(r#"(?i)(?:\\+|/+)[.?](?:\\+|/+)[a-z]:(?:$|[\s'"`;&|)<>])"#),
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
        "flock" => &[
            "-w",
            "-E",
            "--timeout",
            "--wait",
            "--conflict-exit-code",
            "#1",
        ],
        "wsl" => &["-d", "--distribution", "-u", "--user", "--cd"],
        "command" | "nohup" | "setsid" | "busybox" | "sh" | "bash" | "zsh" | "dash" | "fish"
        | "csh" | "tcsh" | "eval" | "{" | "!" | "if" | "then" | "else" | "do" => &[],
        _ => return None,
    })
}

/// Programs that run the text after a command flag: `su -c`, `cmd /c`,
/// `powershell -Command` (any prefix of it, `-c` too). Returns whether a
/// lower-case token is that flag.
fn command_flag(name: &str) -> Option<fn(&str) -> bool> {
    Some(match name {
        "su" => |t| t == "-c" || t == "--command",
        "cmd" => |t| matches!(t, "/c" | "/k" | "/r"),
        "powershell" | "pwsh" => |t| t.len() > 1 && "-command".starts_with(t),
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
            let name = command_name(toks[i]);
            if let Some(is_flag) = command_flag(&name) {
                // The command is the text after the flag; without one, nothing
                // runs that we can read.
                let at = toks[i + 1..]
                    .iter()
                    .position(|t| is_flag(&t.to_lowercase()));
                i = at.map_or(toks.len(), |k| i + k + 2);
                continue;
            }
            if let Some(valued) = wrapper(&name) {
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

/// Whether `command` runs `callguard trust` (anything but `--list`). Read from
/// the raw text, as the other built-ins are: quotes and a path or `.exe` on the
/// program do not hide it. It misses a script written earlier, a program name
/// the shell expands, a renamed copy of the binary and a wrapper that builds
/// the command at run time; the terminal requirement of the verb is the second
/// lock.
pub fn runs_trust_verb(command: &str) -> bool {
    // The text as written, and with quotes and backslashes removed, where
    // `tr""ust` is `trust`.
    [command.to_owned(), unquoted(command)].iter().any(|text| {
        text.split([';', '&', '|', '\n', '(', ')', '`']).any(|seg| {
            let words: Vec<String> = seg
                .replace(['\'', '"'], " ")
                .split_whitespace()
                .map(str::to_owned)
                .collect();
            words.iter().enumerate().any(|(i, w)| {
                command_name(w) == "callguard"
                    && words.get(i + 1).is_some_and(|n| n == "trust")
                    && !words[i + 2..].iter().any(|a| a == "--list" || a == "-list")
            })
        })
    })
}

/// `s` without quotes and backslashes: how a shell reads a word split by empty
/// quotes (`.cla""ude`) or escapes (`.cl\aude`). Shell guards read both this
/// and the raw text. Globs and variables stay a known limit.
fn unquoted(s: &str) -> String {
    s.replace(['"', '\'', '\\'], "")
}

/// Tool writes to the trust record are denied; shell commands that name it or
/// run the trust verb ask. Always on.
fn trust_guard(c: &Call) -> Option<Hit> {
    let file = crate::trust::FILE;
    let named = |s: &str| {
        s.to_ascii_lowercase().contains(file) || unquoted(s).to_ascii_lowercase().contains(file)
    };
    let hit = |decision: &str, reason: &str| {
        Some(Hit {
            id: "self-protect-trust".into(),
            decision: decision.into(),
            reason: reason.into(),
        })
    };
    if c.kind == KIND_WRITE {
        if c.paths()
            .any(|p| p.to_ascii_lowercase().ends_with(&format!("/{file}")))
        {
            return hit(
                "deny",
                "callguard denies edits to its project trust record; the user runs `callguard trust`",
            );
        }
        if c.path.is_empty() && named(&c.whole) {
            return hit(
                "ask",
                "edit names the project trust record; a human should confirm",
            );
        }
    }
    if c.kind == KIND_SHELL && !c.command.is_empty() {
        if c.commands().any(named) {
            return hit(
                "ask",
                "command names the project trust record; a human should confirm",
            );
        }
        if c.commands().any(runs_trust_verb) {
            return hit(
                "ask",
                "command runs `callguard trust`, which grants project rules; a human should confirm",
            );
        }
    }
    None
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
            // Cleaned like the paths of a call, so a `..` in the setting still matches.
            let p = env.normalize(p, "");
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
        [text.to_owned(), unquoted(text)].iter().any(|text| {
            let text = self.env.slash(text);
            if PROTECTED_SHELL.is_match(&text) {
                return true;
            }
            let folded = self.env.fold(&text);
            self.extra.iter().any(|p| folded.contains(p.as_str()))
        })
    }

    /// The first built-in rule that fires for `c`. Hard denies are checked
    /// before the self-protection ask.
    pub fn check(&self, c: &Call) -> Option<Hit> {
        // The trust record guard has no id: `disable_builtin` cannot name it.
        if let Some(hit) = trust_guard(c) {
            return Some(hit);
        }
        let on = |id: &str| !self.disabled.iter().any(|d| d == id);
        let hit = |id: &str, decision: &str, reason: String| {
            Some(Hit {
                id: id.into(),
                decision: decision.into(),
                reason,
            })
        };
        if c.kind == KIND_WRITE && on("self-protect-write") {
            if c.paths()
                .any(|p| self.protected.iter().any(|re| re.is_match(p)))
            {
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
            if on("rm-root") && c.commands().any(rm_root) {
                return hit(
                    "rm-root",
                    "deny",
                    "recursive deletion of a root, home or .git directory".into(),
                );
            }
            if on("disk-wipe")
                && c.commands()
                    .any(|cmd| DISK_WIPE.iter().any(|re| re.is_match(cmd)))
            {
                return hit(
                    "disk-wipe",
                    "deny",
                    "command formats or overwrites a disk".into(),
                );
            }
            if on("fork-bomb") && c.commands().any(|cmd| FORK_BOMB.is_match(cmd)) {
                return hit("fork-bomb", "deny", "fork bomb".into());
            }
            if on("self-protect-shell") && c.commands().any(|cmd| self.names_protected(cmd)) {
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
        // A regex rule reads every spelling of the command (see
        // `Call::command_joined`): deny and ask fire on any, allow needs all.
        let allow = self.rule.decision == "allow";
        if let Some(re) = &self.command {
            let hit = |c: &str| !c.is_empty() && re.is_match(c);
            if call.command.is_empty()
                || if allow {
                    !call.commands().all(hit)
                } else {
                    !call.commands().any(hit)
                }
            {
                return false;
            }
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
        if call.path.is_empty() {
            return m.in_project.is_none() && self.path.is_empty();
        }
        if m.in_project.is_none() && self.path.is_empty() && self.not_path.is_empty() {
            return true;
        }
        // The path conditions hold for the path as written, and for where it
        // really is. Deny and ask need one of them (a link into a protected
        // place fires), allow needs both, and a path that does not resolve
        // cannot be allowed.
        let lexical = self.path_ok(&call.path, call.in_project);
        let real = call
            .real_path
            .as_deref()
            .is_some_and(|p| self.path_ok(p, call.real_in_project));
        if allow {
            lexical && real
        } else {
            lexical || real
        }
    }

    /// The path conditions for one form of a non-empty path.
    fn path_ok(&self, path: &str, in_project: bool) -> bool {
        self.rule
            .r#match
            .in_project
            .is_none_or(|ip| ip == in_project)
            && (self.path.is_empty() || self.path.iter().any(|re| re.is_match(path)))
            && !self.not_path.iter().any(|re| re.is_match(path))
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
            quote_string(&r.decision)
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
        c.fields.insert(
            k.clone(),
            re(v, format!("match.field[{}]", quote_string(k)))?,
        );
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
                    .map_err(|e| RulesError(format!("rule {}: {e}", quote_string(&r.id))))?,
            );
        }
        Ok(Set { rules: set })
    }

    /// The matching rule that wins: deny over ask over allow, then list order.
    /// (Named `match_call` because `match` is a keyword.)
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
