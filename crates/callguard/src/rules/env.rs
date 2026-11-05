use super::*;

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

/// Replaces a lone UTF-16 surrogate escape in a JSON string with `\ufffd`.
/// `serde_json` accepts such an escape in a raw value but fails when it decodes
/// the string, and the call would then be matched on its escaped text (where
/// `\n` is not a line break) instead of its content.
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
    Some(plain_path(&out))
}

/// `p` as a string in slash form without the Windows `//?/` prefix (a share
/// `//?/UNC/h/s` is `//h/s`). A backslash separates only on Windows; in a Unix
/// file name it is a letter.
pub(crate) fn plain_path(p: &std::path::Path) -> String {
    let s = p.to_string_lossy();
    let s = if cfg!(windows) {
        s.replace('\\', "/")
    } else {
        s.into_owned()
    };
    if let Some(unc) = s.strip_prefix("//?/UNC/") {
        format!("//{unc}") // a network share
    } else {
        s.strip_prefix("//?/").unwrap_or(&s).to_owned()
    }
}

/// Windows names `//?/C:/x` and `//./C:/x` the file `C:/x`, `//?/UNC/h/s` the
/// share `//h/s`, and `//localhost/C$/x` the file `C:/x` again. Returns the
/// path in its plain form so anchored globs see what the file system sees;
/// other device names stay as they are.
fn plain_windows_path(p: String) -> String {
    let drive = |s: &str| {
        let b = s.as_bytes();
        b.len() >= 2 && b[0].is_ascii_alphabetic() && b[1] == b':'
    };
    let mut p = p;
    if let Some(rest) = ["//?/", "//./", "/??/"]
        .iter()
        .find_map(|x| p.strip_prefix(x))
    {
        if drive(rest) {
            return rest.to_owned();
        }
        match rest.get(..4) {
            Some(unc) if unc.eq_ignore_ascii_case("unc/") => p = format!("//{}", &rest[4..]),
            _ => return p,
        }
    }
    // The local machine's administrative share of a drive: `//localhost/C$/x`.
    let share = p.strip_prefix("//").and_then(|r| {
        let (host, tail) = r.split_once('/')?;
        let local = host.eq_ignore_ascii_case("localhost") || host == "127.0.0.1";
        let (letter, rest) = tail.split_once('/').unwrap_or((tail, ""));
        let b = letter.as_bytes();
        (local && b.len() == 2 && b[0].is_ascii_alphabetic() && b[1] == b'$')
            .then(|| format!("{}:/{rest}", b[0] as char))
    });
    share.unwrap_or(p)
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

    /// Whether `raw` is `C:rel`, a path relative to the current directory of
    /// drive C. Only the process knows that directory, so such a path is in no
    /// project and has no real location; deny and ask rules still match its
    /// text.
    pub(crate) fn drive_relative(&self, raw: &str) -> bool {
        let b = raw.as_bytes();
        self.windows
            && b.len() >= 2
            && b[0].is_ascii_alphabetic()
            && b[1] == b':'
            && !matches!(b.get(2), Some(b'/' | b'\\'))
    }

    /// An absolute, slash-normalized path for `p` relative to `cwd`: expands
    /// `~`, makes `p` absolute against `cwd` and cleans it. A relative `p` with
    /// no `cwd` stays relative.
    pub(crate) fn normalize(&self, p: &str, cwd: &str) -> String {
        let mut p = self.slash(p);
        if !self.home.is_empty() && (p == "~" || p.starts_with("~/")) {
            p = format!("{}{}", self.slash(&self.home), &p[1..]);
        }
        if self.windows {
            p = plain_windows_path(p);
        }
        if !self.is_abs(&p) && !cwd.is_empty() {
            p = format!("{}/{p}", self.slash(cwd));
        }
        let mut p = path_clean(&p);
        if self.windows && p.len() == 2 && p.as_bytes()[1] == b':' {
            p.push('/'); // `path_clean("C:/")` drops the slash
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
    pub(crate) fn in_dir(&self, p: &str, dir: &str) -> bool {
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
                    && (i == 0 || matches!(segs[i - 1], "?" | "."));
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
    pub(super) fn is_broad_dir(&self, dir: &str, real: Option<&str>) -> bool {
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

    /// Compiles a policy path glob (`glob::Dialect::Policy`): `*` and `?` stay inside one path segment, `**`
    /// crosses segments, `**/` also matches nothing and a trailing `/**` also
    /// matches the directory itself. A leading `~/` is expanded. The result
    /// matches normalized (slash, absolute) paths.
    pub(crate) fn compile_glob(&self, glob: &str) -> Result<Regex, RulesError> {
        let mut g = self.slash(glob);
        if !self.home.is_empty() && g.starts_with("~/") {
            g = format!("{}{}", self.slash(&self.home), &g[1..]);
        }
        crate::glob::compile(
            &g,
            crate::glob::Dialect::Policy {
                caseless: self.caseless(),
            },
        )
    }
}
