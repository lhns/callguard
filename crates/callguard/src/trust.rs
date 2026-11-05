//! Project trust, like Claude's workspace trust: a project's `permissions.allow`
//! rules and `permissions.additionalDirectories` count only after the user has
//! seen them and said yes with `callguard trust`. The record is `<user config
//! dir>/callguard/trusted-projects.json`, a list of `{project, rules_sha256,
//! at}`; the hash covers the project directory, the allow list in file order
//! and the directories, so a changed rule, or the same file in another place,
//! is not trusted.

use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::policy::{self, UserConfig};

/// The record's file name; the self-protection rules know it.
pub const FILE: &str = "trusted-projects.json";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entry {
    pub project: String,
    pub rules_sha256: String,
    pub at: String,
}

/// What reading the record found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Record {
    /// No file: nothing is trusted, and that is not worth a warning.
    Missing,
    Entries(Vec<Entry>),
    /// The file exists and cannot be used: nothing is trusted.
    Unreadable(String),
}

/// How a project's allow rules stand.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    Trusted,
    /// Trusted before, but the rules changed since.
    Changed,
    Untrusted,
}

/// Where the record lives: next to the user policy. None when the user layer is
/// skipped or its directory is unknown.
pub fn record_path(user_config_dir: &UserConfig) -> Option<PathBuf> {
    let p = policy::user_path(user_config_dir)?;
    Path::new(&p).parent().map(|d| d.join(FILE))
}

/// The project directory in one spelling: absolute, symlinks resolved, `/`
/// separators, no `\\?\` prefix.
pub fn canonical(dir: &str) -> String {
    let real = std::fs::canonicalize(dir)
        .or_else(|_| std::path::absolute(dir))
        .unwrap_or_else(|_| PathBuf::from(dir));
    crate::rules::plain_path(&real)
}

fn same_project(a: &str, b: &str) -> bool {
    if cfg!(any(windows, target_os = "macos")) {
        a.eq_ignore_ascii_case(b)
    } else {
        a == b
    }
}

/// SHA-256 over the canonical project, the allow rules in file order and the
/// additional directories. Without directories the input is what it was before
/// they existed, so earlier trusts stay valid.
pub(crate) fn rules_hash(project: &str, allow: &[String], dirs: &[String]) -> String {
    let mut h = Sha256::new();
    h.update(b"callguard-trust-v1\n");
    // Length-prefixed, so no rule can borrow from its neighbour.
    let put = |h: &mut Sha256, part: &str| {
        h.update((part.len() as u64).to_le_bytes());
        h.update(part.as_bytes());
    };
    for p in std::iter::once(project).chain(allow.iter().map(String::as_str)) {
        put(&mut h, p);
    }
    if !dirs.is_empty() {
        h.update(b"additionalDirectories\n");
        for d in dirs {
            put(&mut h, d);
        }
    }
    hex::encode(h.finalize())
}

pub fn load(path: &Path) -> Record {
    let data = match std::fs::read(path) {
        Ok(d) => d,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Record::Missing,
        Err(e) => return Record::Unreadable(e.to_string()),
    };
    match serde_json::from_slice::<Vec<Entry>>(&data) {
        Ok(v) => Record::Entries(v),
        Err(e) => Record::Unreadable(e.to_string()),
    }
}

/// The state of `allow` and `dirs` for the canonical `project` in `entries`.
pub fn state(entries: &[Entry], project: &str, allow: &[String], dirs: &[String]) -> State {
    let want = rules_hash(project, allow, dirs);
    match entries.iter().find(|e| same_project(&e.project, project)) {
        Some(e) if e.rules_sha256 == want => State::Trusted,
        Some(_) => State::Changed,
        None => State::Untrusted,
    }
}

fn now() -> String {
    time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_default()
}

/// Writes `entries` atomically: a temporary file in the same directory, then a
/// rename over the record.
fn store(path: &Path, entries: &[Entry]) -> std::io::Result<()> {
    let dir = path.parent().unwrap_or(Path::new("."));
    std::fs::create_dir_all(dir)?;
    let tmp = dir.join(format!(".{FILE}.{}.tmp", std::process::id()));
    let body = serde_json::to_vec_pretty(entries).map_err(std::io::Error::other)?;
    let res = std::fs::write(&tmp, body).and_then(|()| std::fs::rename(&tmp, path));
    if res.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    res
}

/// Entries to keep when the record is rewritten: a malformed file is replaced.
fn existing(path: &Path) -> Vec<Entry> {
    match load(path) {
        Record::Entries(v) => v,
        _ => Vec::new(),
    }
}

/// Trusts `allow` and `dirs` for `project` (canonical), replacing an older entry.
pub fn write_entry(
    path: &Path,
    project: &str,
    allow: &[String],
    dirs: &[String],
) -> std::io::Result<()> {
    let mut entries = existing(path);
    entries.retain(|e| !same_project(&e.project, project));
    entries.push(Entry {
        project: project.to_owned(),
        rules_sha256: rules_hash(project, allow, dirs),
        at: now(),
    });
    store(path, &entries)
}

/// Removes the entry for `project`; whether there was one.
pub fn revoke(path: &Path, project: &str) -> std::io::Result<bool> {
    let mut entries = existing(path);
    let before = entries.len();
    entries.retain(|e| !same_project(&e.project, project));
    if entries.len() == before {
        return Ok(false);
    }
    store(path, &entries)?;
    Ok(true)
}

/// What a project asks to have trusted, as the warning names it.
fn subject(allow: &[String], dirs: &[String]) -> String {
    let mut parts = Vec::new();
    if !allow.is_empty() {
        let rules = if allow.len() == 1 { "rule" } else { "rules" };
        parts.push(format!("permissions.allow ({} {rules})", allow.len()));
    }
    if !dirs.is_empty() {
        let n = dirs.len();
        let dir = if n == 1 { "directory" } else { "directories" };
        parts.push(format!("permissions.additionalDirectories ({n} {dir})"));
    }
    format!("project {}", parts.join(" and "))
}

/// The decision a project's allow rules and additional directories get at
/// policy load: Err carries the warning when they are dropped.
pub fn check_for_load(
    user_config_dir: &UserConfig,
    project_dir: &str,
    allow: &[String],
    dirs: &[String],
) -> Result<(), String> {
    let project = canonical(project_dir);
    let what = subject(allow, dirs);
    let run = "run `callguard trust` in that project to review and trust them";
    let Some(path) = record_path(user_config_dir) else {
        return Err(format!("{what} ignored: the project is not trusted; {run}"));
    };
    let mut note = String::new();
    let entries = match load(&path) {
        Record::Entries(v) => v,
        Record::Missing => Vec::new(),
        Record::Unreadable(e) => {
            note = format!(" ({} is unreadable: {e})", path.display());
            Vec::new()
        }
    };
    match state(&entries, &project, allow, dirs) {
        State::Trusted => Ok(()),
        State::Changed => Err(format!(
            "{what} ignored: the rules changed since they were trusted; {run}"
        )),
        State::Untrusted => Err(format!(
            "{what} ignored: the project is not trusted; {run}{note}"
        )),
    }
}

/// Shows the rules and reads the answer: only `y` or `yes` trusts. The
/// terminal check is the caller's; this takes readers and writers so the logic
/// can be tested.
pub fn confirm(input: &mut dyn BufRead, out: &mut dyn Write) -> bool {
    let _ = write!(out, "Trust these rules? [y/N] ");
    let _ = out.flush();
    let mut line = String::new();
    if input.read_line(&mut line).is_err() {
        return false;
    }
    matches!(line.trim().to_ascii_lowercase().as_str(), "y" | "yes")
}

#[cfg(test)]
mod tests;
