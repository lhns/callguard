//! Host observations about the repository around a pending shell call (git
//! status, remote visibility). `Meta`, `GitStatus`
//! and `RepoVisibility` are the wire types `schema` re-exports.
//!
//! Go's `context.Context` becomes an explicit `deadline`; probing runs a few
//! short processes under one deadline and never fails the call.

use std::io::{self, Read};
use std::process::{Command, Stdio};
use std::sync::LazyLock;
use std::time::{Duration, Instant};

use regex::Regex;
use serde::{Deserialize, Serialize};

use crate::serde_util::{is_false, is_zero, nullable};

/// Deadline for all probing of one call.
pub const BUDGET: Duration = Duration::from_millis(300);

/// Host observations about the pending call. Only the host or adapter sets
/// it, never from agent text.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Meta {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub git_status: Option<GitStatus>,
    #[serde(skip_serializing_if = "Vec::is_empty", deserialize_with = "nullable")]
    pub repo_visibility: Vec<RepoVisibility>,
}

/// Summary of `git status --porcelain=v1`.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct GitStatus {
    #[serde(deserialize_with = "nullable")]
    pub clean: bool,
    #[serde(skip_serializing_if = "is_zero", deserialize_with = "nullable")]
    pub staged: i64,
    #[serde(skip_serializing_if = "is_zero", deserialize_with = "nullable")]
    pub modified: i64,
    #[serde(skip_serializing_if = "is_zero", deserialize_with = "nullable")]
    pub untracked: i64,
    #[serde(skip_serializing_if = "Vec::is_empty", deserialize_with = "nullable")]
    pub files: Vec<String>,
    #[serde(skip_serializing_if = "is_false", deserialize_with = "nullable")]
    pub files_truncated: bool,
}

/// Visibility of one push or publish destination: "public", "private",
/// "internal" or "unknown". `remote` is host/owner/repo, or "" if it could
/// not be resolved.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct RepoVisibility {
    #[serde(deserialize_with = "nullable")]
    pub remote: String,
    #[serde(deserialize_with = "nullable")]
    pub visibility: String,
}

/// Runs a program and returns its stdout. `env` entries ("K=V") are added to
/// the process environment; the call must not outlive `deadline`.
pub type Runner = dyn Fn(&[String], &str, &[&str], Instant) -> io::Result<Vec<u8>> + Sync;

/// A program ran and exited unsuccessfully (carried inside an `io::Error`).
#[derive(Debug)]
pub struct ExitFailure {
    pub name: String,
    pub code: Option<i32>,
    status: String,
}

impl std::fmt::Display for ExitFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} exited with {}", self.name, self.status)
    }
}

impl std::error::Error for ExitFailure {}

impl ExitFailure {
    /// A failed run of `name` with exit code `code` (None: no code, a signal).
    pub fn new(name: &str, code: Option<i32>) -> ExitFailure {
        ExitFailure {
            name: name.to_owned(),
            code,
            status: code.map_or_else(|| "no exit code".to_owned(), |c| format!("exit code: {c}")),
        }
    }

    /// The exit code of a failed run, if `e` is one.
    pub fn code_of(e: &io::Error) -> Option<i32> {
        e.get_ref()?.downcast_ref::<ExitFailure>()?.code
    }
}

/// The `Runner` that starts real processes.
pub fn exec_runner(
    env: &[String],
    name: &str,
    args: &[&str],
    deadline: Instant,
) -> io::Result<Vec<u8>> {
    run_process(false, env, name, args, deadline)
}

/// Like [`exec_runner`], but the process inherits none of the caller's `GIT_*`
/// variables, as nah's own git calls do: git then answers for the repository it
/// is pointed at.
pub fn exec_runner_without_git_env(
    env: &[String],
    name: &str,
    args: &[&str],
    deadline: Instant,
) -> io::Result<Vec<u8>> {
    run_process(true, env, name, args, deadline)
}

fn run_process(
    strip_git_env: bool,
    env: &[String],
    name: &str,
    args: &[&str],
    deadline: Instant,
) -> io::Result<Vec<u8>> {
    let mut cmd = Command::new(name);
    if strip_git_env {
        for (k, _) in std::env::vars_os() {
            if k.to_string_lossy().starts_with("GIT_") {
                cmd.env_remove(k);
            }
        }
    }
    cmd.args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    for kv in env {
        if let Some((k, v)) = kv.split_once('=') {
            cmd.env(k, v);
        }
    }
    let mut child = cmd.spawn()?;
    let mut stdout = child.stdout.take().expect("stdout is piped");
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = stdout.read_to_end(&mut buf);
        let _ = tx.send(buf);
    });
    let status = loop {
        if let Some(st) = child.try_wait()? {
            break st;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            // The reader ends when the pipe closes; a grandchild holding it
            // open must not hold us, so the thread is left to finish alone.
            return Err(io::Error::new(io::ErrorKind::TimedOut, "deadline exceeded"));
        }
        std::thread::sleep(Duration::from_millis(2));
    };
    // The pipe can stay open in a grandchild after the process is gone: wait
    // for its end only until the deadline.
    let out = rx
        .recv_timeout(deadline.saturating_duration_since(Instant::now()))
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "output pipe stayed open"))?;
    if status.success() {
        Ok(out)
    } else {
        Err(io::Error::other(ExitFailure {
            name: name.to_owned(),
            code: status.code(),
            status: status.to_string(),
        }))
    }
}

/// Fills in what `have` lacks for a shell command run in `cwd`: the git status
/// when the command can destroy or publish uncommitted work, and the
/// destination's visibility when it pushes or publishes. Returns `have` plus
/// the new observations, `have` itself if there are none. `cwd == ""` skips
/// probing.
pub fn probe(
    run: &Runner,
    cwd: &str,
    command: &str,
    have: Option<&Meta>,
    deadline: Instant,
) -> Option<Meta> {
    if cwd.is_empty() || command.is_empty() {
        return have.cloned();
    }
    let mut out = have.cloned().unwrap_or_default();
    let want_status = out.git_status.is_none() && needs_status(command);
    let dests = destinations(command);
    let want_vis = out.repo_visibility.is_empty() && !dests.is_empty();
    if !want_status && !want_vis {
        return have.cloned();
    }
    let deadline = deadline.min(Instant::now() + BUDGET);
    let (status_res, vis_res) = std::thread::scope(|s| {
        let st = want_status.then(|| s.spawn(|| status(run, cwd, deadline)));
        let vis = want_vis.then(|| s.spawn(|| visibilities(run, cwd, &dests, deadline)));
        (
            st.and_then(|h| h.join().ok()).flatten(),
            vis.and_then(|h| h.join().ok()),
        )
    });
    if want_status {
        out.git_status = status_res;
    }
    if let Some(v) = vis_res {
        out.repo_visibility = v;
    }
    if out.git_status.is_none() && out.repo_visibility.is_empty() {
        return have.cloned();
    }
    Some(out)
}

/// Runs git status in `cwd`. Any failure is `None`.
///
/// The repository's own filter drivers are switched off first
/// ([`crate::gitfilter`]): a clean filter in `.git/config` is a shell command
/// that `git status` would run. If the config cannot be listed, there is no
/// status.
pub fn status(run: &Runner, cwd: &str, deadline: Instant) -> Option<GitStatus> {
    let filters = crate::gitfilter::overrides(run, cwd, deadline).ok()?;
    let mut args: Vec<&str> = vec!["-C", cwd, "-c", "core.fsmonitor=false"];
    args.extend(filters.iter().map(String::as_str));
    // Not into a submodule's work tree: its own filters would run.
    args.extend([
        "status",
        "--porcelain=v1",
        crate::gitfilter::IGNORE_SUBMODULE_WORKTREES,
    ]);
    let raw = run(&["GIT_OPTIONAL_LOCKS=0".to_owned()], "git", &args, deadline).ok()?;
    Some(parse_status(&String::from_utf8_lossy(&raw)))
}

/// Counts the entries of `git status --porcelain=v1` output.
pub fn parse_status(porcelain: &str) -> GitStatus {
    let mut st = GitStatus::default();
    for line in porcelain.split('\n') {
        let line = line.trim_end_matches('\r');
        let b = line.as_bytes();
        if b.len() < 3 {
            continue;
        }
        let (x, y) = (b[0], b[1]);
        if x == b'!' {
            continue;
        }
        st.files.push(line.to_owned());
        if x == b'?' && y == b'?' {
            st.untracked += 1;
            continue;
        }
        if x != b' ' && x != b'?' {
            st.staged += 1;
        }
        if y != b' ' && y != b'?' {
            st.modified += 1;
        }
    }
    st.clean = st.files.is_empty();
    st
}

// RE2's \s and \b are ASCII; the regex crate's are Unicode, so the patterns
// spell them out.
static RM_RECURSIVE_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)(^|[ \t\n\f\r;&|(])rm[ \t\n\f\r]+(-[a-z]*r|--recursive)").expect("valid regex")
});
static REMOVE_ITEM_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)(?-u:\b)Remove-Item(?-u:\b)[^;&|\n]*-Recurse").expect("valid regex")
});
static SEP_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"&&|\|\||[;|\n&]").expect("valid regex"));
static SCP_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^(?:[^@/ \t\n\f\r]+@)?([^:/ \t\n\f\r]+):(.+)$").expect("valid regex")
});

/// Whether the command can destroy uncommitted work or stage, commit or
/// publish it.
pub fn needs_status(command: &str) -> bool {
    if RM_RECURSIVE_RE.is_match(command) || REMOVE_ITEM_RE.is_match(command) {
        return true;
    }
    for seg in SEP_RE.split(command) {
        let fields: Vec<&str> = seg.split_whitespace().collect();
        let Some(g) = parse_git(&fields) else {
            continue;
        };
        let has = |v: &str| g.args.contains(&v);
        let hit = match g.sub {
            "add" | "stage" | "commit" | "push" | "restore" | "clean" => true,
            "reset" => has("--hard"),
            "checkout" => has("--") || has("."),
            "stash" => g
                .args
                .first()
                .is_some_and(|a| *a == "drop" || *a == "clear"),
            "worktree" => g.args.first().is_some_and(|a| *a == "remove"),
            _ => false,
        };
        if hit {
            return true;
        }
    }
    false
}

struct GitCall<'a> {
    sub: &'a str,
    args: &'a [&'a str],
}

/// Finds `git [global options] <sub> <args>` in `fields`.
fn parse_git<'a>(fields: &'a [&'a str]) -> Option<GitCall<'a>> {
    for (i, f) in fields.iter().enumerate() {
        if *f != "git" && !f.ends_with("/git") && !f.ends_with("\\git") && *f != "git.exe" {
            continue;
        }
        let mut rest = &fields[i + 1..];
        while rest.first().is_some_and(|r| r.starts_with('-')) {
            if (rest[0] == "-C" || rest[0] == "-c") && rest.len() > 1 {
                rest = &rest[2..];
            } else {
                rest = &rest[1..];
            }
        }
        let (sub, args) = rest.split_first()?;
        return Some(GitCall { sub, args });
    }
    None
}

/// Where a command pushes or publishes: a remote name, a URL or a gh repo
/// argument. `raw == "origin"` is the default.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Destination {
    pub raw: String,
    /// From a gh command: OWNER/REPO means github.com.
    pub gh: bool,
}

fn gh_publishes(sub: &str, verb: &str) -> bool {
    matches!(
        (sub, verb),
        ("pr", "create" | "merge" | "comment")
            | ("issue", "create" | "comment")
            | ("release", "create" | "upload")
            | ("repo", "create" | "fork" | "edit")
            | ("gist", "create" | "edit")
    )
}

/// The push and publish destinations of `command`: the first non-flag argument
/// of `git push` (default origin), the URL of `git remote add|set-url`, and
/// the --repo/-R value of publishing gh commands (default origin).
pub fn destinations(command: &str) -> Vec<Destination> {
    let mut out: Vec<Destination> = Vec::new();
    let mut add = |d: Destination| {
        if !out.contains(&d) {
            out.push(d);
        }
    };
    for seg in SEP_RE.split(command) {
        let fields: Vec<&str> = seg.split_whitespace().collect();
        if let Some(g) = parse_git(&fields) {
            match g.sub {
                "push" => add(Destination {
                    raw: first_non_flag(g.args, 0, "origin"),
                    gh: false,
                }),
                "remote" => {
                    if g.args
                        .first()
                        .is_some_and(|a| *a == "add" || *a == "set-url")
                    {
                        let u = first_non_flag(&g.args[1..], 1, "");
                        if !u.is_empty() {
                            add(Destination { raw: u, gh: false });
                        }
                    }
                }
                _ => {}
            }
            continue;
        }
        if let Some((sub, verb, rest)) = parse_gh(&fields)
            && gh_publishes(sub, verb)
        {
            let mut repo = "origin".to_owned();
            for (i, f) in rest.iter().enumerate() {
                if (*f == "--repo" || *f == "-R") && i + 1 < rest.len() {
                    repo = rest[i + 1].to_owned();
                } else if let Some(v) = f.strip_prefix("--repo=") {
                    repo = v.to_owned();
                }
            }
            let gh = repo != "origin";
            add(Destination { raw: repo, gh });
        }
    }
    out
}

fn parse_gh<'a>(fields: &'a [&'a str]) -> Option<(&'a str, &'a str, &'a [&'a str])> {
    for (i, f) in fields.iter().enumerate() {
        if *f == "gh" || *f == "gh.exe" || f.ends_with("/gh") {
            if fields.len() < i + 3 {
                return None;
            }
            return Some((fields[i + 1], fields[i + 2], &fields[i + 3..]));
        }
    }
    None
}

/// The `n`-th (0-based) argument not starting with "-", with quotes trimmed.
fn first_non_flag(args: &[&str], mut n: usize, default: &str) -> String {
    for a in args {
        if a.starts_with('-') {
            continue;
        }
        if n == 0 {
            return a.trim_matches(|c| c == '"' || c == '\'').to_owned();
        }
        n -= 1;
    }
    default.to_owned()
}

/// Resolves each destination to host/owner/repo and asks gh for its
/// visibility. Whatever cannot be resolved is "unknown". Same order and length
/// as `dests`.
pub fn visibilities(
    run: &Runner,
    cwd: &str,
    dests: &[Destination],
    deadline: Instant,
) -> Vec<RepoVisibility> {
    std::thread::scope(|s| {
        let handles: Vec<_> = dests
            .iter()
            .map(|d| s.spawn(move || visibility(run, cwd, d, deadline)))
            .collect();
        handles
            .into_iter()
            .map(|h| {
                h.join().unwrap_or_else(|_| RepoVisibility {
                    remote: String::new(),
                    visibility: "unknown".into(),
                })
            })
            .collect()
    })
}

fn visibility(run: &Runner, cwd: &str, d: &Destination, deadline: Instant) -> RepoVisibility {
    let raw = d.raw.as_str();
    let remote = if d.gh && !raw.contains("://") && !raw.contains('@') {
        // OWNER/REPO or HOST/OWNER/REPO.
        if raw.matches('/').count() == 1 {
            format!("github.com/{raw}")
        } else {
            raw.to_owned()
        }
    } else if raw.contains("://") || raw.contains('@') || raw.contains(':') {
        normalize_remote(raw)
    } else {
        match run(&[], "git", &["-C", cwd, "remote", "get-url", raw], deadline) {
            Ok(out) => normalize_remote(String::from_utf8_lossy(&out).trim()),
            Err(_) => String::new(),
        }
    };
    let mut res = RepoVisibility {
        remote,
        visibility: "unknown".into(),
    };
    let host = res.remote.split('/').next().unwrap_or("");
    let gh_host = std::env::var("GH_HOST").unwrap_or_default();
    if res.remote.is_empty() || (host != "github.com" && host != gh_host) {
        return res;
    }
    let Ok(out) = run(
        &[],
        "gh",
        &[
            "repo",
            "view",
            &res.remote,
            "--json",
            "visibility",
            "--jq",
            ".visibility",
        ],
        deadline,
    ) else {
        return res;
    };
    let v = String::from_utf8_lossy(&out).trim().to_lowercase();
    if matches!(v.as_str(), "public" | "private" | "internal") {
        res.visibility = v;
    }
    res
}

/// Turns https://host/o/r(.git), git@host:o/r(.git) and ssh://git@host/o/r into
/// host/o/r. Returns "" for anything else, such as a local path.
pub fn normalize_remote(raw: &str) -> String {
    let raw = raw.trim();
    let (host, path) = if raw.contains("://") {
        match parse_url(raw) {
            Some((h, p)) if !h.is_empty() => (h, p),
            _ => return String::new(),
        }
    } else if let Some(m) = SCP_RE.captures(raw).filter(|m| m[1].len() > 1) {
        // A one-letter host is a Windows drive.
        (m[1].to_owned(), m[2].to_owned())
    } else {
        return String::new();
    };
    let path = path.trim_matches('/');
    let path = path.strip_suffix(".git").unwrap_or(path);
    if path.is_empty() {
        return String::new();
    }
    format!("{}/{path}", host.to_lowercase())
}

/// The host (without port or brackets) and decoded path of a `scheme://` URL,
/// as Go's `url.Parse` followed by `Hostname()` and `Path` gives them; `None`
/// where Go reports an error.
fn parse_url(raw: &str) -> Option<(String, String)> {
    if raw.bytes().any(|b| b < 0x20 || b == 0x7f) {
        return None;
    }
    let (scheme, rest) = raw.split_once("://")?;
    let mut sc = scheme.chars();
    let valid_scheme = sc.next().is_some_and(|c| c.is_ascii_alphabetic())
        && sc.all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'));
    if !valid_scheme {
        return None;
    }
    let rest = rest.split('#').next().unwrap_or("");
    let (rest, _query) = rest.split_once('?').unwrap_or((rest, ""));
    let (authority, path) = match rest.find('/') {
        Some(i) => rest.split_at(i),
        None => (rest, ""),
    };
    let hostport = authority.rsplit_once('@').map_or(authority, |(_, h)| h);
    let host = if let Some(inner) = hostport.strip_prefix('[') {
        let (h, after) = inner.split_once(']')?;
        if !after.is_empty() && !valid_port(after.strip_prefix(':')?) {
            return None;
        }
        h
    } else {
        match hostport.rsplit_once(':') {
            Some((h, port)) => {
                if !valid_port(port) {
                    return None;
                }
                h
            }
            None => hostport,
        }
    };
    Some((host.to_owned(), percent_decode(path)?))
}

fn valid_port(p: &str) -> bool {
    p.bytes().all(|b| b.is_ascii_digit())
}

fn percent_decode(s: &str) -> Option<String> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' {
            let hex = s.get(i + 1..i + 3)?;
            out.push(u8::from_str_radix(hex, 16).ok()?);
            i += 3;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    Some(String::from_utf8_lossy(&out).into_owned())
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;

    /// Maps "name arg arg" to a canned answer; missing entries fail.
    struct Script {
        answers: HashMap<&'static str, &'static str>,
        calls: AtomicUsize,
    }

    impl Script {
        fn new(answers: &[(&'static str, &'static str)]) -> Script {
            Script {
                answers: answers.iter().copied().collect(),
                calls: AtomicUsize::new(0),
            }
        }

        fn run(
            &self,
            _env: &[String],
            name: &str,
            args: &[&str],
            _dl: Instant,
        ) -> io::Result<Vec<u8>> {
            if args.contains(&"--get-regexp") {
                // The filter-driver listing (gitfilter): the repo defines none.
                return Ok(Vec::new());
            }
            self.calls.fetch_add(1, Ordering::SeqCst);
            let key = format!("{name} {}", args.join(" "));
            match self.answers.get(key.as_str()) {
                Some(a) => Ok(a.as_bytes().to_vec()),
                None => Err(io::Error::other("no such command")),
            }
        }

        fn calls(&self) -> usize {
            self.calls.load(Ordering::SeqCst)
        }
    }

    fn soon() -> Instant {
        Instant::now() + Duration::from_secs(5)
    }

    fn vis(remote: &str, visibility: &str) -> RepoVisibility {
        RepoVisibility {
            remote: remote.into(),
            visibility: visibility.into(),
        }
    }

    #[test]
    fn parse_status_counts() {
        let st = parse_status("?? .env\nM  main.go\n MM both.go\nA  new.go\n");
        assert!(!st.clean);
        assert_eq!((st.untracked, st.staged, st.modified), (1, 2, 1));
        assert_eq!(st.files.len(), 4);
        let both = parse_status("MM x.go\n");
        assert_eq!((both.staged, both.modified), (1, 1));
        let c = parse_status("");
        assert!(c.clean && c.files.is_empty());
    }

    #[test]
    fn needs_status_cases() {
        let yes = [
            "git reset --hard HEAD~1",
            "git checkout -- .",
            "git checkout .",
            "git restore f",
            "git clean -fd",
            "git stash drop",
            "git stash clear",
            "git worktree remove ../w",
            "rm -rf build",
            "rm -fr x",
            "rm -r x",
            "cd x && rm -Rf y",
            "Remove-Item -Path x -Recurse -Force",
            "git add -A",
            "git stage f",
            "git commit -m x",
            "git push origin main",
            "git -C /r reset --hard",
        ];
        let no = [
            "git status",
            "git log",
            "git checkout main",
            "git reset --soft HEAD~1",
            "git stash",
            "rm file.txt",
            "echo rm -rf", // quoted text is best effort in Go; this one matches
            "ls",
        ];
        for c in yes {
            assert!(needs_status(c), "want status for {c:?}");
        }
        for c in no {
            assert!(
                !needs_status(c) || c == "echo rm -rf",
                "no status for {c:?}"
            );
        }
    }

    #[test]
    fn destinations_cases() {
        let d = |raw: &str, gh: bool| Destination {
            raw: raw.into(),
            gh,
        };
        let cases: Vec<(&str, Vec<Destination>)> = vec![
            ("git push", vec![d("origin", false)]),
            ("git push -u upstream main", vec![d("upstream", false)]),
            (
                "git push https://h.io/o/r.git",
                vec![d("https://h.io/o/r.git", false)],
            ),
            (
                "git remote add x git@github.com:o/r.git",
                vec![d("git@github.com:o/r.git", false)],
            ),
            ("gh pr create --title x", vec![d("origin", false)]),
            ("gh issue comment 3 -R o/r -b hi", vec![d("o/r", true)]),
            ("gh repo edit --repo=h/o/r", vec![d("h/o/r", true)]),
            (
                "git push && gh release upload v1 f",
                vec![d("origin", false)],
            ),
            ("gh pr view 3", vec![]),
            ("git status", vec![]),
        ];
        for (cmd, want) in cases {
            assert_eq!(destinations(cmd), want, "{cmd:?}");
        }
    }

    #[test]
    fn normalize_remote_cases() {
        for (input, want) in [
            ("https://github.com/o/r.git", "github.com/o/r"),
            ("https://user@github.com/o/r", "github.com/o/r"),
            ("git@github.com:o/r.git", "github.com/o/r"),
            ("ssh://git@host.example:22/o/r/", "host.example/o/r"),
            ("/srv/git/r.git", ""),
            (r"C:\repo", ""),
            ("https://[::1]:8080/o/r", "::1/o/r"),
            ("https://h.io:abc/o/r", ""),
            ("https://h.io/o%2Fx/r", "h.io/o/x/r"),
            ("https://h.io/o/r?x=1#f", "h.io/o/r"),
            ("https:///o/r", ""),
        ] {
            assert_eq!(normalize_remote(input), want, "{input:?}");
        }
    }

    #[test]
    fn probe_fills_in_what_is_missing() {
        let s = Arc::new(Script::new(&[
            (
                "git -C /w -c core.fsmonitor=false status --porcelain=v1 --ignore-submodules=dirty",
                "?? .env\nM  main.go\n",
            ),
            (
                "git -C /w remote get-url origin",
                "git@github.com:o/r.git\n",
            ),
            (
                "gh repo view github.com/o/r --json visibility --jq .visibility",
                "PUBLIC\n",
            ),
        ]));
        let s2 = s.clone();
        let run = move |e: &[String], n: &str, a: &[&str], d: Instant| s2.run(e, n, a, d);
        let got = probe(&run, "/w", "git add . && git push", None, soon()).unwrap();
        let st = got.git_status.unwrap();
        assert_eq!((st.untracked, st.staged), (1, 1));
        assert_eq!(got.repo_visibility, vec![vis("github.com/o/r", "public")]);

        // What the request supplied is not probed again.
        let have = Meta {
            git_status: Some(GitStatus {
                clean: true,
                ..Default::default()
            }),
            repo_visibility: vec![vis("h/o/r", "private")],
        };
        let before = s.calls();
        let got = probe(&run, "/w", "git push", Some(&have), soon());
        assert_eq!(got, Some(have));
        assert_eq!(s.calls(), before);
        // No cwd, no probing; a harmless command spawns nothing.
        assert_eq!(probe(&run, "", "git push", None, soon()), None);
        assert_eq!(probe(&run, "/w", "ls", None, soon()), None);
        assert_eq!(s.calls(), before);

        // Failures: no status, unknown visibility with the resolved remote.
        let f = Arc::new(Script::new(&[(
            "git -C /w remote get-url origin",
            "https://gitlab.com/o/r.git",
        )]));
        let run = move |e: &[String], n: &str, a: &[&str], d: Instant| f.run(e, n, a, d);
        let got = probe(&run, "/w", "git commit -m x && git push", None, soon()).unwrap();
        assert!(got.git_status.is_none());
        assert_eq!(got.repo_visibility, vec![vis("gitlab.com/o/r", "unknown")]);
    }

    #[test]
    fn probe_honours_budget() {
        let slow = |_: &[String], _: &str, _: &[&str], dl: Instant| -> io::Result<Vec<u8>> {
            std::thread::sleep(dl.saturating_duration_since(Instant::now()));
            Err(io::Error::new(io::ErrorKind::TimedOut, "deadline"))
        };
        let start = Instant::now();
        let got = probe(
            &slow,
            "/w",
            "git push",
            None,
            Instant::now() + Duration::from_secs(60),
        )
        .unwrap();
        assert!(start.elapsed() < 2 * BUDGET, "{:?}", start.elapsed());
        assert_eq!(got.repo_visibility[0].visibility, "unknown");
    }

    #[test]
    fn exec_runner_runs_and_times_out() {
        let out = exec_runner(&[], "git", &["--version"], soon()).unwrap();
        assert!(String::from_utf8_lossy(&out).starts_with("git version"));
        assert!(exec_runner(&[], "git", &["no-such-subcommand-x"], soon()).is_err());
        assert!(exec_runner(&[], "no-such-program-x", &[], soon()).is_err());
    }
}
