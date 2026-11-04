//! nah's host observation, with one change: the git state of a repository
//! whose own config defines a filter driver is observed with those drivers
//! switched off, because the `git status` nah runs would otherwise run the
//! driver's command (a shell command in `.git/config`) before any verdict.
//!
//! The same goes for a submodule's own filters, which no top-level listing
//! shows: a repository with a gitlink is observed without entering submodule
//! work trees (`--ignore-submodules=dirty`).
//!
//! nah-observe's git calls cannot take extra options and strip `GIT_*`
//! from their environment, so for such a repository the `GitState` queries are
//! answered here by the same git commands plus the overrides, and everything
//! else by nah-observe. A repository without filter drivers, or in a scope
//! callguard does not list, goes straight to nah-observe. If the config cannot
//! be listed, the observation is refused: it comes back as an error, so
//! coverage is partial and no allow rule can match.

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::path::Path;
use std::time::{Duration, Instant};

use callguard::gitfilter;
use callguard::hostmeta::{ExitFailure, exec_runner_without_git_env as run};
use nah_proto::ctx::{AbsolutePath, Platform};
use nah_proto::observation::{
    GitStateObservation, GitUntrackedObservation, MAX_GIT_STATE_ENTRIES, Observation,
    ObservationFact, ObservationFailure, ObservationQuery, ObservationRequest, ObservationValue,
    Observed,
};

/// nah-observe's own limit per git call.
const GIT_TIMEOUT: Duration = Duration::from_millis(500);
const STATUS_MAX_BYTES: usize = 1024 * 1024;
const INDEX_MAX_BYTES: usize = 32 * 1024 * 1024;

/// Variables that point git at a repository other than the one found from the
/// directory it runs in.
const REDIRECTING_VARIABLES: [&str; 4] = [
    "GIT_DIR",
    "GIT_WORK_TREE",
    "GIT_INDEX_FILE",
    "GIT_COMMON_DIR",
];

pub(crate) fn host_platform() -> Platform {
    if cfg!(windows) {
        Platform::Windows
    } else if cfg!(target_os = "macos") {
        Platform::Macos
    } else {
        Platform::Linux
    }
}

/// Answers `request` for nah. `warnings` collects what the caller should tell
/// the user.
pub(crate) fn observe(
    request: &ObservationRequest,
    warnings: &RefCell<Vec<String>>,
) -> Result<Observation, String> {
    let git_queries: Vec<&ObservationQuery> = request
        .queries()
        .iter()
        .filter(|q| matches!(q, ObservationQuery::GitState { .. }))
        .collect();
    if git_queries.is_empty() {
        return nah_observe::fulfill_observation_request(request).map_err(|e| e.to_string());
    }
    // What each repository directory needs: nothing, our own observation (with
    // filter overrides, and without entering submodules) or a refusal.
    let mut plans: BTreeMap<String, Result<Plan, String>> = BTreeMap::new();
    for q in &git_queries {
        if let ObservationQuery::GitState { requested, .. } = q {
            plans
                .entry(requested.clone())
                .or_insert_with(|| plan(requested));
        }
    }
    if plans.values().all(|p| matches!(p, Ok(p) if p.is_plain())) {
        return nah_observe::fulfill_observation_request(request).map_err(|e| e.to_string());
    }

    // Everything but the git state goes to nah-observe.
    let rest: Vec<ObservationQuery> = request
        .queries()
        .iter()
        .filter(|q| !matches!(q, ObservationQuery::GitState { .. }))
        .cloned()
        .collect();
    let reduced = ObservationRequest::new(request.version(), request.request_id(), rest)
        .map_err(|e| e.to_string())?;
    let observed = nah_observe::fulfill_observation_request(&reduced).map_err(|e| e.to_string())?;
    let mut facts: Vec<ObservationFact> = observed.facts().to_vec();
    for q in git_queries {
        let ObservationQuery::GitState {
            requested,
            inspect_untracked,
            ..
        } = q
        else {
            continue;
        };
        let value = match &plans[requested] {
            Ok(p) => git_state(requested, *inspect_untracked, p),
            Err(why) => {
                let note = format!("nah: git state not observed, filter drivers unreadable: {why}");
                if !warnings.borrow().contains(&note) {
                    warnings.borrow_mut().push(note);
                }
                Observed::Error {
                    error: ObservationFailure::Unavailable,
                }
            }
        };
        facts.push(
            ObservationFact::new(q.clone(), ObservationValue::GitState { observed: value })
                .map_err(|e| e.to_string())?,
        );
    }
    Observation::new(request.version(), request.request_id(), facts).map_err(|e| e.to_string())
}

/// How to observe the git state of one repository.
struct Plan {
    /// `-c filter.<name>....=` pairs for the repository's own filter drivers.
    overrides: Vec<String>,
    /// The index holds a gitlink: do not enter submodule work trees.
    gitlinks: bool,
}

impl Plan {
    /// nah-observe can answer as it is.
    fn is_plain(&self) -> bool {
        self.overrides.is_empty() && !self.gitlinks
    }
}

fn plan(dir: &str) -> Result<Plan, String> {
    let deadline = Instant::now() + GIT_TIMEOUT;
    // Two git calls that do not depend on each other: run them together, as
    // git is slow to start on Windows.
    let (overrides, gitlinks) = std::thread::scope(|s| {
        let links = s.spawn(|| gitfilter::has_gitlinks(&run, dir, deadline));
        let overrides = gitfilter::overrides(&run, dir, deadline);
        (
            overrides,
            links
                .join()
                .unwrap_or_else(|_| Err("git thread panicked".into())),
        )
    });
    Ok(Plan {
        overrides: overrides?,
        gitlinks: gitlinks?,
    })
}

fn unavailable<T>() -> Observed<T> {
    Observed::Error {
        error: ObservationFailure::Unavailable,
    }
}

fn timeout_or_unavailable<T>(e: &std::io::Error) -> Observed<T> {
    Observed::Error {
        error: if e.kind() == std::io::ErrorKind::TimedOut {
            ObservationFailure::Timeout
        } else {
            ObservationFailure::Unavailable
        },
    }
}

fn absolute(path: &Path) -> Option<AbsolutePath> {
    let canon = std::fs::canonicalize(path).ok()?;
    let text = canon.to_str()?;
    let platform = host_platform();
    let text = if platform == Platform::Windows {
        nah_observe::normalize_windows_observed_path(text)
    } else {
        text.to_owned()
    };
    AbsolutePath::new(platform, text).ok()
}

/// nah-observe's `observe_git_state`, with `overrides` (`-c` pairs) before
/// `status`.
fn git_state(
    directory: &str,
    inspect_untracked: bool,
    plan: &Plan,
) -> Observed<GitStateObservation> {
    if REDIRECTING_VARIABLES
        .iter()
        .any(|name| std::env::var_os(name).is_some())
    {
        return unavailable();
    }
    let git = |args: &[&str], max: usize, dir: &str| -> std::io::Result<Vec<u8>> {
        let mut all = vec!["-C", dir];
        all.extend_from_slice(args);
        let out = run(&[], "git", &all, Instant::now() + GIT_TIMEOUT)?;
        if out.len() > max {
            return Err(std::io::Error::other("too much output"));
        }
        Ok(out)
    };
    let top_level = match git(
        &["rev-parse", "--show-toplevel"],
        STATUS_MAX_BYTES,
        directory,
    ) {
        Ok(out) => String::from_utf8(out)
            .ok()
            .map(|t| t.trim_end_matches(['\r', '\n']).to_owned())
            .filter(|t| !t.is_empty() && !t.contains(['\r', '\n']))
            .and_then(|t| absolute(Path::new(&t))),
        Err(e) if ExitFailure::code_of(&e).is_some() => None,
        Err(e) => return timeout_or_unavailable(&e),
    };
    let Some(top_level) = top_level else {
        return unavailable();
    };
    let mut args: Vec<&str> = vec!["--no-optional-locks", "-c", "core.fsmonitor=false"];
    args.extend(plan.overrides.iter().map(String::as_str));
    // nah looks into submodules (`none`); with a gitlink that would run the
    // submodule's own filters, so only the recorded commit is compared.
    let submodules = if plan.gitlinks {
        gitfilter::IGNORE_SUBMODULE_WORKTREES
    } else {
        "--ignore-submodules=none"
    };
    args.extend(["status", "--porcelain=v1", "-z", submodules]);
    args.extend(if inspect_untracked {
        ["--untracked-files=normal", "--ignored=matching"]
    } else {
        ["--untracked-files=no", "--ignored=no"]
    });
    let entries = match git(&args, STATUS_MAX_BYTES, directory) {
        Ok(out) => out,
        Err(e) => return timeout_or_unavailable(&e),
    };
    let Ok(entries) = String::from_utf8(entries) else {
        return Observed::Error {
            error: ObservationFailure::NonUnicode,
        };
    };
    let (mut tracked_changes, mut untracked, mut ignored) = (false, Vec::new(), Vec::new());
    let mut fields = entries.split_terminator('\0');
    while let Some(entry) = fields.next() {
        let Some((state, path)) = entry.split_at_checked(3) else {
            return unavailable();
        };
        match state {
            "?? " => untracked.push(path.to_owned()),
            "!! " => ignored.push(path.to_owned()),
            _ => {
                tracked_changes = true;
                // A rename or copy is followed by the path it came from.
                if state.starts_with(['R', 'C']) {
                    fields.next();
                }
            }
        }
    }
    if untracked.len() > MAX_GIT_STATE_ENTRIES || ignored.len() > MAX_GIT_STATE_ENTRIES {
        return unavailable();
    }
    // Status does not look at a file the index marks assume-unchanged or
    // skip-worktree, yet a checkout or reset overwrites an edit to one.
    if !tracked_changes {
        let top = top_level.as_str().to_owned();
        tracked_changes = match git(&["ls-files", "-v", "-z"], INDEX_MAX_BYTES, &top) {
            Ok(index) => index.split(|b| *b == 0).any(|entry| {
                entry
                    .first()
                    .is_some_and(|tag| tag.is_ascii_lowercase() || *tag == b'S')
            }),
            Err(e) => return timeout_or_unavailable(&e),
        };
    }
    let stash_entries = match git(
        &["rev-parse", "--verify", "--quiet", "refs/stash"],
        STATUS_MAX_BYTES,
        directory,
    ) {
        Ok(_) => true,
        Err(e) if ExitFailure::code_of(&e) == Some(1) => false,
        Err(e) => return timeout_or_unavailable(&e),
    };
    let state = GitStateObservation::new(top_level, tracked_changes, stash_entries);
    if !inspect_untracked {
        return Observed::Ok { value: state };
    }
    match GitUntrackedObservation::new(untracked, ignored) {
        Ok(u) => Observed::Ok {
            value: state.with_untracked(u),
        },
        Err(_) => unavailable(),
    }
}

#[cfg(test)]
mod tests {
    use std::process::Command;

    use super::*;

    fn git(dir: &std::path::Path, args: &[&str]) {
        let out = Command::new("git")
            .arg("-C")
            .arg(dir)
            .args(args)
            .output()
            .unwrap();
        assert!(out.status.success(), "git {args:?}: {out:?}");
    }

    /// A repo with an embedded repository `sub`; returns the repo.
    fn with_gitlink(root: &std::path::Path) -> std::path::PathBuf {
        let repo = root.join("repo");
        let sub = repo.join("sub");
        std::fs::create_dir_all(&sub).unwrap();
        for d in [&repo, &sub] {
            git(d, &["init", "-q", "."]);
            git(d, &["config", "user.email", "a@b.example"]);
            git(d, &["config", "user.name", "a"]);
            std::fs::write(d.join("f.txt"), "one\n").unwrap();
            git(d, &["add", "f.txt"]);
            git(d, &["commit", "-qm", "one"]);
        }
        git(&repo, &["add", "sub"]);
        git(&repo, &["commit", "-qm", "sub"]);
        repo
    }

    fn tracked_changes(repo: &std::path::Path) -> bool {
        let plan = Plan {
            overrides: Vec::new(),
            gitlinks: true,
        };
        match git_state(repo.to_str().unwrap(), false, &plan) {
            Observed::Ok { value } => value.tracked_changes(),
            Observed::Error { error } => panic!("not observed: {error:?}"),
        }
    }

    #[test]
    fn a_gitlink_is_planned_and_a_changed_submodule_commit_is_a_tracked_change() {
        let dir = tempfile::tempdir().unwrap();
        let repo = with_gitlink(dir.path());
        let p = plan(repo.to_str().unwrap()).unwrap();
        assert!(p.gitlinks && !p.is_plain());
        assert!(!tracked_changes(&repo), "a fresh repo has no changes");

        // A dirty submodule work tree is not entered: not a tracked change.
        std::fs::write(repo.join("sub/f.txt"), "dirty\n").unwrap();
        assert!(!tracked_changes(&repo));

        // A new commit in the submodule moves the recorded gitlink: it is one.
        git(&repo.join("sub"), &["commit", "-qam", "two"]);
        assert!(tracked_changes(&repo));
    }

    #[test]
    fn a_plain_repo_is_left_to_nah_observe() {
        let dir = tempfile::tempdir().unwrap();
        let repo = dir.path().join("plain");
        std::fs::create_dir_all(&repo).unwrap();
        git(&repo, &["init", "-q", "."]);
        assert!(plan(repo.to_str().unwrap()).unwrap().is_plain());
    }
}
