//! The filter payload must not run. These tests use the real `git` and `sh`
//! (Git for Windows ships both) on Windows and Linux.

use std::path::Path;
use std::process::Command;
use std::time::{Duration, Instant};

use super::*;
use crate::hostmeta::{self, exec_runner};

fn soon() -> Instant {
    Instant::now() + Duration::from_secs(20)
}

fn git(dir: &Path, args: &[&str]) {
    let out = Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(args)
        .output()
        .expect("git runs");
    assert!(out.status.success(), "git {args:?}: {out:?}");
}

/// A repo whose tracked file differs from the index in content but not in size
/// (git hashes it through the clean filter then) and whose clean filter,
/// `sh payload`, leaves `marker` behind. `extra` are more config lines.
fn crafted(root: &Path, extra: &[(&str, &str)]) -> (std::path::PathBuf, std::path::PathBuf) {
    let repo = root.join("repo");
    std::fs::create_dir_all(&repo).unwrap();
    let marker = root.join("payload-ran");
    // Forward slashes: git hands the filter command to sh.
    let marker_sh = marker
        .to_string_lossy()
        .replace(std::path::MAIN_SEPARATOR, "/");
    git(&repo, &["init", "-q", "."]);
    git(&repo, &["config", "user.email", "a@b.example"]);
    git(&repo, &["config", "user.name", "a"]);
    std::fs::write(repo.join("tracked.txt"), "one\n").unwrap();
    std::fs::write(repo.join(".gitattributes"), "* filter=x\n").unwrap();
    git(&repo, &["add", "-A"]);
    git(&repo, &["commit", "-qm", "one"]);
    // Git compares whole seconds: a write in the same second as the commit looks
    // unchanged and the filter would not run.
    std::thread::sleep(Duration::from_millis(1100));
    std::fs::write(repo.join("tracked.txt"), "two\n").unwrap();
    git(
        &repo,
        &[
            "config",
            "filter.x.clean",
            &format!("sh -c 'touch \"{marker_sh}\"; cat'"),
        ],
    );
    for (k, v) in extra {
        git(&repo, &["config", k, v]);
    }
    (repo, marker)
}

fn status(repo: &Path) -> Option<hostmeta::GitStatus> {
    hostmeta::status(&exec_runner, &repo.to_string_lossy(), soon())
}

#[test]
fn status_does_not_run_a_planted_clean_filter() {
    let dir = tempfile::tempdir().unwrap();
    let (repo, marker) = crafted(dir.path(), &[]);
    // Control: plain git runs the payload, so the test can tell.
    git(&repo, &["status", "--porcelain=v1"]);
    assert!(marker.exists(), "the control run must trigger the payload");
    std::fs::remove_file(&marker).unwrap();

    let st = status(&repo).expect("status is available");
    assert!(!marker.exists(), "the filter payload ran");
    assert_eq!(st.modified, 1, "{st:?}");
}

#[test]
fn empty_overrides_also_beat_process_and_required() {
    let dir = tempfile::tempdir().unwrap();
    let (repo, marker) = crafted(
        dir.path(),
        &[
            ("filter.x.smudge", "false"),
            ("filter.x.process", "false"),
            ("filter.x.required", "true"),
        ],
    );
    let st = status(&repo).expect("status survives a required filter");
    assert!(!marker.exists(), "the filter payload ran");
    assert_eq!(st.modified, 1, "{st:?}");
}

#[test]
fn a_dotted_filter_name_and_a_worktree_scope_are_found() {
    let dir = tempfile::tempdir().unwrap();
    let (repo, _) = crafted(dir.path(), &[("filter.a.b.clean", "x")]);
    let names = local_filter_names(&exec_runner, &repo.to_string_lossy(), soon()).unwrap();
    assert_eq!(names, ["a.b", "x"]);
    let args = override_args(&["a.b".into()]);
    assert_eq!(
        args,
        [
            "-c",
            "filter.a.b.clean=",
            "-c",
            "filter.a.b.smudge=",
            "-c",
            "filter.a.b.process=",
            "-c",
            "filter.a.b.required=false"
        ]
    );
}

#[test]
fn no_filter_means_no_overrides_and_a_listing_failure_is_an_error() {
    let dir = tempfile::tempdir().unwrap();
    let repo = dir.path().join("plain");
    std::fs::create_dir_all(&repo).unwrap();
    git(&repo, &["init", "-q", "."]);
    // The host's global and system filters (git-lfs) are not ours to touch.
    let got = overrides(&exec_runner, &repo.to_string_lossy(), soon()).unwrap();
    assert!(got.is_empty(), "{got:?}");

    let failing =
        |_: &[String], _: &str, _: &[&str], _: Instant| Err(std::io::Error::other("no git"));
    assert!(overrides(&failing, "/x", soon()).is_err());
    assert!(hostmeta::status(&failing, "/x", soon()).is_none());
}

// --- submodules: their own filters are not in the top-level listing ---------

/// A superproject with a submodule `sub` whose own config defines a clean
/// filter, and a same-size edit inside it. `plain` makes `sub/.git` a plain
/// directory (an embedded repository) instead of a gitfile.
fn crafted_submodule(root: &Path, plain: bool) -> (std::path::PathBuf, std::path::PathBuf) {
    let marker = root.join("sub-payload-ran");
    let marker_sh = marker
        .to_string_lossy()
        .replace(std::path::MAIN_SEPARATOR, "/");
    let identity = |dir: &Path| {
        git(dir, &["config", "user.email", "a@b.example"]);
        git(dir, &["config", "user.name", "a"]);
    };
    let inner = root.join("inner");
    std::fs::create_dir_all(&inner).unwrap();
    git(&inner, &["init", "-q", "."]);
    identity(&inner);
    std::fs::write(inner.join("a.txt"), "one\n").unwrap();
    std::fs::write(inner.join(".gitattributes"), "*.txt filter=evil\n").unwrap();
    git(&inner, &["add", "-A"]);
    git(&inner, &["commit", "-qm", "one"]);

    let repo = root.join("super");
    std::fs::create_dir_all(&repo).unwrap();
    git(&repo, &["init", "-q", "."]);
    identity(&repo);
    std::fs::write(repo.join("top.txt"), "top\n").unwrap();
    git(&repo, &["add", "-A"]);
    git(&repo, &["commit", "-qm", "top"]);
    let inner_url = inner.to_string_lossy().into_owned();
    if plain {
        git(&repo, &["clone", "-q", &inner_url, "sub"]);
    } else {
        git(
            &repo,
            &[
                "-c",
                "protocol.file.allow=always",
                "submodule",
                "add",
                "-q",
                &inner_url,
                "sub",
            ],
        );
    }
    let sub = repo.join("sub");
    identity(&sub);
    git(&repo, &["add", "-A"]);
    git(&repo, &["commit", "-qm", "sub"]);
    // The filter lives in the submodule's own config only.
    git(
        &sub,
        &[
            "config",
            "filter.evil.clean",
            &format!("sh -c 'touch \"{marker_sh}\"; cat'"),
        ],
    );
    std::thread::sleep(Duration::from_millis(1100));
    // The same size as the index records (autocrlf may have changed what was
    // checked out), other bytes: git hashes such a file through the filter.
    let debug = Command::new("git")
        .arg("-C")
        .arg(&sub)
        .args(["ls-files", "--debug", "a.txt"])
        .output()
        .unwrap();
    let debug = String::from_utf8_lossy(&debug.stdout).into_owned();
    let size: usize = debug
        .lines()
        .find_map(|l| l.trim().strip_prefix("size: "))
        .and_then(|l| l.split_whitespace().next())
        .and_then(|n| n.parse().ok())
        .expect("index size");
    let mut bytes = vec![b't'; size];
    bytes[size - 1] = b'\n';
    std::fs::write(sub.join("a.txt"), bytes).unwrap();
    (repo, marker)
}

const STATUS_NONE: &[&str] = &[
    "--no-optional-locks",
    "-c",
    "core.fsmonitor=false",
    "status",
    "--porcelain=v1",
    "-z",
    "--ignore-submodules=none",
];

#[test]
fn a_submodules_own_filter_runs_unless_worktrees_are_ignored() {
    for plain in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let (repo, marker) = crafted_submodule(dir.path(), plain);
        let top = repo.to_string_lossy().into_owned();
        // The top-level listing does not see the filter, so no override helps.
        assert!(
            local_filter_names(&exec_runner, &top, soon())
                .unwrap()
                .is_empty(),
            "plain={plain}"
        );
        assert!(
            has_gitlinks(&exec_runner, &top, soon()).unwrap(),
            "plain={plain}"
        );

        // Control: nah's own status call runs the payload.
        git(&repo, STATUS_NONE);
        assert!(
            marker.exists(),
            "plain={plain}: the control run must trigger the payload"
        );
        std::fs::remove_file(&marker).unwrap();

        // The flag holds: not entering the work tree, nothing runs.
        let mut dirty = STATUS_NONE.to_vec();
        *dirty.last_mut().unwrap() = IGNORE_SUBMODULE_WORKTREES;
        git(&repo, &dirty);
        assert!(
            !marker.exists(),
            "plain={plain}: --ignore-submodules=dirty ran the payload"
        );

        // And hostmeta::status, which always passes it.
        let st = status(&repo).expect("status");
        assert!(
            !marker.exists(),
            "plain={plain}: hostmeta::status ran the payload"
        );
        assert_eq!(
            st.modified, 0,
            "an edit inside the submodule is not entered: {st:?}"
        );
    }
}

#[test]
fn a_changed_submodule_commit_still_shows_in_the_status() {
    for plain in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let (repo, marker) = crafted_submodule(dir.path(), plain);
        let sub = repo.join("sub");
        // Commit the edit inside the submodule (the filter off for the commit).
        git(
            &sub,
            &[
                "-c",
                "filter.evil.clean=",
                "-c",
                "filter.evil.required=false",
                "commit",
                "-qam",
                "two",
            ],
        );
        let st = status(&repo).expect("status");
        assert!(!marker.exists(), "plain={plain}: the payload ran");
        assert_eq!(st.modified, 1, "plain={plain}: {st:?}");
        assert!(st.files.iter().any(|f| f.ends_with("sub")), "{st:?}");
    }
}

#[test]
fn a_repo_without_a_gitlink_has_none() {
    let dir = tempfile::tempdir().unwrap();
    let (repo, _) = crafted(dir.path(), &[]);
    assert!(!has_gitlinks(&exec_runner, &repo.to_string_lossy(), soon()).unwrap());
    let failing =
        |_: &[String], _: &str, _: &[&str], _: Instant| Err(std::io::Error::other("no git"));
    assert!(has_gitlinks(&failing, "/x", soon()).is_err());
}

#[test]
fn a_driver_name_that_is_not_utf8_is_refused() {
    let ok = parse_names(b"local\0filter.a.b.clean\0global\0filter.g.clean\0").unwrap();
    assert_eq!(ok, ["a.b"], "only repository scopes, dots kept");
    let err = parse_names(b"local\0filter.\xff.clean\0").unwrap_err();
    assert!(err.contains("not UTF-8"), "{err}");
    // A global one is not the repository's to plant.
    assert!(
        parse_names(b"global\0filter.\xff.clean\0")
            .unwrap()
            .is_empty()
    );
}
