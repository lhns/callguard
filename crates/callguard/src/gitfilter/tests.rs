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
