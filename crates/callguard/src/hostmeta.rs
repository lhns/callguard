//! Host observations about the repository around a pending shell call (git
//! status, remote visibility). Stub except for the types: `Meta`, `GitStatus`
//! and `RepoVisibility` are the wire types `schema` re-exports.
//!
//! Go's `context.Context` becomes an explicit `deadline`; probing runs a few
//! short processes under one deadline and never fails the call.
#![allow(unused_variables)]

use std::io;
use std::time::{Duration, Instant};

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

/// The `Runner` that starts real processes.
pub fn exec_runner(
    env: &[String],
    name: &str,
    args: &[&str],
    deadline: Instant,
) -> io::Result<Vec<u8>> {
    todo!("port hostmeta.ExecRunner")
}

/// Fills in what `have` lacks for a shell command run in `cwd`: the git status
/// when the command can destroy or publish uncommitted work, and the
/// destination's visibility when it pushes or publishes. Returns `have` plus
/// the new observations, or `None` if there are none. `cwd == ""` skips probing.
pub fn probe(
    run: &Runner,
    cwd: &str,
    command: &str,
    have: Option<&Meta>,
    deadline: Instant,
) -> Option<Meta> {
    todo!("port hostmeta.Probe")
}

/// Runs git status in `cwd`. Any failure is `None`.
pub fn status(run: &Runner, cwd: &str, deadline: Instant) -> Option<GitStatus> {
    todo!("port hostmeta.Status")
}

/// Counts the entries of `git status --porcelain=v1` output.
pub fn parse_status(porcelain: &str) -> GitStatus {
    todo!("port hostmeta.ParseStatus")
}

/// Whether the command can destroy or publish uncommitted work.
pub fn needs_status(command: &str) -> bool {
    todo!("port hostmeta.NeedsStatus")
}

/// Where a command pushes or publishes: a remote name, a URL or a gh repo
/// argument. `raw == "origin"` is the default.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Destination {
    pub raw: String,
    /// From a gh command: OWNER/REPO means github.com.
    pub gh: bool,
}

/// The push or publish destinations of a command.
pub fn destinations(command: &str) -> Vec<Destination> {
    todo!("port hostmeta.Destinations")
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
    todo!("port hostmeta.Visibilities")
}

/// Turns https://host/o/r(.git), git@host:o/r(.git) and ssh://git@host/o/r into
/// host/o/r. Returns "" for anything else, such as a local path.
pub fn normalize_remote(raw: &str) -> String {
    todo!("port hostmeta.NormalizeRemote")
}
