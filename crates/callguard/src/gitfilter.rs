//! Keeps a repository's own filter drivers from running when callguard or nah
//! asks git for the status of that repository.
//!
//! `git status` of a modified tracked file hashes the file through its clean
//! filter, and `filter.<name>.clean|smudge|process` in `.git/config` is a shell
//! command. A repo can carry that config (an unpacked archive, an earlier write
//! by the agent), so asking for the status would run repo code before any
//! verdict. An empty `filter.<name>.<var>` makes git skip the filter (convert.c
//! returns early on an empty command), and `required=false` stops it from
//! failing the file. Only the repository's own scopes are overridden: global
//! and system filters (git-lfs) cannot be planted by a repo.

use std::collections::BTreeSet;
use std::time::Instant;

use crate::hostmeta::Runner;

/// The variables that name a command or make a missing one fatal.
const VARS: [&str; 4] = ["clean", "smudge", "process", "required"];

/// Filter driver names defined in the local or worktree scope of the
/// repository around `dir`, includes followed. An error means the config could
/// not be listed; the caller must then not run `git status` at all.
pub fn local_filter_names(
    run: &Runner,
    dir: &str,
    deadline: Instant,
) -> Result<Vec<String>, String> {
    let out = run(
        &[],
        "git",
        &[
            "-C",
            dir,
            "config",
            "--show-scope",
            "--name-only",
            "-z",
            "--includes",
            "--get-regexp",
            r"^filter\.",
        ],
        deadline,
    );
    let out = match out {
        Ok(out) => out,
        // Exit 1 is "no key matches": nothing to override.
        Err(e) if crate::hostmeta::ExitFailure::code_of(&e) == Some(1) => return Ok(Vec::new()),
        Err(e) => return Err(format!("cannot list git filter drivers: {e}")),
    };
    let text = String::from_utf8_lossy(&out);
    let mut fields = text.split('\0');
    let mut names = BTreeSet::new();
    while let (Some(scope), Some(key)) = (fields.next(), fields.next()) {
        if scope != "local" && scope != "worktree" {
            continue;
        }
        // filter.<name>.<var>; the name may hold dots.
        let Some(rest) = key.strip_prefix("filter.") else {
            continue;
        };
        let Some((name, _var)) = rest.rsplit_once('.') else {
            continue;
        };
        if name.is_empty() || name.contains(['=', '\n', '\r']) {
            return Err(format!(
                "git filter driver name {name:?} cannot be overridden"
            ));
        }
        names.insert(name.to_owned());
    }
    Ok(names.into_iter().collect())
}

/// `-c filter.<name>.clean= ...` for each name, as separate arguments.
pub fn override_args(names: &[String]) -> Vec<String> {
    let mut args = Vec::new();
    for name in names {
        for var in VARS {
            args.push("-c".to_owned());
            let value = if var == "required" { "false" } else { "" };
            args.push(format!("filter.{name}.{var}={value}"));
        }
    }
    args
}

/// The overrides for the repository around `dir`: empty when it defines no
/// filter.
pub fn overrides(run: &Runner, dir: &str, deadline: Instant) -> Result<Vec<String>, String> {
    local_filter_names(run, dir, deadline).map(|names| override_args(&names))
}

#[cfg(test)]
mod tests;
