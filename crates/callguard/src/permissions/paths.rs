//! `Read(path)` and `Edit(path)` patterns: Claude's anchors, matched on
//! POSIX-form paths (`/c/Users/x` on Windows), with symlink resolution.

use std::collections::HashSet;

use crate::rules::{Env, path_clean};

use super::spec::glob_with;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Anchor {
    /// `//abs`
    Abs,
    /// `~/x`
    Home,
    /// `/x`: the project directory (in every layer).
    Project,
    /// `./x`, `x/y`, `x`: the working directory.
    Cwd,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathSpec {
    pub anchor: Anchor,
    /// The pattern after its anchor, with `/` separators.
    pub rest: String,
    /// A bare name with no slash: matches at any depth.
    bare: bool,
    /// `seg/**` written without `./`: any depth for deny and ask.
    one_dir: bool,
}

impl PathSpec {
    pub fn parse(spec: &str) -> Result<PathSpec, String> {
        let s = spec.trim().replace('\\', "/");
        if s.is_empty() {
            return Err("empty path pattern".into());
        }
        let b = s.as_bytes();
        let drive = |i: usize| b.len() > i + 1 && b[i].is_ascii_alphabetic() && b[i + 1] == b':';
        if drive(0) || (s.starts_with("//") && drive(2)) {
            let (l, rest) = if drive(0) {
                (b[0], &s[2..])
            } else {
                (b[2], &s[4..])
            };
            return Err(format!(
                "a drive path is written //{}{}",
                (l as char).to_ascii_lowercase(),
                if rest.starts_with('/') { rest } else { "/…" }
            ));
        }
        if s.starts_with('!') {
            return Err("`!` negation is not supported".into());
        }
        let (anchor, mut rest, dotted) = if let Some(r) = s.strip_prefix("//") {
            (Anchor::Abs, r.to_owned(), false)
        } else if s == "~" {
            (Anchor::Home, String::new(), false)
        } else if let Some(r) = s.strip_prefix("~/") {
            (Anchor::Home, r.to_owned(), false)
        } else if let Some(r) = s.strip_prefix('/') {
            (Anchor::Project, r.to_owned(), false)
        } else {
            let mut r = s.as_str();
            let mut dotted = false;
            while let Some(t) = r.strip_prefix("./") {
                r = t;
                dotted = true;
            }
            (Anchor::Cwd, r.to_owned(), dotted)
        };
        if rest.ends_with('/') {
            rest.push_str("**");
        }
        let bare = anchor == Anchor::Cwd && !dotted && !rest.contains('/');
        let one_dir = anchor == Anchor::Cwd
            && !dotted
            && rest
                .strip_suffix("/**")
                .is_some_and(|d| !d.is_empty() && !d.contains(['/', '*', '?']));
        Ok(PathSpec {
            anchor,
            rest,
            bare,
            one_dir,
        })
    }

    /// Nothing but wildcards after the anchor.
    pub fn is_blanket(&self) -> bool {
        self.rest
            .split('/')
            .all(|s| s.chars().all(|c| matches!(c, '*' | '?')))
    }

    /// The absolute POSIX-form glob for this call. None if the anchor is not
    /// known (no project, no home) and the rule cannot match.
    fn absolute(&self, ctx: &Ctx, allow: bool) -> Option<String> {
        let r = &self.rest;
        let anywhere = || (!allow).then(|| format!("/**/{r}"));
        let pat = match self.anchor {
            Anchor::Abs => format!("/{r}"),
            Anchor::Home => {
                if ctx.home.is_empty() {
                    return None;
                }
                format!("{}/{r}", ctx.home)
            }
            Anchor::Project => match &ctx.project {
                Some(p) => format!("{p}/{r}"),
                None => anywhere()?,
            },
            Anchor::Cwd => match &ctx.cwd {
                Some(c) if self.bare || (self.one_dir && !allow) => format!("{c}/**/{r}"),
                Some(c) => format!("{c}/{r}"),
                None => anywhere()?,
            },
        };
        Some(path_clean(&pat))
    }

    /// Whether the POSIX-form absolute `path` matches.
    pub fn matches(&self, path: &str, ctx: &Ctx, allow: bool) -> bool {
        let Some(pat) = self.absolute(ctx, allow) else {
            return false;
        };
        let (pat, path) = if ctx.caseless {
            (pat.to_lowercase(), path.to_lowercase())
        } else {
            (pat, path.to_owned())
        };
        let pat: Vec<&str> = pat.split('/').collect();
        let path: Vec<&str> = path.split('/').collect();
        match_segs(&pat, &path, 0, 0, &mut HashSet::new())
    }
}

/// What a pattern anchors at, in POSIX form.
pub struct Ctx {
    pub home: String,
    pub cwd: Option<String>,
    pub project: Option<String>,
    pub caseless: bool,
}

fn match_segs(
    pat: &[&str],
    path: &[&str],
    i: usize,
    j: usize,
    failed: &mut HashSet<(usize, usize)>,
) -> bool {
    if i == pat.len() {
        return j == path.len();
    }
    if failed.contains(&(i, j)) {
        return false;
    }
    let ok = if pat[i] == "**" {
        (j..=path.len()).any(|k| match_segs(pat, path, i + 1, k, failed))
    } else {
        j < path.len()
            && glob_with(&pat[i].replace("**", "*"), path[j], true)
            && match_segs(pat, path, i + 1, j + 1, failed)
    };
    if !ok {
        failed.insert((i, j));
    }
    ok
}

/// POSIX form of a normalized (slash, absolute) path: `C:/Users/x` becomes
/// `/c/Users/x` on Windows.
pub(super) fn to_posix(env: &Env, p: &str) -> String {
    let b = p.as_bytes();
    if env.windows && b.len() >= 2 && b[1] == b':' && b[0].is_ascii_alphabetic() {
        let drive = (b[0] as char).to_ascii_lowercase();
        let rest = &p[2..];
        return format!("/{drive}{}", if rest.starts_with('/') { rest } else { "" });
    }
    p.to_owned()
}

/// The normalized absolute directory `d` in POSIX form, None if empty or
/// relative.
pub(super) fn dir_posix(env: &Env, d: &str) -> Option<String> {
    if d.is_empty() {
        return None;
    }
    let n = env.normalize(d, "");
    env.is_abs(&n).then(|| to_posix(env, &n))
}

/// Whether the path as the host wrote it names a network location (UNC).
pub(super) fn is_network(env: &Env, raw: &str) -> bool {
    env.windows && (raw.starts_with("\\\\") || raw.starts_with("//"))
}

/// The real location of the normalized path `p` in POSIX form (see
/// [`crate::rules::resolve_real`]).
pub(super) fn resolve(env: &Env, p: &str) -> Option<String> {
    crate::rules::resolve_real(p).map(|s| to_posix(env, &s))
}
