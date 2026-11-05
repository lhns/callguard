//! The directories and files that carry hooks, tool configuration and VCS
//! state. One list serves the default write rule and the allow-rule vetting.

/// Directory names, matched at any depth. A name with a slash is a run of
/// consecutive segments (`.config/git`).
pub(crate) const PROTECTED_DIRS: &[&str] = &[
    ".git",
    ".config/git",
    ".vscode",
    ".idea",
    ".husky",
    ".cargo",
    ".devcontainer",
    ".yarn",
    ".mvn",
    ".claude",
    ".callguard",
    ".opencode",
    ".pi",
    ".hermes",
];

/// File names, matched at any depth.
pub(crate) const PROTECTED_FILES: &[&str] = &[
    ".gitconfig",
    ".gitmodules",
    ".bashrc",
    ".bash_profile",
    ".bash_login",
    ".bash_aliases",
    ".bash_logout",
    ".zshrc",
    ".zprofile",
    ".zshenv",
    ".zlogin",
    ".zlogout",
    ".profile",
    ".envrc",
    ".npmrc",
    ".yarnrc",
    ".yarnrc.yml",
    ".pnp.cjs",
    ".pnp.loader.mjs",
    ".pnpmfile.cjs",
    "bunfig.toml",
    ".bunfig.toml",
    ".bazelrc",
    ".bazelversion",
    ".bazeliskrc",
    ".pre-commit-config.yaml",
    "lefthook.yml",
    "lefthook.yaml",
    ".lefthook.yml",
    ".lefthook.yaml",
    "gradle-wrapper.properties",
    "maven-wrapper.properties",
    ".devcontainer.json",
    ".ripgreprc",
    "pyrightconfig.json",
    ".mcp.json",
    ".claude.json",
];

/// The policy globs for the default write rule's `not_path`.
pub(crate) fn globs() -> Vec<String> {
    let dirs = PROTECTED_DIRS.iter().map(|d| format!("**/{d}/**"));
    let files = PROTECTED_FILES.iter().map(|f| format!("**/{f}"));
    dirs.chain(files).collect()
}

/// Whether the lower-case path segments contain a protected directory (also
/// as the last segment) or file name.
pub(crate) fn in_segments(segs: &[&str]) -> bool {
    segs.iter().any(|s| PROTECTED_FILES.contains(s))
        || PROTECTED_DIRS.iter().any(|d| {
            let parts: Vec<&str> = d.split('/').collect();
            segs.windows(parts.len()).any(|w| w == parts.as_slice())
        })
}
