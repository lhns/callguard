use super::*;

// --- Dropping allow rules that loosen too far ----------------------------------

/// Programs that run what their arguments say: a wildcard allow for one of
/// these is an allow for everything. Best effort: a list of known names cannot
/// be complete, and an exact rule such as `Bash(make test)` is never dropped.
pub(super) const OPEN_ENDED: &[&str] = &[
    "bash",
    "sh",
    "zsh",
    "dash",
    "fish",
    "ksh",
    "csh",
    "tcsh",
    "pwsh",
    "powershell",
    "cmd",
    "python",
    "python2",
    "python3",
    "py",
    "pypy",
    "node",
    "deno",
    "bun",
    "ruby",
    "perl",
    "php",
    "lua",
    "rscript",
    "tclsh",
    "osascript",
    "env",
    "sudo",
    "su",
    "doas",
    "xargs",
    "parallel",
    "find",
    "fd",
    "watch",
    "setsid",
    "ionice",
    "flock",
    "nohup",
    "nice",
    "timeout",
    "time",
    "stdbuf",
    "exec",
    "eval",
    "command",
    "builtin",
    "source",
    ".",
    "chroot",
    "unshare",
    "nsenter",
    "strace",
    "ltrace",
    "gdb",
    "script",
    "ssh",
    "scp",
    "sftp",
    "rsync",
    "curl",
    "wget",
    "nc",
    "ncat",
    "netcat",
    "socat",
    "telnet",
    "ftp",
    "awk",
    "gawk",
    "sed",
    "ed",
    "ex",
    "vi",
    "vim",
    "nvim",
    "emacs",
    "tee",
    "dd",
    "npx",
    "devbox",
    "direnv",
    "mise",
    "nix",
    "nodejs",
    "tsx",
    "ts-node",
    "uvx",
    "bunx",
    "pipx",
    "pnpx",
    "yarnpkg",
    "make",
    "just",
    "tar",
    "zip",
    "gcc",
    "cc",
    "clang",
];

/// A program name without its version: `python3.12` is `python`, `node22` is
/// `node`.
pub(super) fn family(name: &str) -> String {
    let t = name.trim_end_matches(|c: char| c.is_ascii_digit() || c == '.');
    if t.is_empty() { name } else { t }.to_owned()
}

/// Tools whose subcommand decides what they do: the wildcard must come after it.
pub(super) const SUBCOMMAND_TOOLS: &[&str] = &[
    "git", "gh", "docker", "podman", "kubectl", "npm", "yarn", "pnpm", "cargo", "go", "uv",
    "poetry", "dotnet", "pipenv",
];

/// Commands that run repository code (or, `git config`, set a program git
/// runs); a wildcard allow for any of them is dropped (Claude's auto mode drops
/// the same). Best effort, like `OPEN_ENDED`.
pub(super) const RUN_COMMANDS: &[(&str, &str)] = &[
    ("npm", "run"),
    ("npm", "run-script"),
    ("npm", "rum"),
    ("npm", "urn"),
    ("npm", "x"),
    ("npm", "exec"),
    ("yarn", "run"),
    ("yarn", "dlx"),
    ("pnpm", "run"),
    ("pnpm", "exec"),
    ("pnpm", "dlx"),
    ("bun", "run"),
    ("bun", "x"),
    ("cargo", "run"),
    ("go", "run"),
    ("deno", "run"),
    ("deno", "task"),
    ("git", "config"),
    ("uv", "run"),
    ("poetry", "run"),
    ("pipenv", "run"),
    ("dotnet", "run"),
];

/// Hook, policy and VCS directories. Allow rules do not match inside them
/// unless they name one outright, which only the system layer can do.
pub(super) const GUARDED_DIRS: [&str; 6] = [
    ".git",
    ".claude",
    ".callguard",
    ".hermes",
    ".opencode",
    ".pi",
];

/// Whether the pattern spells out a guarded directory.
pub(super) fn names_guarded_dir(s: &PathSpec) -> bool {
    s.rest
        .split('/')
        .any(|seg| GUARDED_DIRS.contains(&seg.to_lowercase().as_str()))
}

/// Whether the POSIX-form `path`, below `root` when it is inside, has a
/// guarded directory in it. Parents of the project do not count.
pub(super) fn in_guarded_dir(path: &str, root: Option<&str>) -> bool {
    let path = path.to_lowercase();
    let below = root
        .and_then(|r| path.strip_prefix(&format!("{}/", r.to_lowercase().trim_end_matches('/'))))
        .unwrap_or(&path);
    below.split('/').any(|seg| GUARDED_DIRS.contains(&seg))
}

/// Reads an allow rule and refuses the ones that loosen the guard too far.
/// `layer` is the policy layer that wrote it; None applies only the limits
/// every layer shares. The error is the reason, for the warning.
pub(crate) fn vet_allow(text: &str, layer: Option<&str>) -> Result<Rule, String> {
    let rule = parse(text).map_err(|e| format!("cannot be read: {e}"))?;
    let guarded_layer = matches!(layer, Some(policy::LAYER_USER | policy::LAYER_PROJECT));
    let head = text.split('(').next().unwrap_or("").trim();
    if matches!(head, "Agent" | "Task" | "task" | "Monitor") {
        return Err(format!(
            "{head} allows start agents or background work and are never honoured"
        ));
    }
    let blocked = |why: &str| Err(why.to_owned());
    match &rule {
        Rule::Shell {
            powershell: true, ..
        } => return blocked("PowerShell allow rules are not honoured"),
        Rule::Shell { spec: None, .. } => return blocked("a bare Bash rule allows every command"),
        Rule::Shell { spec: Some(s), .. } => {
            let Tok::Lit(first) = s.first() else {
                return blocked("the first word is a wildcard");
            };
            let name = family(&prog_name(first, true));
            if OPEN_ENDED.contains(&name.as_str()) && s.has_wildcard() {
                return Err(format!("{name} with a wildcard runs whatever it is given"));
            }
            if SUBCOMMAND_TOOLS.contains(&name.as_str())
                && s.has_wildcard()
                && !matches!(s.toks.get(1), Some(Tok::Lit(w)) if !w.starts_with(['-', '+']))
            {
                return Err(format!("a wildcard may not come right after {name}"));
            }
            if let Some(second) = s.toks.get(1).and_then(|t| match t {
                Tok::Lit(w) => Some(w.as_str()),
                _ => None,
            }) && s.has_wildcard()
                && RUN_COMMANDS.contains(&(name.as_str(), second))
            {
                return Err(format!(
                    "{name} {second} with a wildcard runs repository code"
                ));
            }
        }
        Rule::Path { spec: None, .. } => return blocked("a bare file rule allows every path"),
        Rule::Path { spec: Some(s), .. } => {
            if s.is_blanket() {
                return blocked("the pattern allows every path under its anchor");
            }
            // Hook, policy and VCS directories are never pre-approved by a
            // user or project rule; only the system layer may allow them.
            if guarded_layer && names_guarded_dir(s) {
                return blocked(
                    "a user or project rule may not allow paths in hook, policy or VCS directories",
                );
            }
        }
        Rule::Fetch { domain: None } => return blocked("a bare WebFetch rule allows every URL"),
        Rule::Fetch { domain: Some(d) } if d.is_blanket() => {
            return blocked("the domain pattern matches every host");
        }
        Rule::Tool(n) if matches!(kind_of(n), KIND_SHELL | KIND_READ | KIND_WRITE | KIND_FETCH) => {
            return blocked("name the tool with its pattern, such as Bash(...) or Read(...)");
        }
        _ => {}
    }
    Ok(rule)
}

/// [`vet_allow`] for callers outside the crate: why the rule would be dropped.
pub fn vet_reason(text: &str, layer: Option<&str>) -> Result<(), String> {
    vet_allow(text, layer).map(|_| ())
}

/// The allow rules of one policy layer that survive [`vet_allow`], and a
/// warning for each that does not.
pub(crate) fn vet_allow_list(
    allow: &[String],
    layer: &str,
    src: &str,
) -> (Vec<String>, Vec<String>) {
    let (mut kept, mut warns) = (Vec::new(), Vec::new());
    for r in allow {
        match vet_allow(r, Some(layer)) {
            Ok(_) => kept.push(r.clone()),
            Err(why) => warns.push(format!(
                "{src}: permissions.allow {} dropped: {why}",
                quote_string(r)
            )),
        }
    }
    (kept, warns)
}
