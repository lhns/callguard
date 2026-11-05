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

/// Whether the pattern spells out a protected directory or file name
/// (`policy::protected`). Allow rules do not match inside them unless they name
/// one outright, which only the system layer can do.
pub(super) fn names_protected(s: &PathSpec) -> bool {
    let rest = s.rest.to_lowercase();
    policy::protected::in_segments(&rest.split('/').collect::<Vec<_>>())
}

/// Whether the POSIX-form `path`, below `root` when it is inside, has a
/// protected directory or file name in it. Parents of the project do not count.
pub(super) fn in_protected(path: &str, root: Option<&str>) -> bool {
    let path = path.to_lowercase();
    let below = root
        .and_then(|r| path.strip_prefix(&format!("{}/", r.to_lowercase().trim_end_matches('/'))))
        .unwrap_or(&path);
    policy::protected::in_segments(&below.split('/').collect::<Vec<_>>())
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
        Rule::Negation { .. } => {
            return blocked("a `!` rule carves paths out of deny and ask rules only");
        }
        Rule::Path { carve, .. } if !carve.is_empty() => {
            return blocked("a carve-out belongs to a deny or ask rule");
        }
        Rule::Path { spec: None, .. } => return blocked("a bare file rule allows every path"),
        Rule::Path { spec: Some(s), .. } => {
            if s.is_blanket() {
                return blocked("the pattern allows every path under its anchor");
            }
            // Hook, policy and VCS directories are never pre-approved by a
            // user or project rule; only the system layer may allow them.
            if guarded_layer && names_protected(s) {
                return blocked(
                    "a user or project rule may not allow protected paths (hook, policy, VCS and tool configuration directories and files)",
                );
            }
        }
        Rule::Fetch { domain: None } => return blocked("a bare WebFetch rule allows every URL"),
        Rule::Fetch { domain: Some(d) } if d.is_blanket() => {
            return blocked("the domain pattern matches every host");
        }
        Rule::Param { .. } => {
            return blocked("a parameter value does not establish that a call is safe");
        }
        Rule::Skill { by_param: true, .. } => {
            return blocked("a parameter value does not establish that a call is safe");
        }
        Rule::Skill { name, .. } if name.chars().all(|c| c == '*') => {
            return blocked("a blanket Skill allow allows every skill");
        }
        Rule::Tool(n) if matches!(kind_of(n), KIND_SHELL | KIND_READ | KIND_WRITE | KIND_FETCH) => {
            return blocked("name the tool with its pattern, such as Bash(...) or Read(...)");
        }
        _ => {}
    }
    Ok(rule)
}

/// Reads an additional directory: absolute (`~/x` is expanded), not the home
/// directory or a file system root, not on the network. Returns the normalized
/// path; the error is the reason, for the warning.
pub(crate) fn vet_dir(env: &Env, text: &str) -> Result<String, String> {
    let t = text.trim();
    if t.is_empty() {
        return Err("it is empty".into());
    }
    if t.chars().any(is_hiding) {
        return Err("it contains a control or bidirectional character".into());
    }
    if paths::is_network(env, t) {
        return Err("it is a network path".into());
    }
    let norm = env.clean_names(&env.normalize(t, ""));
    if env.drive_relative(t) || !env.is_abs(&norm) {
        return Err("it is a relative path; write an absolute one or start with ~/".into());
    }
    if env.is_broad_dir(&norm, env.real(&norm).as_deref()) {
        return Err("it is the home directory or a file system root".into());
    }
    Ok(norm)
}

/// [`vet_dir`] for callers outside the crate: why the directory would be
/// ignored.
pub fn vet_dir_reason(text: &str) -> Result<(), String> {
    vet_dir(&Env::host(), text).map(|_| ())
}

/// The additional directories of one policy file that survive [`vet_dir`] (as
/// written), and a warning for each that does not.
pub(crate) fn vet_dir_list(env: &Env, dirs: &[String], src: &str) -> (Vec<String>, Vec<String>) {
    let (mut kept, mut warns) = (Vec::new(), Vec::new());
    for d in dirs {
        match vet_dir(env, d) {
            Ok(_) => kept.push(d.clone()),
            Err(why) => warns.push(format!(
                "{src}: permissions.additionalDirectories {} ignored: {why}",
                quote_string(&escape_unprintable(d))
            )),
        }
    }
    (kept, warns)
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
