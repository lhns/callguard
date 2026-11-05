use super::*;

// --- Built-in rules ---------------------------------------------------------

/// A built-in rule that fired. `decision` is deny or ask.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hit {
    pub id: String,
    pub decision: Decision,
    pub reason: String,
}

/// The files that carry hook and policy configuration.
const PROTECTED_GLOBS: [&str; 10] = [
    "**/.claude/settings.json",
    "**/.claude/settings.local.json",
    "**/.callguard/**",
    "/etc/callguard/**",
    "**/.hermes/config.yaml",
    "**/.hermes/shell-hooks-allowlist.json",
    "**/.config/opencode/plugins/**",
    "**/.opencode/plugins/**",
    "**/.pi/agent/extensions/**",
    "**/.pi/extensions/**",
];

/// Finds those paths in a slash-normalized command line. A glob in the file
/// name (`.claude/*.json`) counts as naming them.
static PROTECTED_SHELL: LazyLock<Regex> = LazyLock::new(|| {
    builtin_regex(concat!(
        r"(?i)\.claude/(?:settings|[^/\s]*[*?\[])|\.callguard\b|/etc/callguard|programdata/callguard",
        r"|\.hermes/(?:config\.yaml|shell-hooks-allowlist\.json|[^/\s]*[*?\[])|\.config/opencode/plugins|\.opencode/plugins|\.pi/(?:agent/)?extensions"
    ))
});

/// The names of whole-disk and partition block devices.
macro_rules! disk_dev_re {
    () => {
        "(?:sd|hd|vd|xvd|nvme|mmcblk|disk)"
    };
}

static DISK_WIPE: LazyLock<Vec<Regex>> = LazyLock::new(|| {
    vec![
        builtin_regex(
            r"(?m)(?:^|[;&|(])\s*(?:(?:sudo|doas)\b[^;&|\n]*\s)?(?:\S*/)?mkfs(?:\.\w+)?\b",
        ),
        builtin_regex(concat!(r"\bdd\b[^;&|\n]*\bof=/dev/", disk_dev_re!())),
        builtin_regex(concat!(r">\s*/dev/", disk_dev_re!())),
        builtin_regex(r"(?i)(?:^|[;&|])\s*format(?:\.com)?\s+[a-z]:"),
        // A raw Windows disk, however the command writes it: \\.\PhysicalDrive0,
        // \\?\PhysicalDrive0, \\.\Harddisk0, \\.\HarddiskVolume1 (backslashes
        // doubled for a shell too, or slashes).
        builtin_regex(r"(?i)(?:\\+|/+)[.?](?:\\+|/+)(?:physicaldrive|harddisk(?:volume)?)\d"),
        // A raw volume, \\.\C: or \\?\C:, only when the colon ends the path:
        // \\?\C:\Users\x is an ordinary long path.
        builtin_regex(r#"(?i)(?:\\+|/+)[.?](?:\\+|/+)[a-z]:(?:$|[\s'"`;&|)<>])"#),
    ]
});

static FORK_BOMB: LazyLock<Regex> =
    LazyLock::new(|| builtin_regex(r":\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:"));

/// Cuts a command line at separators, subshells and command substitutions, so
/// each piece starts at a command position.
pub(crate) static SEGMENT_SPLIT: LazyLock<Regex> =
    LazyLock::new(|| builtin_regex("[;&|\\n\\r()`]+"));
static RM_DANGER: LazyLock<Regex> = LazyLock::new(|| {
    builtin_regex(
        r"(?i)^(?:/+\*?|~/?\*?|(?:\$home|\$\{home\}|\$env:(?:userprofile|home)|%userprofile%)/?\*?|(?:\./)?\.git/?|[a-z]:/?\*?)$",
    )
});
static UNIX_FLAGS: LazyLock<Regex> = LazyLock::new(|| builtin_regex(r"^-[a-zA-Z]+$")); // -rf, -Rfv
static WIN_FLAG: LazyLock<Regex> = LazyLock::new(|| builtin_regex(r"^/[a-zA-Z]$"));

/// Commands that delete files.
const REMOVERS: [&str; 7] = ["rm", "rmdir", "rd", "del", "erase", "remove-item", "ri"];

/// The wrappers run the rest of their arguments as a command (shells with -c
/// too). Returns the options that take a separate argument, and "#n" says that
/// n positional arguments precede the command; None if `name` is no wrapper.
fn wrapper(name: &str) -> Option<&'static [&'static str]> {
    Some(match name {
        "sudo" => &[
            "-u",
            "-g",
            "-C",
            "-D",
            "-h",
            "-p",
            "-r",
            "-t",
            "-T",
            "-U",
            "--user",
            "--group",
            "--chdir",
            "--chroot",
            "--close-from",
            "--host",
            "--prompt",
            "--role",
            "--type",
            "--command-timeout",
            "--other-user",
        ],
        "doas" => &["-u", "-C"],
        // `-S` takes the command as its value: it is not skipped.
        "env" => &["-u", "-C", "--unset", "--chdir"],
        "nice" => &["-n", "--adjustment"],
        "ionice" => &["-c", "-n", "-p"],
        "timeout" => &["-s", "-k", "--signal", "--kill-after", "#1"],
        "stdbuf" => &["-i", "-o", "-e"],
        "chroot" => &["#1"],
        "xargs" => &["-a", "-d", "-E", "-I", "-L", "-n", "-P", "-s"],
        "exec" => &["-a"],
        "time" => &["-f", "-o"],
        "flock" => &[
            "-w",
            "-E",
            "--timeout",
            "--wait",
            "--conflict-exit-code",
            "#1",
        ],
        "wsl" => &["-d", "--distribution", "-u", "--user", "--cd"],
        "command" | "nohup" | "setsid" | "busybox" | "sh" | "bash" | "zsh" | "dash" | "fish"
        | "csh" | "tcsh" | "eval" | "{" | "!" | "if" | "then" | "elif" | "else" | "do"
        | "while" | "until" => &[],
        _ => return None,
    })
}

/// Programs that run the text after a command flag: `su -c`, `cmd /c`,
/// `powershell -Command` (any prefix of it, `-c` too). Returns whether a
/// lower-case token is that flag.
fn command_flag(name: &str) -> Option<fn(&str) -> bool> {
    Some(match name {
        "su" => |t| t == "-c" || t == "--command",
        "cmd" => |t| matches!(t, "/c" | "/k" | "/r"),
        "powershell" | "pwsh" => |t| t.len() > 1 && "-command".starts_with(t),
        _ => return None,
    })
}

/// The index of the command a wrapper at `toks[i - 1]` runs.
fn skip_wrapper(toks: &[&str], mut i: usize, valued: &[&str]) -> usize {
    let mut positional = valued
        .iter()
        .find_map(|o| o.strip_prefix('#'))
        .and_then(|n| n.parse::<usize>().ok())
        .unwrap_or(0);
    while i < toks.len() {
        let t = toks[i];
        if t == "--" {
            return i + 1;
        } else if t.starts_with('-') && t.len() > 1 {
            i += 1;
            if valued.contains(&t) {
                i += 1; // the option's value
            }
        } else if t.contains('=') {
            i += 1; // env VAR=value
        } else if positional > 0 {
            positional -= 1;
            i += 1;
        } else {
            return i;
        }
    }
    i
}

/// Whether a shell command recursively deletes a root-like target (`/`, `~`,
/// `$HOME`, a drive root, `.git`) or passes `--no-preserve-root`, at a command
/// position: after wrappers such as sudo, timeout or `sh -c`, so text inside
/// an ordinary argument does not fire it.
pub(crate) fn rm_root(command: &str) -> bool {
    for seg in SEGMENT_SPLIT.split(command) {
        let unquoted = seg.replace(['"', '\''], "");
        let toks: Vec<&str> = unquoted
            .split_whitespace()
            .flat_map(|t| match t.strip_prefix("--split-string=") {
                Some(cmd) => vec!["--split-string", cmd],
                None => vec![t],
            })
            .collect();
        let mut i = 0;
        while i < toks.len() {
            let name = prog_name(toks[i], true);
            if let Some(is_flag) = command_flag(&name) {
                // The command is the text after the flag; without one, nothing
                // runs that we can read.
                let at = toks[i + 1..]
                    .iter()
                    .position(|t| is_flag(&t.to_lowercase()));
                i = at.map_or(toks.len(), |k| i + k + 2);
                continue;
            }
            if let Some(valued) = wrapper(&name) {
                i = skip_wrapper(&toks, i + 1, valued);
                continue;
            }
            if toks[i].contains('=') {
                i += 1; // VAR=value prefix
                continue;
            }
            break;
        }
        if i >= toks.len() {
            continue;
        }
        let name = prog_name(toks[i], true);
        if !REMOVERS.contains(&name.as_str()) {
            continue;
        }
        let mut recursive = false;
        let mut targets: Vec<String> = Vec::new();
        for t in &toks[i + 1..] {
            let lower = t.to_lowercase();
            // GNU rm takes any unambiguous prefix of a long option.
            if t.len() > 3 && "--no-preserve-root".starts_with(t) {
                return true;
            }
            if (t.len() > 2 && "--recursive".starts_with(t))
                || (t.len() > 1 && "-recurse".starts_with(&lower)) // PowerShell accepts -r, -rec, ...
                || ((name == "rm" || name == "rmdir")
                    && UNIX_FLAGS.is_match(t)
                    && t.contains(['r', 'R']))
            {
                recursive = true;
            } else if t.starts_with('-') {
                // any other option
            } else if WIN_FLAG.is_match(t) && name != "rm" {
                recursive = recursive || lower == "/s";
            } else {
                targets.push(path_clean(&t.replace('\\', "/")));
            }
        }
        if recursive && targets.iter().any(|t| RM_DANGER.is_match(t)) {
            return true;
        }
    }
    false
}

/// Whether `command` runs `callguard trust` (anything but `--list`). Read from
/// the raw text, as the other built-ins are: quotes and a path or `.exe` on the
/// program do not hide it. It misses a script written earlier, a program name
/// the shell expands, a renamed copy of the binary and a wrapper that builds
/// the command at run time; the terminal requirement of the verb is the second
/// lock.
pub(crate) fn runs_trust_verb(command: &str) -> bool {
    // The text as written, and with quotes and backslashes removed, where
    // `tr""ust` is `trust`.
    [command.to_owned(), unquoted(command)].iter().any(|text| {
        SEGMENT_SPLIT.split(text).any(|seg| {
            let words: Vec<String> = seg
                .replace(['\'', '"'], " ")
                .split_whitespace()
                .map(str::to_owned)
                .collect();
            words.iter().enumerate().any(|(i, w)| {
                prog_name(w, true) == "callguard"
                    && words.get(i + 1).is_some_and(|n| n == "trust")
                    && !plain_list(&words[i + 2..])
            })
        })
    })
}

/// Whether the arguments of `callguard trust` ask for the listing, and
/// nothing else: `--list` is there and every spelling of it is a bare flag.
/// The last value of a flag wins, so `--list --list=false` is not a list.
fn plain_list(args: &[String]) -> bool {
    let lists: Vec<&String> = args
        .iter()
        .filter(|a| {
            a.starts_with('-') && a.trim_start_matches('-').split('=').next() == Some("list")
        })
        .collect();
    !lists.is_empty() && lists.iter().all(|a| *a == "--list" || *a == "-list")
}

/// `s` without quotes and backslashes: how a shell reads a word split by empty
/// quotes (`.cla""ude`) or escapes (`.cl\aude`). Shell guards read both this
/// and the raw text. Globs and variables stay a known limit.
fn unquoted(s: &str) -> String {
    s.replace(['"', '\'', '\\'], "")
}

/// Tool writes to the trust record are denied; shell commands that name it or
/// run the trust verb ask. Always on.
fn trust_guard(c: &Call) -> Option<Hit> {
    let file = crate::trust::FILE;
    let named = |s: &str| {
        s.to_ascii_lowercase().contains(file) || unquoted(s).to_ascii_lowercase().contains(file)
    };
    let hit = |decision: Decision, reason: &str| {
        Some(Hit {
            id: "self-protect-trust".into(),
            decision,
            reason: reason.into(),
        })
    };
    if c.kind == KIND_WRITE {
        if c.paths()
            .any(|p| p.to_ascii_lowercase().ends_with(&format!("/{file}")))
        {
            return hit(
                Decision::Deny,
                "callguard denies edits to its project trust record; the user runs `callguard trust`",
            );
        }
        if c.path.is_none() && named(&c.whole) {
            return hit(
                Decision::Ask,
                "edit names the project trust record; a human should confirm",
            );
        }
    }
    if c.kind == KIND_SHELL && !c.command.is_empty() {
        if c.commands().any(named) {
            return hit(
                Decision::Ask,
                "command names the project trust record; a human should confirm",
            );
        }
        if c.commands().any(runs_trust_verb) {
            return hit(
                Decision::Ask,
                "command runs `callguard trust`, which grants project rules; a human should confirm",
            );
        }
    }
    None
}

/// The always-on layer 0.
#[derive(Debug)]
pub(crate) struct Builtin {
    env: Env,
    disabled: Vec<String>,
    /// Write targets.
    protected: Vec<Regex>,
    /// Extra files as they may appear in a command, folded.
    extra: Vec<String>,
}

impl Builtin {
    /// Compiles the built-in rules, minus the `disabled` ids. `extra` are
    /// further files for the self-protection rules (such as an explicit policy
    /// file).
    pub fn new(env: Env, disabled: &[String], extra: &[String]) -> Result<Builtin, RulesError> {
        let mut globs: Vec<String> = PROTECTED_GLOBS.iter().map(|g| (*g).to_owned()).collect();
        let sys_dir = std::path::Path::new(&policy::system_path())
            .parent()
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_default();
        globs.push(format!("{}/**", env.slash(&sys_dir)));
        let mut protected = Vec::new();
        for g in &globs {
            protected.push(env.compile_glob(g)?);
        }
        let mut folded_extra = Vec::new();
        for p in extra {
            // Cleaned like the paths of a call, so a `..` in the setting still matches.
            let p = env.normalize(p, "");
            let mut pat = format!("^{}$", ::regex::escape(&p));
            if env.caseless() {
                pat.insert_str(0, "(?i)");
            }
            protected.push(compile_regex(&pat)?);
            folded_extra.push(env.fold(&p));
            let slashed_home = env.slash(&env.home);
            let home = slashed_home.strip_suffix('/').unwrap_or(&slashed_home);
            if !home.is_empty()
                && env.in_dir(&p, home)
                && let Some(rest) = p.get(home.len()..)
            {
                folded_extra.push(env.fold(&format!("~{rest}")));
                folded_extra.push(env.fold(&format!("$HOME{rest}")));
            }
        }
        Ok(Builtin {
            env,
            disabled: disabled.to_vec(),
            protected,
            extra: folded_extra,
        })
    }

    /// Whether `text` (a command line or a tool input) names a hook or policy
    /// file.
    fn names_protected(&self, text: &str) -> bool {
        [text.to_owned(), unquoted(text)].iter().any(|text| {
            let text = self.env.slash(text);
            if PROTECTED_SHELL.is_match(&text) {
                return true;
            }
            let folded = self.env.fold(&text);
            self.extra.iter().any(|p| folded.contains(p.as_str()))
        })
    }

    /// The first built-in rule that fires for `c`. Hard denies are checked
    /// before the self-protection ask.
    pub fn check(&self, c: &Call) -> Option<Hit> {
        // The trust record guard has no id: `disable_builtin` cannot name it.
        if let Some(hit) = trust_guard(c) {
            return Some(hit);
        }
        let on = |id: &str| !self.disabled.iter().any(|d| d == id);
        let hit = |id: &str, decision: Decision, reason: String| {
            Some(Hit {
                id: id.into(),
                decision,
                reason,
            })
        };
        if c.kind == KIND_WRITE && on("self-protect-write") {
            if c.paths()
                .any(|p| self.protected.iter().any(|re| re.is_match(p)))
            {
                return hit(
                    "self-protect-write",
                    Decision::Deny,
                    format!(
                        "callguard denies edits to hook and policy files ({}); ask the user to change them",
                        c.path.as_deref().unwrap_or_default()
                    ),
                );
            }
            // Patch tools carry their target paths inside the input.
            if c.path.is_none() && self.names_protected(&c.whole) {
                return hit(
                    "self-protect-write",
                    Decision::Ask,
                    "edit names a hook or policy file; a human should confirm".into(),
                );
            }
        }
        if c.kind == KIND_SHELL && !c.command.is_empty() {
            if on("rm-root") && c.commands().any(rm_root) {
                return hit(
                    "rm-root",
                    Decision::Deny,
                    "recursive deletion of a root, home or .git directory".into(),
                );
            }
            if on("disk-wipe")
                && c.commands()
                    .any(|cmd| DISK_WIPE.iter().any(|re| re.is_match(cmd)))
            {
                return hit(
                    "disk-wipe",
                    Decision::Deny,
                    "command formats or overwrites a disk".into(),
                );
            }
            if on("fork-bomb") && c.commands().any(|cmd| FORK_BOMB.is_match(cmd)) {
                return hit("fork-bomb", Decision::Deny, "fork bomb".into());
            }
            if on("self-protect-shell") && c.commands().any(|cmd| self.names_protected(cmd)) {
                return hit(
                    "self-protect-shell",
                    Decision::Ask,
                    "command names a hook or policy file; a human should confirm".into(),
                );
            }
        }
        None
    }
}
