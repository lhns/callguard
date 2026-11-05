use super::*;

/// The whole call's deadline. It has to fit nah's hard deadline and the judge
/// after it, yet stay under the 12 s timeout of the opencode and pi plugins,
/// which block the call when it passes.
pub(crate) const DEFAULT_DEADLINE_MS: i64 = 11_000;

/// The hard deadline for the nah process (see [`Nah::timeout_ms`]).
pub(crate) const DEFAULT_NAH_TIMEOUT_MS: i64 = 10_000;

/// nah's analysis budget (kept by the load run, `git show 145fe3e:docs/rust-phase0.md`).
pub const DEFAULT_NAH_BUDGET_MS: i64 = 2_000;

/// The confidence the judge needs for an allow to stand.
pub(crate) const DEFAULT_MIN_CONFIDENCE: f64 = 0.7;

/// The built-in policy: the default rules plus the default of every setting.
pub fn default() -> Policy {
    with_defaults(Policy {
        policy_version: VERSION,
        rules: default_rules(),
        ..Default::default()
    })
}

/// Fills every unset setting with its default. Does not add rules.
pub(crate) fn with_defaults(mut p: Policy) -> Policy {
    if p.policy_version == 0 {
        p.policy_version = VERSION;
    }
    if p.mode.is_empty() {
        p.mode = MODE_ENFORCE.into();
    }
    if p.unattended_ask.is_empty() {
        p.unattended_ask = "deny".into();
    }
    if p.deadline_ms == 0 {
        p.deadline_ms = DEFAULT_DEADLINE_MS;
    }
    let mut nah = p.nah.take().unwrap_or_default();
    if nah.enabled.is_none() {
        nah.enabled = Some(true);
    }
    if nah.timeout_ms == 0 {
        nah.timeout_ms = DEFAULT_NAH_TIMEOUT_MS;
    }
    if nah.budget_ms == 0 {
        nah.budget_ms = DEFAULT_NAH_BUDGET_MS.min(nah.timeout_ms);
    }
    if nah.mode.is_empty() {
        nah.mode = MODE_ENFORCE.into();
    }
    p.nah = Some(nah);

    let mut llm = p.llm.take().unwrap_or_default();
    if llm.enabled.is_none() {
        llm.enabled = Some(true);
    }
    if llm.mode.is_empty() {
        llm.mode = MODE_SHADOW.into();
    }
    if llm.backend.is_empty() {
        llm.backend = "anthropic".into();
    }
    if llm.timeout_ms == 0 {
        llm.timeout_ms = 3000;
    }
    if llm.min_confidence.is_none() {
        llm.min_confidence = Some(DEFAULT_MIN_CONFIDENCE);
    }
    let mut tr = llm.transcript.take().unwrap_or_default();
    if tr.max_messages == 0 {
        tr.max_messages = crate::transcript::DEFAULT_MESSAGES as i64;
    }
    if tr.max_bytes == 0 {
        tr.max_bytes = crate::transcript::DEFAULT_BYTES as i64;
    }
    llm.transcript = Some(tr);
    p.llm = Some(llm);

    p.backends
        .entry("anthropic".into())
        .or_insert_with(|| Backend {
            r#type: "anthropic".into(),
            model: "claude-haiku-5-5".into(),
            api_key_env: "ANTHROPIC_API_KEY".into(),
            base_url: "https://api.anthropic.com".into(),
            data_classes: vec!["open".into(), "private".into()],
            ..Default::default()
        });
    p
}

fn strings(v: &[&str]) -> Vec<String> {
    v.iter().map(|s| (*s).to_owned()).collect()
}

/// The default rules (design section 4, "Default rules").
pub(crate) fn default_rules() -> Vec<Rule> {
    let secret_paths = strings(&[
        "**/.ssh/**",
        "**/.aws/**",
        "**/.env",
        "**/.env.*",
        "**/*.pem",
        "**/id_rsa*",
        "**/id_ed25519*",
        "**/.netrc",
    ]);
    let sh = || strings(&["shell"]);
    let rule = |id: &str, decision: &str, description: &str, m: Match| Rule {
        id: id.into(),
        description: description.into(),
        decision: decision.into(),
        r#match: m,
    };
    let shell_cmd = |command: &str| Match {
        kind: sh(),
        command: command.into(),
        ..Default::default()
    };
    vec![
        rule(
            "read-in-project",
            "allow",
            "reads inside the project need no review",
            Match {
                kind: strings(&["read"]),
                in_project: Some(true),
                ..Default::default()
            },
        ),
        rule(
            "write-in-project",
            "allow",
            "writes inside the project (outside protected directories and files) need no review",
            Match {
                kind: strings(&["write"]),
                in_project: Some(true),
                not_path: protected::globs(),
                ..Default::default()
            },
        ),
        rule(
            "read-only-command",
            "allow",
            "read-only commands (ls, cat, git status...) on files inside the project need no review",
            Match {
                kind: strings(&["shell"]),
                read_only: Some(true),
                ..Default::default()
            },
        ),
        rule(
            "docs-fetch",
            "allow",
            "fetching a page of a well-known documentation site needs no review",
            Match {
                tool: strings(&["WebFetch", "webfetch", "web_extract"]),
                url: "(?i)^https://".into(),
                host: strings(DOCS_HOSTS),
                ..Default::default()
            },
        ),
        rule(
            "secret-read",
            "ask",
            "reads a common secret location",
            Match {
                kind: strings(&["read"]),
                path: secret_paths,
                ..Default::default()
            },
        ),
        rule(
            "secret-read-shell",
            "ask",
            "shell command touches a common secret location",
            shell_cmd(r"\.ssh[\\/]id_|\.aws[\\/]credentials|\.netrc"),
        ),
        rule(
            "secret-exfil",
            "deny",
            "sends a common secret location over the network",
            shell_cmd(SECRET_EXFIL_RE),
        ),
        rule(
            "pipe-to-shell",
            "deny",
            "downloads and runs remote code without review (pipe to a shell or interpreter)",
            shell_cmd(PIPE_TO_SHELL_RE),
        ),
        rule(
            "ssh-remote-destructive",
            "ask",
            "runs a destructive command on a remote host over ssh",
            shell_cmd(SSH_REMOTE_DESTRUCTIVE_RE),
        ),
        rule(
            "scp-home-secret",
            "deny",
            "copies a secret directory (.ssh, .aws, .gnupg) to a remote host",
            shell_cmd(SCP_HOME_SECRET_RE),
        ),
        rule(
            "git-force-push",
            "ask",
            "force push rewrites shared history",
            shell_cmd(GIT_FORCE_PUSH_RE),
        ),
        rule(
            "git-discard",
            "ask",
            "discards uncommitted work",
            shell_cmd(GIT_DISCARD_RE),
        ),
        rule(
            "infra-destroy",
            "ask",
            "destroys infrastructure or remote resources",
            shell_cmd(INFRA_DESTROY_RE),
        ),
        rule(
            "package-publish",
            "ask",
            "publishes a package to a public registry",
            shell_cmd(PACKAGE_PUBLISH_RE),
        ),
        rule(
            "sudo",
            "ask",
            "runs a command with elevated privileges",
            shell_cmd(SUDO_RE),
        ),
        rule(
            "classifier-injection",
            "ask",
            "tool input contains instruction-like text aimed at a classifier",
            Match {
                field: BTreeMap::from([("*".to_owned(), INJECTION_RE.to_owned())]),
                ..Default::default()
            },
        ),
    ]
}

/// Hosts of the `docs-fetch` rule (https only): documentation of languages,
/// frameworks and tools, exact names only. Not every page there is written by
/// the site's owners: docs.rs, pkg.go.dev and go.dev show content of third
/// parties (a package's own docs and README), so a page can carry text meant
/// for the judge. The rule only skips the review of the fetch; the text is
/// still checked when it comes back (`classifier-injection`). No code hosting,
/// pastes, wikis or forums are listed.
pub const DOCS_HOSTS: &[&str] = &[
    "docs.python.org",
    "docs.rs",
    "doc.rust-lang.org",
    "developer.mozilla.org",
    "go.dev",
    "pkg.go.dev",
    "docs.github.com",
    "nodejs.org",
    "docs.npmjs.com",
    "docs.oracle.com",
    "docs.docker.com",
    "kubernetes.io",
    "react.dev",
    "vuejs.org",
    "angular.dev",
    "www.typescriptlang.org",
    "docs.aws.amazon.com",
    "www.postgresql.org",
    "www.sqlite.org",
    "redis.io",
    "docs.djangoproject.com",
    "flask.palletsprojects.com",
    "fastapi.tiangolo.com",
    "numpy.org",
    "pandas.pydata.org",
    "docs.pytest.org",
    "git-scm.com",
    "www.gnu.org",
    "man7.org",
    "docs.anthropic.com",
    "tailwindcss.com",
    "expressjs.com",
];

// Command patterns of the default rules (RE2 syntax, compiled with
// `rules::compile_regex`). Best effort, not a parser.

macro_rules! net_tools_re {
    () => {
        "curl|wget|scp|rsync|sftp|ftp|nc|ncat|socat|iwr|invoke-webrequest|invoke-restmethod"
    };
}
macro_rules! secret_shell_re {
    () => {
        r"(?:\.ssh[\\/]id_|\.aws[\\/]credentials|\.netrc|\.env\b|\.pem\b)"
    };
}

pub(crate) const PIPE_TO_SHELL_RE: &str = concat!(
    r#"(?i)\b(?:curl|wget|iwr|irm|invoke-webrequest|invoke-restmethod)\b[^|]*(?:\|[^|][^|]*)*?\|\s*(?:(?:sudo|doas|env)(?:\s+-\S+)*\s+)?(?:\S*/)?(?:sh|bash|zsh|dash|python3?|perl|ruby|node|iex|invoke-expression)\b"#,
    r#"|(?i)\b(?:sh|bash|zsh|dash)\s+(?:-c\s+)?["']?\$\(\s*(?:curl|wget)\b"#,
    r"|(?i)\b(?:sh|bash|zsh|dash)\s+<\(\s*(?:curl|wget)\b"
);
pub(crate) const GIT_FORCE_PUSH_RE: &str = r"\bgit\b[^;&|\n]*\bpush\b[^;&|\n]*(?:\s--force(?:-with-lease)?\b|\s-[a-zA-Z]*f[a-zA-Z]*(?:\s|$)|\s\+\S)";
pub(crate) const GIT_DISCARD_RE: &str = r"\bgit\b[^;&|\n]*(?:\breset\b[^;&|\n]*\s--hard\b|\bclean\b[^;&|\n]*\s(?:-[a-zA-Z]*f[a-zA-Z]*|--force)\b|\bcheckout\s+(?:--\s+)?\.(?:\s|$)|\bcheckout\b[^;&|\n]*\s--\s+\.|\brestore\b[^;&|\n]*\s\.(?:\s|$))";
pub(crate) const INFRA_DESTROY_RE: &str = r"\b(?:terraform|tofu|pulumi|cdk|terragrunt)\b[^;&|\n]*\bdestroy\b|\bkubectl\b[^;&|\n]*\bdelete\b|\bgh\s+repo\s+delete\b";
pub(crate) const PACKAGE_PUBLISH_RE: &str = r"\b(?:npm|pnpm|yarn)\s+(?:[^;&|\n]*\s)?publish(?:\s|$)|\bcargo\s+publish(?:\s|$)|\btwine\s+upload\b|\bgem\s+push\b";
pub(crate) const SUDO_RE: &str = r"(?:^|[^\w.-])(?:sudo|doas)\s+\S";
/// `ssh` with a destructive verb in the remote command: the verbs of the
/// `rm-root` and `disk-wipe` checks, power commands, and cluster and
/// infrastructure deletes, Linux and Windows (`ssh`, `autossh`, `ssh.exe`). The
/// verb may carry a path (`/bin/rm`) and `.exe`. It must start a word, so
/// `ssh rm@host ls`, `ssh host ls rmdir.txt` and `--format=rm` do not match;
/// `ssh-add` is not `ssh`. Known limit: a path that ends in a verb
/// (`ssh host cat /tmp/rm`) also asks.
pub(crate) const SSH_REMOTE_DESTRUCTIVE_RE: &str = concat!(
    r#"(?i)(?:^|[\s;&|(`'"/\\])(?:auto)?ssh(?:\.exe)?\s[^;&|\n]*[\s'"`;&|(/\\]+"#,
    r"(?:rm|rmdir|rd|del|erase|remove-item|ri|mkfs(?:\.\w+)?|dd|format(?:\.com)?|shutdown|reboot|poweroff|halt|shred|wipefs|stop-computer|restart-computer",
    r"|find\b[^;&|\n]*\s-delete|kubectl\b[^;&|\n]*\bdelete|(?:terraform|tofu)\b[^;&|\n]*\bdestroy)(?:\.exe)?",
    r#"(?:[\s'"`;&|)]|$)"#
);
/// `scp`, `rsync` or `sftp` of a whole secret directory (`~/.aws`, `~/.ssh/`,
/// `$HOME/.gnupg/*`) with a remote target after it: `host:`, `user@h:` (any
/// host length) or `[::1]:`. `secret-exfil` names files (`.aws/credentials`,
/// `id_rsa`), not directories. A `-i ~/.ssh/key` identity file is not a
/// directory, and a bare one-letter `h:` is taken for a drive. Known limit:
/// the regex has no lookbehind, so `--exclude .ssh` and `--exclude ~/.aws`
/// (with a space) are denied like a copy; `--exclude=.ssh` is not.
pub(crate) const SCP_HOME_SECRET_RE: &str = concat!(
    r#"(?i)\b(?:scp|rsync|sftp)(?:\.exe)?\s[^;&|\n]*[\s'"]"#,
    r"(?:~|\$home|\$\{home\}|%userprofile%|\$env:userprofile|[a-z]:[\\/]users[\\/][^\\/\s'\x22]+|/(?:home|users)/[^/\s'\x22]+|/root)?",
    r#"[\\/]?\.(?:ssh|aws|gnupg)(?:[\\/]\*?)?['"]?\s"#,
    r"[^;&|\n]*?(?:[\w.-]{2,}|@[\w.-]+|\]):"
);

/// Separators include _ - . so file names like IGNORE_PREVIOUS_INSTRUCTIONS match.
pub(crate) const INJECTION_RE: &str = concat!(
    r"(?i)ignore[\s_.-]+(?:(?:all|any)[\s_.-]+)?(?:previous|prior)[\s_.-]+instructions",
    r"|you[\s_.-]+are[\s_.-]+(?:now[\s_.-]+)?(?:(?:a|the)[\s_.-]+)?(?:security[\s_.-]+)?classifier",
    r"|(?:label|classify|mark|rate)[\s_.-]+(?:this|it|the)(?:[\s_.-]+call)?[\s_.-]+(?:as[\s_.-]+)?(?:allow|safe|benign)",
    r"|callguard\W+(?:allow|approve)|callguard-data"
);
/// A network tool and a common secret location in one command.
pub(crate) const SECRET_EXFIL_RE: &str = concat!(
    r"(?i)\b(?:",
    net_tools_re!(),
    r")\b[^;&\n]*",
    secret_shell_re!(),
    r"|(?i)",
    secret_shell_re!(),
    r"[^;&\n]*\b(?:",
    net_tools_re!(),
    r")\b"
);
