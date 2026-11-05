//! Rule parsing, the Claude-docs matching table, deny/ask on nah's calls and on
//! raw text, every allow condition with fake `NahResult`s, the lexer, the
//! dropped allow rules, paths, domains and MCP names.

use super::lexer;
use super::spec::{self, Spec};
use super::*;
use crate::nah::NahCall;
use crate::rules::CallInput;
use crate::schema::Facts;
use serde_json::value::RawValue;

const CWD: &str = "/w/p";

fn env() -> Env {
    Env {
        home: "/home/u".into(),
        windows: false,
        fold_case: false,
        host: false,
    }
}

fn call_in(tool: &str, input: &str, cwd: &str) -> Call {
    Call::new(
        CallInput {
            harness: "claude".into(),
            tool: tool.into(),
            input: Some(RawValue::from_string(input.into()).unwrap()),
            cwd: cwd.into(),
            project_dir: "/w/p".into(),
            ..Default::default()
        },
        &env(),
    )
}

fn call(tool: &str, input: &str) -> Call {
    call_in(tool, input, CWD)
}

fn bash(cmd: &str) -> Call {
    call("Bash", &serde_json::json!({ "command": cmd }).to_string())
}

fn set(deny: &[&str], ask: &[&str], allow: &[&str]) -> Permissions {
    let v = |l: &[&str]| l.iter().map(|s| (*s).to_owned()).collect();
    let p = policy::Permissions {
        deny: v(deny),
        ask: v(ask),
        allow: v(allow),
    };
    let (perms, warns) = Permissions::compile(&p, &env()).unwrap();
    assert!(warns.is_empty(), "{warns:?}");
    // No file system: a path resolves to itself.
    perms.with_resolver(Box::new(|e, p| Some(paths::to_posix(e, p))))
}

fn allow(rules: &[&str]) -> Permissions {
    set(&[], &[], rules)
}

fn deny(rules: &[&str]) -> Permissions {
    set(rules, &[], &[])
}

fn argv(a: &[&str]) -> Vec<String> {
    a.iter().map(|s| (*s).to_owned()).collect()
}

/// A complete answer of nah whose calls (all in `CWD`) are `calls`.
fn nah_of(calls: &[&[&str]]) -> NahResult {
    NahResult {
        verdict: NahVerdict::Delegate,
        rule: String::new(),
        reason: String::new(),
        coverage: "full".into(),
        facts: Some(Facts {
            source: "nah".into(),
            coverage: "full".into(),
            ..Default::default()
        }),
        warnings: Vec::new(),
        calls: calls
            .iter()
            .map(|a| NahCall {
                argv: Some(argv(a)),
                program: a[0].to_owned(),
                cwd: Some(CWD.into()),
                via: String::new(),
            })
            .collect(),
    }
}

fn spec_matches(rule: &str, command: &str) -> bool {
    let s = Spec::parse(rule).unwrap();
    let mut work = spec::WORK_LIMIT;
    s.matches(
        &spec::shell_words(command).unwrap(),
        Some(false),
        false,
        false,
        &mut work,
    )
}

// --- the table from Claude's documentation -------------------------------------

#[test]
fn claude_docs_wildcard_table() {
    let rows: &[(&str, &[&str], &[&str])] = &[
        (
            "npm run build",
            &["npm run build"],
            &["npm run build --watch"],
        ),
        (
            "npm run *",
            &["npm run build", "npm run test --watch", "npm run"],
            &["npm install"],
        ),
        (
            "git log * main",
            &[
                "git log --oneline main",
                "git log -5 main",
                "git log --output=<file> main",
            ],
            &["git log main", "git push origin main"],
        ),
        (
            "git * main",
            &[
                "git merge main",
                "git push origin main",
                "git -c core.fsmonitor=<script> diff main",
            ],
            &["git log"],
        ),
        (
            "* --version",
            &["node --version", "bash -c 'echo hi' --version"],
            &["node -v"],
        ),
        ("ls *", &["ls -la", "ls"], &["lsof"]),
        ("ls*", &["ls -la", "lsof", "ls"], &[]),
        ("* --help *", &["npm --help x"], &["npm --help"]),
    ];
    for (rule, yes, no) in rows {
        for c in *yes {
            assert!(spec_matches(rule, c), "{rule} should match {c}");
        }
        for c in *no {
            assert!(!spec_matches(rule, c), "{rule} should not match {c}");
        }
    }
}

#[test]
fn colon_star_is_a_trailing_wildcard_only() {
    assert!(spec_matches("ls:*", "ls -la") && spec_matches("ls:*", "ls"));
    assert!(!spec_matches("ls:*", "lsof"));
    // Elsewhere the colon is a literal character.
    assert!(!spec_matches("git:* push", "git commit push"));
    assert!(spec_matches("git:x", "git:x"));
}

#[test]
fn quotes_in_a_spec_group_words() {
    assert!(spec_matches(
        "git commit -m 'fix bug'",
        "git commit -m 'fix bug'"
    ));
    assert!(!spec_matches(
        "git commit -m 'fix bug'",
        "git commit -m fix"
    ));
    assert!(Spec::parse("git 'unclosed").is_err());
    assert!(Spec::parse("").is_err());
    assert!(Spec::parse("command:rm *").is_err());
}

// --- parsing -----------------------------------------------------------------------

#[test]
fn rule_forms() {
    for ok in [
        "Bash",
        "Bash(git push:*)",
        "PowerShell(Remove-Item *)",
        "Read(~/.ssh/**)",
        "Edit(src/**)",
        "Write(src/**)",
        "NotebookEdit(a.ipynb)",
        "Grep(src)",
        "Glob(*.rs)",
        "LS(.)",
        "WebFetch",
        "WebFetch(domain:example.com)",
        "WebSearch",
        "mcp__github",
        "mcp__github__create_issue",
        "mcp__github__*",
        "mcp__github__get_*",
        "Task",
        "Read",
        "terminal",
    ] {
        assert!(parse(ok).is_ok(), "{ok}: {:?}", parse(ok));
    }
    for bad in [
        "",
        "(x)",
        "Bash(git push",
        "Bash(command:rm *)",
        "Read(!x)",
        "WebFetch(example.com)",
        "WebSearch(x)",
        "mcp__x(y)",
        "mcp__*",
        "mcp__a*__b",
        "mcp__",
        "mcp__s__",
        "Agent(model:x)",
        "Tool(param:value)",
        "*",
        "B*",
    ] {
        assert!(parse(bad).is_err(), "{bad} should not parse");
    }
}

#[test]
fn a_deny_or_ask_rule_that_cannot_be_read_fails_the_policy() {
    for list in ["deny", "ask"] {
        let p: policy::Policy = serde_json::from_str(&format!(
            r#"{{"policy_version":1,"permissions":{{"{list}":["Bash(git push:*)","Agent(model:x)"]}}}}"#
        ))
        .unwrap();
        let problems = policy::validate(&p, false);
        assert_eq!(problems.len(), 1, "{problems:?}");
        assert!(
            problems[0].contains(&format!("permissions.{list}[1]")),
            "{problems:?}"
        );
        assert!(Permissions::compile(&p.permissions, &env()).is_err());
    }
    // An allow rule that cannot be read is dropped, not fatal.
    let p = policy::Permissions {
        allow: vec!["Agent(model:x)".into(), "Bash(ls)".into()],
        ..Default::default()
    };
    let (perms, warns) = Permissions::compile(&p, &env()).unwrap();
    assert_eq!(perms.allow.len(), 1);
    assert_eq!(warns.len(), 1, "{warns:?}");
}

// --- deny and ask ------------------------------------------------------------------

#[test]
fn deny_matches_normalised_calls() {
    let d = deny(&["Bash(git push:*)"]);
    let cases: &[(&str, &[&str])] = &[
        ("git push x", &["git", "push", "x"]),
        ("git -C /tmp push x", &["git", "-C", "/tmp", "push", "x"]),
        ("git -c a=b push x", &["git", "-c", "a=b", "push", "x"]),
        (
            "git --git-dir=/x --no-pager push",
            &["git", "--git-dir=/x", "--no-pager", "push"],
        ),
        (
            "git --git-dir /x -p push",
            &["git", "--git-dir", "/x", "-p", "push"],
        ),
        ("/usr/bin/git push x", &["/usr/bin/git", "push", "x"]),
        ("git.exe push", &["git.exe", "push"]),
        (
            "git --config-env a=b push origin main",
            &["git", "--config-env", "a=b", "push", "origin", "main"],
        ),
        (
            "git --super-prefix x push",
            &["git", "--super-prefix", "x", "push"],
        ),
        (
            "git --attr-source HEAD push",
            &["git", "--attr-source", "HEAD", "push"],
        ),
    ];
    for (cmd, a) in cases {
        let n = nah_of(&[a]);
        let h = d.check(&bash(cmd), Some(&n));
        assert_eq!(h.map(|h| h.decision), Some("deny"), "{cmd}");
    }
    // A command that is not git push is left alone.
    let n = nah_of(&[&["git", "status"]]);
    assert!(d.check(&bash("git status"), Some(&n)).is_none());
}

#[test]
fn a_complete_parse_means_no_raw_text_match() {
    let d = deny(&["Bash(git push:*)"]);
    let n = nah_of(&[&["echo", "git", "push"]]);
    assert!(d.check(&bash("echo git push"), Some(&n)).is_none());
}

#[test]
fn deny_falls_back_to_raw_text_when_the_parse_has_a_hole() {
    let d = deny(&["Bash(git push:*)", "Bash(rm:*)"]);
    let full = nah_of(&[&["true"]]);
    let partial = NahResult {
        coverage: "partial".into(),
        ..nah_of(&[&["true"]])
    };
    let gap = NahResult {
        facts: Some(Facts {
            gaps: vec!["limit exec".into()],
            ..Default::default()
        }),
        ..nah_of(&[&["true"]])
    };
    let unknown = NahResult {
        calls: vec![NahCall::default()],
        ..nah_of(&[])
    };
    let no_calls = nah_of(&[]);
    let raw = [
        "git push x",
        "git -C /tmp push x",
        "FOO=1 git push x",
        "sudo git push x",
        r#"bash -c "git push x""#,
        r#"bash -c 'bash -c "bash -c \"bash -c \\\"git push x\\\"\""'"#,
        "git 'push' x",
        "rm ~/x",
        r#"rm "$HOME/x""#,
        "xargs rm",
        "git status; rm x",
        "(git push)",
        "echo $(git push)",
        "{ git push; }",
        r"C:\tools\git.exe push",
    ];
    for hole in [
        None,
        Some(&partial),
        Some(&gap),
        Some(&unknown),
        Some(&no_calls),
    ] {
        for c in raw {
            let h = d.check(&bash(c), hole);
            assert_eq!(h.map(|h| h.decision), Some("deny"), "{c} / {hole:?}");
        }
        assert!(d.check(&bash("ls"), hole).is_none());
    }
    // A full parse does not look at the raw text.
    assert!(d.check(&bash("git push x"), Some(&full)).is_none());
    // The tool is not Bash: the hole is there by definition.
    let c = call("PowerShell", r#"{"command":"git push origin"}"#);
    assert!(d.check(&c, Some(&full)).is_some());
}

#[test]
fn ask_and_the_order_of_decisions() {
    let p = set(&["Bash(git push:*)"], &["Bash(git *)"], &[]);
    let n = nah_of(&[&["git", "push"]]);
    assert_eq!(
        p.check(&bash("git push"), Some(&n)).unwrap().decision,
        "deny"
    );
    let n = nah_of(&[&["git", "log"]]);
    let h = p.check(&bash("git log"), Some(&n)).unwrap();
    assert_eq!((h.decision, h.rule.as_str()), ("ask", "Bash(git *)"));
}

#[test]
fn bash_covers_the_shell_tools_and_powershell_only_its_own() {
    let d = deny(&["Bash(rm:*)", "PowerShell(del:*)"]);
    for tool in [
        "Bash",
        "bash",
        "terminal",
        "PowerShell",
        "execute_code",
        "process",
    ] {
        let c = call(tool, r#"{"command":"rm x"}"#);
        assert!(d.check(&c, None).is_some(), "{tool}");
    }
    let c = call("Bash", r#"{"command":"del x"}"#);
    assert!(d.check(&c, None).is_none());
    let c = call("PowerShell", r#"{"command":"del x"}"#);
    assert!(d.check(&c, None).is_some());
    let c = call("Read", r#"{"file_path":"/w/p/rm"}"#);
    assert!(d.check(&c, None).is_none());
}

#[test]
fn a_bare_bash_rule_matches_every_shell_call() {
    let d = deny(&["Bash"]);
    assert!(d.check(&bash("ls"), None).is_some());
    let d = deny(&["Bash(*)"]);
    assert!(d.check(&bash("ls"), None).is_some());
}

// --- allow: every condition ------------------------------------------------------

fn git_allow() -> Permissions {
    allow(&["Bash(git status:*)", "Bash(git log *)"])
}

#[test]
fn plain_commands_are_allowed() {
    let a = git_allow();
    for (cmd, argv_) in [
        ("git status", vec!["git", "status"]),
        ("git status --short", vec!["git", "status", "--short"]),
        (
            "git log --oneline -5",
            vec!["git", "log", "--oneline", "-5"],
        ),
        ("git status 2>/dev/null", vec!["git", "status"]),
        ("git status >/dev/null 2>&1", vec!["git", "status"]),
        ("git 'status'", vec!["git", "status"]),
    ] {
        let n = nah_of(&[&argv_]);
        let h = a
            .check(&bash(cmd), Some(&n))
            .unwrap_or_else(|| panic!("{cmd}"));
        assert_eq!(h.decision, "allow", "{cmd}");
        assert!(h.rule.starts_with("Bash(git "), "{cmd}: {}", h.rule);
    }
}

fn denied_by_allow(a: &Permissions, c: &Call, n: Option<&NahResult>) -> bool {
    a.check(c, n).is_none()
}

#[test]
fn an_allow_needs_a_real_complete_nah_answer() {
    let a = git_allow();
    let c = bash("git status");
    let ok = nah_of(&[&["git", "status"]]);
    assert!(a.check(&c, Some(&ok)).is_some());
    // No nah result: errored, disabled or shadowed block.
    assert!(denied_by_allow(&a, &c, None));
    // A block verdict.
    let blocked = NahResult {
        verdict: NahVerdict::Block,
        ..nah_of(&[&["git", "status"]])
    };
    assert!(denied_by_allow(&a, &c, Some(&blocked)));
    // Coverage other than full.
    for cov in ["partial", "none", "FULL", ""] {
        let n = NahResult {
            coverage: cov.into(),
            ..nah_of(&[&["git", "status"]])
        };
        assert!(denied_by_allow(&a, &c, Some(&n)), "{cov}");
    }
    // Gaps, or no facts at all.
    let gaps = NahResult {
        facts: Some(Facts {
            gaps: vec!["limit".into()],
            ..Default::default()
        }),
        ..nah_of(&[&["git", "status"]])
    };
    assert!(denied_by_allow(&a, &c, Some(&gaps)));
    let nofacts = NahResult {
        facts: None,
        ..nah_of(&[&["git", "status"]])
    };
    assert!(denied_by_allow(&a, &c, Some(&nofacts)));
    // No calls (an older reply, or a command nah dropped).
    assert!(denied_by_allow(&a, &c, Some(&nah_of(&[]))));
}

#[test]
fn every_call_needs_a_known_argv_and_a_matching_rule_and_the_cwd() {
    let a = git_allow();
    let c = bash("git status");
    // One call with an unknown argv.
    let mut n = nah_of(&[&["git", "status"]]);
    n.calls.push(NahCall::default());
    assert!(denied_by_allow(&a, &c, Some(&n)));
    // An empty argv counts as unknown.
    let mut n = nah_of(&[&["git", "status"]]);
    n.calls[0].argv = Some(Vec::new());
    assert!(denied_by_allow(&a, &c, Some(&n)));
    // A second call that no rule names.
    let n = nah_of(&[&["git", "status"], &["rm", "x"]]);
    assert!(denied_by_allow(&a, &c, Some(&n)));
    // Literal: the program is not normalised.
    for prog in ["./git", "/tmp/git", "/usr/bin/git", "GIT", "git.exe"] {
        let n = nah_of(&[&[prog, "status"]]);
        assert!(denied_by_allow(&a, &bash("git status"), Some(&n)), "{prog}");
    }
    // A cwd that differs, is unknown, or is empty.
    let mut n = nah_of(&[&["git", "status"]]);
    n.calls[0].cwd = Some("/elsewhere".into());
    assert!(denied_by_allow(&a, &c, Some(&n)));
    n.calls[0].cwd = None;
    assert!(denied_by_allow(&a, &c, Some(&n)));
    let mut n = nah_of(&[&["git", "status"]]);
    n.calls[0].cwd = Some("/w/p/".into()); // normalised
    assert!(a.check(&c, Some(&n)).is_some());
    let n = nah_of(&[&["git", "status"]]);
    assert!(denied_by_allow(
        &a,
        &call_in("Bash", r#"{"command":"git status"}"#, ""),
        Some(&n)
    ));
}

#[test]
fn several_commands_each_need_a_rule() {
    let a = allow(&["Bash(git status:*)", "Bash(echo hi)"]);
    let n = nah_of(&[&["git", "status"], &["echo", "hi"]]);
    assert!(a.check(&bash("git status && echo hi"), Some(&n)).is_some());
    let a = git_allow();
    assert!(denied_by_allow(
        &a,
        &bash("git status && echo hi"),
        Some(&n)
    ));
}

#[test]
fn the_lexer_has_a_veto() {
    let a = git_allow();
    // nah sees only `git status`; the raw command says more.
    let n = nah_of(&[&["git", "status"]]);
    for cmd in [
        "git status > /tmp/out",
        "git status >> ~/.bashrc",
        "FOO=1 git status",
        "GIT_SSH_COMMAND=evil git status",
        "git status &",
        "git status $X",
        "git status `rm x`",
        "git status $(rm x)",
        "git status <(rm x)",
        "git status | tee /tmp/x",
        "git status; rm x",
        "git status\nrm x",
        "cd /tmp && git status",
        "alias git=rm; git status",
        "git status # c",
        "git st*",
        "git status ~",
        "git status \\",
        "git(){ rm x; }; git status",
        "git status 'unbalanced",
        "git status \"$HOME\"",
        "git status && ",
        "git status;;",
        "(git status)",
        "{ git status; }",
        "git status |& cat",
    ] {
        assert!(denied_by_allow(&a, &bash(cmd), Some(&n)), "{cmd}");
    }
    // More than one spelling of the command: the harness may read the other.
    let c = call("Bash", r#"{"Command":"git status","command":"rm x"}"#);
    assert!(denied_by_allow(&a, &c, Some(&n)));
    // The same text twice is one spelling.
    let c = call("Bash", r#"{"Command":"git status","command":"git status"}"#);
    assert!(a.check(&c, Some(&n)).is_some());
}

#[test]
fn allow_matches_only_bash_bash_and_terminal() {
    let a = git_allow();
    let n = nah_of(&[&["git", "status"]]);
    for (tool, ok) in [
        ("Bash", true),
        ("bash", true),
        ("terminal", true),
        ("PowerShell", false),
        ("execute_code", false),
        ("process", false),
    ] {
        let c = call(tool, r#"{"command":"git status"}"#);
        assert_eq!(a.check(&c, Some(&n)).is_some(), ok, "{tool}");
    }
}

#[test]
fn deny_beats_ask_beats_allow() {
    let p = set(
        &["Bash(git status --short)"],
        &["Bash(git log *)"],
        &["Bash(git status:*)", "Bash(git log *)"],
    );
    let n = nah_of(&[&["git", "status", "--short"]]);
    assert_eq!(
        p.check(&bash("git status --short"), Some(&n))
            .unwrap()
            .decision,
        "deny"
    );
    let n = nah_of(&[&["git", "log"]]);
    assert_eq!(p.check(&bash("git log"), Some(&n)).unwrap().decision, "ask");
    let n = nah_of(&[&["git", "status"]]);
    assert_eq!(
        p.check(&bash("git status"), Some(&n)).unwrap().decision,
        "allow"
    );
}

// --- the lexer -------------------------------------------------------------------

#[test]
fn lexer_splits_and_refuses() {
    let segs = |c: &str| lexer::split(c);
    assert_eq!(segs("git status"), Some(vec![argv(&["git", "status"])]));
    assert_eq!(
        segs("a b && c || d | e ; f\ng"),
        Some(vec![
            argv(&["a", "b"]),
            argv(&["c"]),
            argv(&["d"]),
            argv(&["e"]),
            argv(&["f"]),
            argv(&["g"])
        ])
    );
    assert_eq!(
        segs("git 'a b' \"c d\" ''"),
        Some(vec![argv(&["git", "a b", "c d", ""])])
    );
    assert_eq!(segs("git status\n"), Some(vec![argv(&["git", "status"])]));
    assert_eq!(segs("a &&\n b"), Some(vec![argv(&["a"]), argv(&["b"])]));
    assert_eq!(segs("a\n\nb"), Some(vec![argv(&["a"]), argv(&["b"])]));
    assert_eq!(segs("a 2>/dev/null"), Some(vec![argv(&["a"])]));
    assert_eq!(segs("a >/dev/null 2>&1"), Some(vec![argv(&["a"])]));
    assert_eq!(segs("a '2>&1'"), Some(vec![argv(&["a", "2>&1"])]));
    assert_eq!(segs("a b=c"), Some(vec![argv(&["a", "b=c"])]));
    assert_eq!(
        segs("a --x=y 'q;r'"),
        Some(vec![argv(&["a", "--x=y", "q;r"])])
    );
    for bad in [
        "",
        "  ",
        "a $x",
        "a \"$x\"",
        "a `b`",
        "a \"`b`\"",
        "a <b",
        "a >b",
        "a >/dev/nullx",
        "a 2>&1x",
        "a (b)",
        "a {b}",
        "a & b",
        "a &",
        "a |& b",
        "a #c",
        "a *",
        "a ?",
        "a [x]",
        "a ~",
        "a !b",
        "a \\b",
        "\"a\\\"b\"",
        "a 'b",
        "a \"b",
        ";a",
        "a;;b",
        "a &&",
        "&& a",
        "a && && b",
        "x=1 a",
        "'x=1' a",
        "a\rb",
        "a\u{0}b",
        "a >&2",
        "a 2>/dev/null2",
    ] {
        assert_eq!(segs(bad), None, "{bad:?}");
    }
    // An assignment is only a problem in command position.
    assert!(segs("a; b=1").is_none());
}

// --- dropping allow rules ------------------------------------------------------------

fn vet(rule: &str, layer: Option<&str>) -> Result<(), String> {
    vet_allow(rule, layer).map(|_| ())
}

#[test]
fn blanket_and_open_ended_allows_are_dropped_in_every_layer() {
    for layer in [None, Some("system"), Some("user"), Some("project")] {
        for r in [
            "Bash",
            "Bash(*)",
            "Bash(:*)",
            "Bash(* --version)",
            "Bash(g*)",
            "Bash(ls*)",
            "PowerShell(Get-ChildItem)",
            "Read",
            "Edit",
            "Write",
            "Read(**)",
            "Edit(**)",
            "Edit(//**)",
            "Edit(~/**)",
            "Edit(/**)",
            "Edit(./**)",
            "Edit(*)",
            "Edit(**/*)",
            "WebFetch",
            "WebFetch(domain:*)",
            "WebFetch(domain:*.*)",
            "mcp__*",
            "*",
            "terminal",
            "bash",
            "Read(!x)",
            "Bash(python:*)",
            "Bash(python3 *)",
            "Bash(bash -c *)",
            "Bash(/bin/sh -c *)",
            "Bash(C:\\Windows\\cmd.exe /c *)",
            "Bash(env *)",
            "Bash(sudo:*)",
            "Bash(xargs *)",
            "Bash(find . -exec *)",
            "Bash(curl *)",
            "Bash(ssh *)",
            "Bash(npx *)",
            "Bash(awk *)",
            "Bash(sed -i *)",
            "Bash(git:*)",
            "Bash(git *)",
            "Bash(git * main)",
            "Bash(git s*)",
            "Bash(gh *)",
            "Bash(docker *)",
            "Bash(podman:*)",
            "Bash(kubectl *)",
            "Bash(npm *)",
            "Bash(yarn:*)",
            "Bash(pnpm *)",
            "Bash(cargo:*)",
            "Bash(go *)",
        ] {
            assert!(vet(r, layer).is_err(), "{r} in {layer:?} should be dropped");
        }
        for r in [
            "Bash(git log *)",
            "Bash(git status:*)",
            "Bash(python tools/check.py)",
            "Bash(npm run build)",
            "Bash(ls *)",
            "Bash(sh)",
            "Read(src/**)",
            "Edit(src/**)",
            "Write(docs/*.md)",
            "Edit(/docs/**)",
            "Edit(./.env.example)",
        ] {
            assert!(
                vet(r, layer).is_ok(),
                "{r} in {layer:?}: {:?}",
                vet(r, layer)
            );
        }
    }
}

#[test]
fn a_trusted_project_is_vetted_like_the_user_layer() {
    // Fine for a user and for a trusted project alike.
    for r in [
        "WebFetch(domain:docs.rs)",
        "mcp__github__get_*",
        "mcp__github",
        "WebSearch",
        "Bash(pytest:*)",
        "Bash(make test)",
        "Bash(./scripts/check.sh *)",
        "Bash(/usr/bin/true)",
        "Read(//etc/hostname)",
        "Read(~/notes/**)",
        "Read(../other/**)",
        "Bash(npm test)",
        "Bash(cargo test *)",
        "Bash(uv sync *)",
        "Bash(pytest -k *)",
        "Bash(npm run build)",
        "Bash(cargo run --release)",
    ] {
        for layer in ["user", "project"] {
            assert!(
                vet(r, Some(layer)).is_ok(),
                "{r} in {layer}: {:?}",
                vet(r, Some(layer))
            );
        }
    }
}

#[test]
fn hook_policy_and_vcs_directories_are_never_pre_approved_below_the_system_layer() {
    for r in [
        "Edit(.git/hooks/*)",
        "Edit(.claude/**)",
        "Edit(/.callguard/policy.json)",
        "Write(.hermes/config.yaml)",
        "Edit(//home/u/.opencode/**)",
        "Edit(**/.pi/**)",
    ] {
        for layer in ["user", "project"] {
            assert!(vet(r, Some(layer)).is_err(), "{r} in {layer}");
        }
        assert!(
            vet(r, Some("system")).is_ok(),
            "{r}: the system layer keeps its authority"
        );
        assert!(vet(r, None).is_ok(), "{r}");
    }
}

#[test]
fn agents_monitors_and_package_manager_runs_are_never_honoured() {
    for layer in [None, Some("system"), Some("user"), Some("project")] {
        for r in [
            "Agent",
            "Task",
            "task",
            "Monitor",
            "Agent(x)",
            "Task(y)",
            "Monitor(z)",
            "Bash(npm run *)",
            "Bash(npm run:*)",
            "Bash(npm exec *)",
            "Bash(yarn run *)",
            "Bash(pnpm run *)",
            "Bash(pnpm exec *)",
            "Bash(pnpm dlx *)",
            "Bash(bun run *)",
            "Bash(bun x *)",
            "Bash(yarn dlx *)",
            "Bash(cargo run *)",
            "Bash(go run *)",
            "Bash(uv run *)",
            "Bash(poetry run *)",
            "Bash(pipenv run *)",
            "Bash(dotnet run *)",
            "Bash(npm run test*)",
            "Bash(npm run build *)",
            "Bash(cargo run:*)",
        ] {
            assert!(vet(r, layer).is_err(), "{r} in {layer:?}");
        }
        for r in [
            "Bash(npm run build)",
            "Bash(npm test)",
            "Bash(cargo run --release)",
            "Bash(go test ./...)",
        ] {
            assert!(vet(r, layer).is_ok(), "{r} in {layer:?}");
        }
    }
}

#[test]
fn the_dropped_rule_is_named_in_a_warning() {
    let (kept, warns) = vet_allow_list(
        &["Bash(*)".into(), "Bash(ls *)".into(), "Agent(x:y)".into()],
        "user",
        "u.json",
    );
    assert_eq!(kept, ["Bash(ls *)"]);
    assert_eq!(warns.len(), 2, "{warns:?}");
    assert!(
        warns[0].contains("u.json") && warns[0].contains("\"Bash(*)\""),
        "{warns:?}"
    );
    assert!(warns[1].contains("Agent(x:y)"), "{warns:?}");
}

// --- paths -----------------------------------------------------------------------

fn read(p: &str) -> Call {
    call("Read", &serde_json::json!({ "file_path": p }).to_string())
}

fn edit(p: &str) -> Call {
    call("Edit", &serde_json::json!({ "file_path": p }).to_string())
}

fn hit(p: &Permissions, c: &Call) -> Option<&'static str> {
    p.check(c, None).map(|h| h.decision)
}

#[test]
fn path_anchors() {
    let d = deny(&[
        "Read(//etc/passwd)",
        "Read(~/.ssh/**)",
        "Read(/secrets/**)",
        "Read(./local.txt)",
    ]);
    assert_eq!(hit(&d, &read("/etc/passwd")), Some("deny"));
    assert_eq!(hit(&d, &read("/home/u/.ssh/id_rsa")), Some("deny"));
    assert_eq!(hit(&d, &read("/home/u/.ssh")), Some("deny"));
    assert_eq!(hit(&d, &read("/home/u/.sshx/id")), None);
    // `/x` is the project directory, in every layer.
    assert_eq!(hit(&d, &read("/w/p/secrets/a")), Some("deny"));
    assert_eq!(hit(&d, &read("/w/p/sub/secrets/a")), None);
    assert_eq!(hit(&d, &read("/secrets/a")), None);
    // `./x` is the working directory.
    assert_eq!(hit(&d, &read("local.txt")), Some("deny"));
    assert_eq!(hit(&d, &read("/w/p/local.txt")), Some("deny"));
    assert_eq!(hit(&d, &read("/w/p/sub/local.txt")), None);
    let c = call_in("Read", r#"{"file_path":"/w/p/local.txt"}"#, "/w/p/sub");
    assert_eq!(hit(&d, &c), None, "cwd is the anchor, not the project");
}

#[test]
fn bare_names_and_single_directory_patterns() {
    // A bare name matches at any depth, in every rule type.
    let d = deny(&["Read(.env)", "Read(*.pem)"]);
    assert_eq!(hit(&d, &read("/w/p/.env")), Some("deny"));
    assert_eq!(hit(&d, &read("/w/p/a/b/.env")), Some("deny"));
    assert_eq!(hit(&d, &read("/w/.env")), None);
    assert_eq!(hit(&d, &read("/w/p/a/k.pem")), Some("deny"));
    let a = allow(&["Read(.env.example)"]);
    assert_eq!(hit(&a, &read("/w/p/a/.env.example")), Some("allow"));

    // `src/**`: allow is the one directory, deny and ask any depth.
    let a = allow(&["Edit(src/**)"]);
    assert_eq!(hit(&a, &edit("/w/p/src/a.rs")), Some("allow"));
    assert_eq!(hit(&a, &edit("/w/p/src/x/a.rs")), Some("allow"));
    assert_eq!(hit(&a, &edit("/w/p/vendor/pkg/src/lib.rs")), None);
    let d = deny(&["Edit(src/**)"]);
    assert_eq!(hit(&d, &edit("/w/p/src/a.rs")), Some("deny"));
    assert_eq!(hit(&d, &edit("/w/p/vendor/pkg/src/lib.rs")), Some("deny"));
    let k = set(&[], &["Edit(src/**)"], &[]);
    assert_eq!(hit(&k, &edit("/w/p/vendor/pkg/src/lib.rs")), Some("ask"));
    for ty in [allow(&["Edit(/src/**)"]), deny(&["Edit(/src/**)"])] {
        assert!(hit(&ty, &edit("/w/p/src/app.ts")).is_some());
        assert!(hit(&ty, &edit("/w/p/vendor/pkg/src/lib.js")).is_none());
    }
    for ty in [allow(&["Edit(**/src/**)"]), deny(&["Edit(**/src/**)"])] {
        assert!(hit(&ty, &edit("/w/p/src/app.ts")).is_some());
        assert!(hit(&ty, &edit("/w/p/vendor/pkg/src/lib.js")).is_some());
    }
    // `./src/**` is anchored in every rule type.
    let d = deny(&["Edit(./src/**)"]);
    assert_eq!(hit(&d, &edit("/w/p/vendor/pkg/src/lib.rs")), None);
    // Single `*` stays inside a segment; `**` crosses.
    let d = deny(&["Read(/a/*/c.txt)", "Read(/x/**/y.txt)"]);
    assert_eq!(hit(&d, &read("/w/p/a/b/c.txt")), Some("deny"));
    assert_eq!(hit(&d, &read("/w/p/a/b/b/c.txt")), None);
    assert_eq!(hit(&d, &read("/w/p/x/y.txt")), Some("deny"));
    assert_eq!(hit(&d, &read("/w/p/x/1/2/y.txt")), Some("deny"));
}

#[test]
fn path_rules_use_the_kind_of_the_tool() {
    let d = deny(&["Read(/s/**)"]);
    for tool in [
        "Read",
        "Grep",
        "Glob",
        "LS",
        "read",
        "grep",
        "glob",
        "list",
        "read_file",
    ] {
        let c = call(tool, r#"{"path":"/w/p/s/a"}"#);
        assert_eq!(hit(&d, &c), Some("deny"), "{tool}");
    }
    let c = call("Edit", r#"{"file_path":"/w/p/s/a"}"#);
    assert_eq!(hit(&d, &c), None);
    let d = deny(&["Write(/s/**)", "NotebookEdit(/n/**)"]);
    for tool in [
        "Edit",
        "Write",
        "MultiEdit",
        "NotebookEdit",
        "write",
        "edit",
        "write_file",
    ] {
        let c = call(
            tool,
            r#"{"file_path":"/w/p/s/a","notebook_path":"/w/p/n/a"}"#,
        );
        assert_eq!(hit(&d, &c), Some("deny"), "{tool}");
    }
    // A bare rule matches the kind, with or without a path (opencode patch).
    let d = deny(&["Edit"]);
    assert_eq!(
        hit(&d, &call("patch", r#"{"patchText":"..."}"#)),
        Some("deny")
    );
    // A path rule does not match a call with no path.
    let d = deny(&["Edit(/s/**)"]);
    assert_eq!(hit(&d, &call("patch", r#"{"patchText":"/w/p/s/a"}"#)), None);
}

#[test]
fn deny_looks_at_every_path_value_allow_at_one() {
    let d = deny(&["Read(/s/**)"]);
    let c = call("Read", r#"{"file_path":"/w/p/ok","path":"/w/p/s/a"}"#);
    assert_eq!(hit(&d, &c), Some("deny"));
    let c = call("Read", r#"{"file_path":"/w/p/ok","FILE_PATH":"/w/p/s/a"}"#);
    assert_eq!(hit(&d, &c), Some("deny"));
    let a = allow(&["Read(/ok/**)"]);
    let c = call("Read", r#"{"file_path":"/w/p/ok/a","path":"/w/p/ok/b"}"#);
    assert_eq!(hit(&a, &c), None, "two distinct values");
    let c = call(
        "Read",
        r#"{"file_path":"/w/p/ok/a","FILE_PATH":"/w/p/ok/b"}"#,
    );
    assert_eq!(hit(&a, &c), None, "two letter cases");
    let c = call("Read", r#"{"file_path":"/w/p/ok/a","path":"/w/p/ok/a"}"#);
    assert_eq!(hit(&a, &c), Some("allow"), "the same value twice is one");
}

#[test]
fn a_read_tools_pattern_cannot_leave_the_allowed_path() {
    let a = allow(&["Read(/ok/**)"]);
    for pat in ["/etc/*", "~/.ssh/*", "../*", "a/../../b", "C:/x", "\\\\x"] {
        let c = call(
            "Glob",
            &serde_json::json!({"path":"/w/p/ok","pattern":pat}).to_string(),
        );
        assert_eq!(hit(&a, &c), None, "{pat}");
        let c = call(
            "Grep",
            &serde_json::json!({"path":"/w/p/ok","glob":pat}).to_string(),
        );
        assert_eq!(hit(&a, &c), None, "{pat}");
    }
    let c = call("Glob", r#"{"path":"/w/p/ok","pattern":"**/*.rs"}"#);
    assert_eq!(hit(&a, &c), Some("allow"));
}

#[test]
fn deny_and_ask_see_a_read_tools_pattern_prefix() {
    let d = set(&["Read(~/.ssh/**)"], &["Read(/private/**)"], &[]);
    for (tool, input, want) in [
        ("Glob", r#"{"pattern":"~/.ssh/*"}"#, Some("deny")),
        ("Glob", r#"{"pattern":"/home/u/.ssh/id_*"}"#, Some("deny")),
        ("Grep", r#"{"pattern":"x","glob":"/home/u/.ssh/**"}"#, Some("deny")),
        ("Glob", r#"{"pattern":"private/**/*.md"}"#, Some("ask")),
        ("Glob", r#"{"pattern":"src/**/*.rs"}"#, None),
        ("Glob", r#"{"pattern":"/home/u/*"}"#, None),
    ] {
        assert_eq!(hit(&d, &call(tool, input)), want, "{input}");
    }
}

#[test]
fn symlinks_deny_on_either_path_allow_on_both() {
    let resolver: Resolver = Box::new(|_, p| {
        Some(if p == "/w/p/src/key" {
            "/home/u/.ssh/id_rsa".to_owned()
        } else if p == "/w/p/src/gone" {
            return None;
        } else {
            p.to_owned()
        })
    });
    let p =
        set(&["Read(~/.ssh/**)"], &[], &["Edit(src/**)", "Read(src/**)"]).with_resolver(resolver);
    // The link sits in src/ and points at ~/.ssh: the deny sees the target.
    assert_eq!(hit(&p, &read("/w/p/src/key")), Some("deny"));
    // An allow for src/** does not cover it.
    let p2 = set(&[], &[], &["Edit(src/**)", "Read(src/**)"]).with_resolver(Box::new(|_, p| {
        Some(if p == "/w/p/src/key" {
            "/home/u/.ssh/id_rsa".to_owned()
        } else {
            p.to_owned()
        })
    }));
    assert_eq!(hit(&p2, &edit("/w/p/src/key")), None);
    assert_eq!(hit(&p2, &edit("/w/p/src/ok")), Some("allow"));
    // Resolution failing is no allow.
    let p3 = set(&[], &[], &["Edit(src/**)"]).with_resolver(Box::new(|_, _| None));
    assert_eq!(hit(&p3, &edit("/w/p/src/ok")), None);
    let _ = p;
}

#[cfg(unix)]
#[test]
fn a_real_symlink_is_resolved() {
    let d = tempfile::tempdir().unwrap();
    let root = std::fs::canonicalize(d.path()).unwrap();
    let (proj, secret) = (root.join("proj"), root.join("secret"));
    std::fs::create_dir_all(proj.join("src")).unwrap();
    std::fs::create_dir_all(&secret).unwrap();
    std::fs::write(secret.join("k"), "x").unwrap();
    std::os::unix::fs::symlink(&secret, proj.join("src/link")).unwrap();
    let e = Env {
        home: root.to_string_lossy().into_owned(),
        windows: false,
        fold_case: false,
        host: true,
    };
    let p = policy::Permissions {
        deny: vec![format!(
            "Read(//{}/secret/**)",
            root.to_string_lossy().trim_start_matches('/')
        )],
        allow: vec!["Read(src/**)".into(), "Edit(src/**)".into()],
        ..Default::default()
    };
    let (perms, w) = Permissions::compile(&p, &e).unwrap();
    assert!(w.is_empty());
    let cwd = proj.to_string_lossy().into_owned();
    let mk = |tool: &str, path: &str| {
        Call::new(
            CallInput {
                tool: tool.into(),
                input: Some(
                    RawValue::from_string(serde_json::json!({"file_path": path}).to_string())
                        .unwrap(),
                ),
                cwd: cwd.clone(),
                project_dir: cwd.clone(),
                ..Default::default()
            },
            &e,
        )
    };
    assert_eq!(hit(&perms, &mk("Read", "src/link/k")), Some("deny"));
    assert_eq!(
        hit(&perms, &mk("Edit", "src/link/k")),
        None,
        "the target is outside src/"
    );
    assert_eq!(
        hit(&perms, &mk("Edit", "src/new.rs")),
        Some("allow"),
        "a new file resolves by its parent"
    );
    std::fs::write(proj.join("src/real"), "x").unwrap();
    assert_eq!(hit(&perms, &mk("Read", "src/real")), Some("allow"));
}

#[test]
fn windows_paths_match_in_posix_form() {
    let e = Env {
        home: "C:\\Users\\u".into(),
        windows: true,
        fold_case: false,
        host: false,
    };
    let to = |p: &str| paths::to_posix(&e, &e.normalize(p, ""));
    assert_eq!(to("C:\\Users\\u\\.ssh"), "/c/Users/u/.ssh");
    let ctx = Ctx {
        home: paths::dir_posix(&e, &e.home).unwrap(),
        cwd: paths::dir_posix(&e, "C:\\w\\p"),
        project: paths::dir_posix(&e, "C:\\w\\p"),
        caseless: true,
    };
    for (rule, path, want) in [
        ("//c/Users/**", "c:\\users\\u\\x", true),
        ("~/.ssh/**", "C:\\USERS\\U\\.SSH\\id_rsa", true),
        ("//**/.env", "D:\\any\\where\\.env", true),
        ("//c/**/.env", "D:\\any\\.env", false),
        ("src/**", "C:\\w\\p\\SRC\\a.rs", true),
        ("/src/**", "C:\\w\\p\\src\\a.rs", true),
    ] {
        let s = PathSpec::parse(rule).unwrap();
        assert_eq!(s.matches(&to(path), &ctx, false), want, "{rule} / {path}");
    }
    assert!(paths::is_network(&e, "\\\\server\\share\\x"));
    assert!(!paths::is_network(&e, "C:\\x"));
}

#[test]
fn a_network_path_is_never_allowed() {
    let e = Env {
        home: "C:\\Users\\u".into(),
        windows: true,
        fold_case: false,
        host: false,
    };
    let p = policy::Permissions {
        allow: vec![
            "Read(//**/share/**)".into(),
            "Read(//server/share/**)".into(),
        ],
        ..Default::default()
    };
    let (perms, _) = Permissions::compile(&p, &e).unwrap();
    let perms = perms.with_resolver(Box::new(|e, p| Some(paths::to_posix(e, p))));
    // `Read(//**/share/**)` is not blanket, and would match: the network
    // check stops it.
    let c = Call::new(
        CallInput {
            tool: "Read".into(),
            input: Some(
                RawValue::from_string(r#"{"file_path":"\\\\server\\share\\x"}"#.into()).unwrap(),
            ),
            cwd: "C:\\w\\p".into(),
            project_dir: "C:\\w\\p".into(),
            ..Default::default()
        },
        &e,
    );
    assert!(perms.check(&c, None).is_none());
}

// --- WebFetch ---------------------------------------------------------------------

fn fetch(url: &str) -> Call {
    call("WebFetch", &serde_json::json!({ "url": url }).to_string())
}

#[test]
fn domain_patterns() {
    let m = |pat: &str, host: &str| {
        Domain::parse(&format!("domain:{pat}"))
            .unwrap()
            .matches(host)
    };
    assert!(m("example.com", "example.com"));
    assert!(m("example.com", "EXAMPLE.com."));
    assert!(m("example.com.", "example.com"));
    assert!(!m("example.com", "api.example.com"));
    assert!(!m("example.com", "notexample.com"));
    assert!(m("*.example.com", "api.example.com"));
    assert!(m("*.example.com", "a.b.example.com"));
    assert!(!m("*.example.com", "example.com"));
    assert!(!m("*.example.com", "evilexample.com"));
    assert!(m("example.*", "example.org"));
    assert!(!m("example.*", "example.evil.com"));
    assert!(m("api.*.example.com", "api.eu.example.com"));
    assert!(!m("api.*.example.com", "api.a.b.example.com"));
    assert!(m("ex*.com", "example.com"));
    assert!(!m("ex*.com", "ex.a.com"));
    assert!(m("*", "anything.at.all"));
    assert!(Domain::parse("domain:").is_err());
    assert!(Domain::parse("example.com").is_err());
    assert!(Domain::parse("domain:a b").is_err());
}

#[test]
fn hosts_are_read_the_way_a_browser_would_or_not_at_all() {
    for (url, host) in [
        ("https://example.com/x?y#z", "example.com"),
        ("HTTP://Example.COM:8080/", "example.com"),
        ("https://example.com.", "example.com"),
        ("https://sub.example.com", "sub.example.com"),
    ] {
        assert_eq!(web::strict_host(url).as_deref(), Some(host), "{url}");
    }
    for url in [
        "https://example.com@evil.com/",
        "https://evil.com\\@example.com/",
        "https://user:pw@example.com/",
        "https://example.com\\x",
        "https://exa mple.com",
        "https://example.com:80a/",
        "https://[::1]/",
        "https://exämple.com",
        "ftp://example.com",
        "example.com/x",
        "//example.com/x",
        "https://",
        "https://a..b/",
        "https://example.com\t.evil.com",
        "https:///example.com",
    ] {
        assert_eq!(web::strict_host(url), None, "{url}");
    }
    let c = web::candidate_hosts("https://example.com@evil.com/");
    assert!(
        c.contains(&"evil.com".into()) && c.contains(&"example.com".into()),
        "{c:?}"
    );
    let c = web::candidate_hosts("https://evil.com\\@example.com/");
    assert!(
        c.contains(&"evil.com".into()) && c.contains(&"example.com".into()),
        "{c:?}"
    );
    let c = web::candidate_hosts("https://ev\til.com/");
    assert!(c.contains(&"evil.com".into()), "{c:?}");
    assert!(web::candidate_hosts("evil.com/x").contains(&"evil.com".into()));
}

#[test]
fn webfetch_rules() {
    let a = allow(&[
        "WebFetch(domain:docs.rs)",
        "WebFetch(domain:*.rust-lang.org)",
    ]);
    assert_eq!(hit(&a, &fetch("https://docs.rs/x")), Some("allow"));
    assert_eq!(
        hit(&a, &fetch("https://doc.rust-lang.org/std")),
        Some("allow")
    );
    assert_eq!(hit(&a, &fetch("https://rust-lang.org/")), None);
    assert_eq!(hit(&a, &fetch("https://docs.rs@evil.com/")), None);
    assert_eq!(hit(&a, &fetch("https://evil.com\\@docs.rs/")), None);
    assert_eq!(hit(&a, &fetch("not a url")), None);
    // Two distinct URLs: no allow; one URL twice is one.
    {
        let tool = "web_extract";
        let c = call(
            tool,
            r#"{"urls":["https://docs.rs/a","https://evil.com/"]}"#,
        );
        assert_eq!(hit(&a, &c), None);
        let c = call(
            tool,
            r#"{"urls":["https://docs.rs/a","https://docs.rs/a"]}"#,
        );
        assert_eq!(hit(&a, &c), Some("allow"));
    }
    let c = call(
        "WebFetch",
        r#"{"url":"https://docs.rs/a","URL":"https://evil.com/"}"#,
    );
    assert_eq!(hit(&a, &c), None);
    // Deny and ask see every candidate host and every URL.
    let d = deny(&["WebFetch(domain:evil.com)"]);
    assert_eq!(hit(&d, &fetch("https://evil.com/x")), Some("deny"));
    assert_eq!(
        hit(&d, &fetch("https://example.com@evil.com/")),
        Some("deny")
    );
    assert_eq!(
        hit(&d, &fetch("https://evil.com\\@example.com/")),
        Some("deny")
    );
    assert_eq!(hit(&d, &fetch("https://example.com/")), None);
    let c = call(
        "webfetch",
        r#"{"url":"https://a.com","urls":["https://evil.com"]}"#,
    );
    assert_eq!(hit(&d, &c), Some("deny"));
    // A call with no URL at all is matched by a deny or ask domain rule.
    assert_eq!(hit(&d, &call("WebFetch", "{}")), Some("deny"));
    // Bare rules.
    let d = deny(&["WebFetch", "WebSearch"]);
    for t in [
        "WebFetch",
        "webfetch",
        "web_extract",
        "WebSearch",
        "websearch",
        "web_search",
    ] {
        assert_eq!(hit(&d, &call(t, "{}")), Some("deny"), "{t}");
    }
    assert_eq!(hit(&d, &call("Read", r#"{"file_path":"/a"}"#)), None);
}

// --- MCP and other tools -----------------------------------------------------------

#[test]
fn mcp_names() {
    let tool = |t: &str| call(t, "{}");
    let d = deny(&["mcp__github"]);
    assert!(hit(&d, &tool("mcp__github__create_issue")).is_some());
    assert!(hit(&d, &tool("mcp__github2__create_issue")).is_none());
    assert!(hit(&d, &tool("mcp__gitlab__x")).is_none());
    let d = deny(&["mcp__github__*"]);
    assert!(hit(&d, &tool("mcp__github__anything")).is_some());
    let d = deny(&["mcp__github__get_*"]);
    assert!(hit(&d, &tool("mcp__github__get_issue")).is_some());
    assert!(hit(&d, &tool("mcp__github__put_issue")).is_none());
    let d = deny(&["mcp__github__create_issue"]);
    assert!(hit(&d, &tool("mcp__github__create_issue")).is_some());
    assert!(hit(&d, &tool("mcp__github__create_issue2")).is_none());
    let a = allow(&["mcp__github__get_*"]);
    assert_eq!(hit(&a, &tool("mcp__github__get_issue")), Some("allow"));
}

#[test]
fn other_bare_names_match_the_tool_exactly() {
    let d = deny(&["Task", "bash"]);
    assert!(hit(&d, &call("Task", "{}")).is_some());
    assert!(hit(&d, &call("task", "{}")).is_none());
    assert!(hit(&d, &call("bash", r#"{"command":"ls"}"#)).is_some());
    let a = allow(&["Skill"]);
    assert_eq!(hit(&a, &call("Skill", "{}")), Some("allow"));
}

// --- the raw-text fallback in itself ---------------------------------------------

#[test]
fn raw_fallback_tokens() {
    let m = |rule: &str, cmd: &str| spec::matches_raw(&Spec::parse(rule).unwrap(), cmd, false);
    assert!(m("git push:*", "git push"));
    assert!(m("git push:*", "echo hi && /usr/bin/git push -f"));
    assert!(m("git push:*", "x=1 git push"));
    assert!(m("git push:*", "bash -c \"git -C /a push\""));
    assert!(
        m("git push", "git push origin"),
        "consecutive tokens, not exact"
    );
    assert!(!m("git push:*", "git pushx"));
    assert!(!m("git push:*", "git status"));
    assert!(m("rm:*", "xargs rm -rf"));
    assert!(m("* --version", "node --version"));
    assert!(!m("git push:*", "git"));
}

#[test]
fn runaway_matching_counts_as_a_match_for_deny_and_not_for_allow() {
    // Many wildcards over a long argv: the step budget runs out.
    let rule = Spec::parse("a * * * * * * z").unwrap();
    let args: Vec<String> = std::iter::repeat_n("a".to_owned(), 400).collect();
    let mut work = 2_000;
    assert!(rule.matches(&args, None, false, true, &mut work));
    let mut work = 2_000;
    assert!(!rule.matches(&args, None, false, false, &mut work));
}

// --- found by review ---------------------------------------------------------------

#[test]
fn a_final_glob_word_does_not_swallow_the_rest_of_an_allowed_command() {
    let a = allow(&["Bash(cat docs/*.md)"]);
    let n = nah_of(&[&["cat", "docs/a.md", "/etc/shadow"]]);
    assert!(
        a.check(&bash("cat docs/a.md /etc/shadow"), Some(&n))
            .is_none()
    );
    let n = nah_of(&[&["cat", "docs/a.md"]]);
    assert!(a.check(&bash("cat docs/a.md"), Some(&n)).is_some());
}

#[test]
fn a_wildcard_may_not_hide_the_subcommand() {
    for r in [
        "Bash(git --no-pager *)",
        "Bash(git -C . *)",
        "Bash(npm --silent *)",
        "Bash(cargo +nightly *)",
        "Bash(git -c * status)",
        "Edit(//?*/**)",
        "Edit(?*)",
        "Edit(**/?*)",
        "WebFetch(domain:*.**)",
        "WebFetch(domain:**)",
    ] {
        assert!(vet(r, Some("user")).is_err(), "{r}");
    }
    for r in [
        "Edit(.git/hooks/*)",
        "Edit(.claude/**)",
        "Edit(/.callguard/policy.json)",
    ] {
        assert!(vet(r, Some("project")).is_err(), "{r}");
    }
}

#[test]
fn deny_sees_git_through_unlisted_options_and_windows_script_names() {
    let d = deny(&["Bash(git push:*)", "Bash(npm publish:*)"]);
    let n = nah_of(&[&["git", "--no-optional-locks", "push"]]);
    assert!(d.check(&bash("x"), Some(&n)).is_some());
    let n = nah_of(&[&["npm.cmd", "publish"]]);
    assert!(d.check(&bash("x"), Some(&n)).is_some());
}

// --- follow-up -----------------------------------------------------------------------

#[test]
fn versioned_and_alias_programs_are_open_ended_too() {
    for r in [
        "Bash(python3.12 *)",
        "Bash(python3 *)",
        "Bash(node22 *)",
        "Bash(ruby3.3 *)",
        "Bash(perl5.36 *)",
        "Bash(php8.2 *)",
        "Bash(lua5.4 *)",
        "Bash(pypy3 *)",
        "Bash(/usr/bin/Python3.11 -m *)",
        "Bash(nodejs *)",
        "Bash(tsx *)",
        "Bash(ts-node *)",
        "Bash(uvx *)",
        "Bash(bunx *)",
        "Bash(pipx run *)",
        "Bash(pnpx *)",
        "Bash(yarnpkg *)",
    ] {
        for layer in ["user", "project"] {
            assert!(vet(r, Some(layer)).is_err(), "{r} in {layer}");
        }
    }
    assert!(vet("Bash(python3.12 tools/check.py)", Some("user")).is_ok());
}

#[test]
fn drive_paths_in_specs_are_refused_with_the_posix_form() {
    for r in ["Read(C:/x/**)", r"Read(c:\x\**)", "Edit(//C:/x/**)"] {
        let e = parse(r).unwrap_err();
        assert!(e.contains("//c/x"), "{r}: {e}");
        assert!(vet(r, Some("user")).is_err(), "{r}");
    }
    let p: policy::Policy =
        serde_json::from_str(r#"{"policy_version":1,"permissions":{"deny":["Read(C:/x/**)"]}}"#)
            .unwrap();
    assert!(policy::validate(&p, false)[0].contains("//c/x"));
    assert!(parse("Read(//c/x/**)").is_ok());
}

#[test]
fn a_brace_in_a_read_pattern_gets_no_allow() {
    let a = allow(&["Read(/ok/**)"]);
    let c = call("Glob", r#"{"path":"/w/p/ok","pattern":"{/etc,x}/*"}"#);
    assert_eq!(hit(&a, &c), None);
}

#[test]
fn an_mcp_allow_skips_names_that_could_be_another_server() {
    let tool = |t: &str| call(t, "{}");
    for rule in ["mcp__a", "mcp__a__*"] {
        let a = allow(&[rule]);
        assert_eq!(hit(&a, &tool("mcp__a__b")), Some("allow"), "{rule}");
        assert_eq!(hit(&a, &tool("mcp__a__b__c")), None, "{rule}");
        assert_eq!(hit(&a, &tool("mcp__ab__c")), None, "{rule}");
        let d = deny(&[rule]);
        assert_eq!(hit(&d, &tool("mcp__a__b__c")), Some("deny"), "{rule}");
    }
}

// --- Review fixes -------------------------------------------------------------

#[test]
fn more_run_commands_and_open_ended_programs_are_dropped() {
    for layer in [None, Some("user"), Some("project")] {
        for r in [
            "Bash(npm run-script *)",
            "Bash(npm rum *)",
            "Bash(npm urn *)",
            "Bash(npm x *)",
            "Bash(deno run *)",
            "Bash(deno task *)",
            "Bash(git config *)",
            "Bash(make:*)",
            "Bash(make *)",
            "Bash(just *)",
            "Bash(tar *)",
            "Bash(zip *)",
            "Bash(gcc *)",
            "Bash(cc *)",
            "Bash(clang *)",
        ] {
            assert!(vet(r, layer).is_err(), "{r} in {layer:?} should be dropped");
        }
        // An exact rule stays: it names the whole command.
        for r in [
            "Bash(make test)",
            "Bash(just build)",
            "Bash(tar tf a.tar)",
            "Bash(deno task build)",
            "Bash(git config user.name)",
            "Bash(npm run-script build)",
        ] {
            assert!(
                vet(r, layer).is_ok(),
                "{r} in {layer:?}: {:?}",
                vet(r, layer)
            );
        }
    }
}

#[test]
fn a_rule_with_a_control_or_bidi_character_is_refused() {
    let bad = [
        "Bash(ls\u{1b}[1A\u{1b}[2K)",
        "Bash(ls)\n",
        "Bash(ls\tfoo)",
        "Read(src/\u{202e}txt.rs)",
        "Bash(git status\u{200f})",
        "WebFetch(domain:docs.rs\u{2066})",
        "Bash(ls)\u{2028}",
    ];
    for r in bad {
        assert!(parse(r).is_err(), "{r:?}");
        for layer in [None, Some("system"), Some("user"), Some("project")] {
            assert!(vet(r, layer).is_err(), "{r:?} in {layer:?}");
        }
        // Deny and ask fail like an unparseable rule.
        for (d, a) in [(vec![r.to_owned()], vec![]), (vec![], vec![r.to_owned()])] {
            let p = policy::Permissions {
                deny: d,
                ask: a,
                allow: vec![],
            };
            assert!(Permissions::compile(&p, &env()).is_err(), "{r:?}");
            let mut pol = policy::default();
            pol.permissions = p;
            assert!(
                policy::validate(&pol, true)
                    .iter()
                    .any(|e| e.contains("control or bidirectional")),
                "{r:?}"
            );
        }
        // Allow is dropped with a warning.
        let (kept, warns) = vet_allow_list(&[r.to_owned()], "user", "f.json");
        assert!(kept.is_empty() && warns.len() == 1, "{kept:?} {warns:?}");
        let p = policy::Permissions {
            allow: vec![r.to_owned()],
            ..Default::default()
        };
        let (perms, warns) = Permissions::compile(&p, &env()).unwrap();
        assert!(perms.is_empty() && warns.len() == 1, "{warns:?}");
    }
    assert!(parse("Bash(ls -l)").is_ok());
    assert_eq!(
        escape_unprintable("a\u{1b}[1Ab\u{202e}c\n"),
        "a\\u{001b}[1Ab\\u{202e}c\\u{000a}"
    );
    assert_eq!(escape_unprintable("Bash(ls) é"), "Bash(ls) é");
}

#[test]
fn deny_and_ask_read_the_raw_text_both_ways() {
    // nah is absent, so the raw text is read: a shell joins `r\<NL>m` to `rm`.
    let d = deny(&["Bash(rm *)"]);
    assert!(d.check(&bash("r\\\nm x"), None).is_some());
    assert!(d.check(&bash("ls"), None).is_none());
}

#[test]
fn a_drive_relative_path_is_never_allowed() {
    let e = Env {
        home: "C:\\Users\\u".into(),
        windows: true,
        fold_case: false,
        host: false,
    };
    let p = policy::Permissions {
        deny: vec!["Edit(/secret/**)".into()],
        allow: vec!["Edit(/x/**)".into()],
        ..Default::default()
    };
    let (perms, _) = Permissions::compile(&p, &e).unwrap();
    let perms = perms.with_resolver(Box::new(|e, p| Some(paths::to_posix(e, p))));
    let at = |path: &str| {
        Call::new(
            CallInput {
                tool: "Edit".into(),
                input: Some(
                    RawValue::from_string(serde_json::json!({ "file_path": path }).to_string())
                        .unwrap(),
                ),
                cwd: "C:\\w\\p".into(),
                project_dir: "C:\\w\\p".into(),
                ..Default::default()
            },
            &e,
        )
    };
    assert_eq!(hit(&perms, &at("C:\\w\\p\\x\\a")), Some("allow"));
    assert_eq!(hit(&perms, &at("C:..\\..\\x\\a")), None, "C:rel is no path of ours");
    assert_eq!(hit(&perms, &at("C:..\\..\\secret\\a")), Some("deny"));
}
