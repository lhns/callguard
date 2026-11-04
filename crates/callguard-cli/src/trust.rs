//! `callguard trust`: review and trust a project's allow rules.
//!
//! Granting needs a person: stdin and stdout must both be terminals, there is
//! no `--yes` and no environment override. `--list` and `--revoke` grant
//! nothing and run anywhere.

use std::io::{BufRead, IsTerminal, Write};
use std::path::Path;

use callguard::engine;
use callguard::permissions;
use callguard::policy;
use callguard::schema::Request;
use callguard::trust::{self, Record, State};

use crate::flags::{self, Kind, spec};

const USAGE: &str =
    "usage: callguard trust [--project dir]      review and trust the project's allow rules
       callguard trust --list             show the trusted projects
       callguard trust --revoke [--project dir]
";

/// What one run is asked to do.
pub struct Opts {
    /// "" means how `decide` finds it: the git root above the cwd, else the cwd.
    pub project: String,
    /// "" means the user config dir.
    pub user_config_dir: String,
    pub list: bool,
    pub revoke: bool,
}

pub fn run(
    args: &[String],
    stdin: &mut dyn std::io::Read,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> i32 {
    let f = match flags::parse(
        &[
            spec("project", Kind::Str),
            spec("list", Kind::Bool),
            spec("revoke", Kind::Bool),
        ],
        args,
    ) {
        Ok(f) => f,
        Err(e) => {
            if let flags::FlagError::Bad(m) = e {
                let _ = writeln!(stderr, "{m}");
            }
            let _ = stderr.write_all(USAGE.as_bytes());
            return 64;
        }
    };
    if !f.rest.is_empty() || (f.bool("list") && f.bool("revoke")) {
        let _ = stderr.write_all(USAGE.as_bytes());
        return 64;
    }
    let opts = Opts {
        project: f.str("project"),
        user_config_dir: String::new(),
        list: f.bool("list"),
        revoke: f.bool("revoke"),
    };
    // Asked of the real handles (the dispatcher holds their locks, and
    // `is_terminal` takes none).
    let interactive = std::io::stdin().is_terminal() && std::io::stdout().is_terminal();
    flow(
        &opts,
        interactive,
        &mut std::io::BufReader::new(stdin),
        stdout,
        stderr,
    )
}

fn project_dir(given: &str) -> String {
    let dir = if given.is_empty() {
        std::env::current_dir()
            .map(|d| d.to_string_lossy().into_owned())
            .unwrap_or_default()
    } else {
        given.to_owned()
    };
    let resolved = if given.is_empty() {
        engine::resolve_project_dir(&Request {
            cwd: dir.clone(),
            ..Default::default()
        })
    } else {
        dir
    };
    trust::canonical(&resolved)
}

/// The project layer's allow rules, or None if it has no readable policy file.
fn project_allow(project: &str) -> Result<Vec<String>, String> {
    let path = Path::new(project).join(".callguard").join("policy.json");
    match policy::read_file(&path.to_string_lossy(), policy::LAYER_PROJECT) {
        Ok(f) => Ok(f.policy.permissions.allow),
        Err(e) => Err(e.to_string()),
    }
}

/// The logic of the verb, with the terminal check and the streams given.
pub fn flow(
    o: &Opts,
    interactive: bool,
    input: &mut dyn BufRead,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> i32 {
    let Some(record) = trust::record_path(&o.user_config_dir) else {
        let _ = writeln!(
            err,
            "callguard trust: no user config directory for the trust record"
        );
        return 1;
    };
    if o.list {
        return list(&record, out);
    }
    let project = project_dir(&o.project);
    if o.revoke {
        return match trust::revoke(&record, &project) {
            Ok(true) => {
                let _ = writeln!(out, "revoked: {project}");
                0
            }
            Ok(false) => {
                let _ = writeln!(out, "no trust entry for {project}");
                0
            }
            Err(e) => {
                let _ = writeln!(err, "callguard trust: {e}");
                1
            }
        };
    }
    let allow = project_allow(&project).unwrap_or_default();
    let _ = writeln!(
        out,
        "project: {}",
        permissions::escape_unprintable(&project)
    );
    if allow.is_empty() {
        let _ = writeln!(
            out,
            "the project's policy has no allow rules; nothing to trust"
        );
        return 0;
    }
    if !interactive {
        let _ = writeln!(
            err,
            "callguard trust: stdin and stdout must both be terminals; nothing was written"
        );
        return 1;
    }
    let _ = writeln!(out, "allow rules ({}):", allow.len());
    // Rules print escaped: a control character must not hide a rule (or the
    // reason one is dropped) from the person approving.
    for r in &allow {
        let shown = permissions::escape_unprintable(r);
        match permissions::vet_reason(r, Some(policy::LAYER_PROJECT)) {
            Ok(_) => {
                let _ = writeln!(out, "  {shown}");
            }
            Err(why) => {
                let why = permissions::escape_unprintable(&why);
                let _ = writeln!(out, "  {shown}   (would be dropped: {why})");
            }
        }
    }
    if !trust::confirm(input, out) {
        let _ = writeln!(out, "not trusted");
        return 1;
    }
    match trust::write_entry(&record, &project, &allow) {
        Ok(()) => {
            let _ = writeln!(out, "trusted: {project}");
            0
        }
        Err(e) => {
            let _ = writeln!(
                err,
                "callguard trust: cannot write {}: {e}",
                record.display()
            );
            1
        }
    }
}

fn list(record: &Path, out: &mut dyn Write) -> i32 {
    match trust::load(record) {
        Record::Missing => {
            let _ = writeln!(out, "no trusted projects");
        }
        Record::Unreadable(e) => {
            let _ = writeln!(out, "{} is unreadable: {e}", record.display());
        }
        Record::Entries(entries) => {
            if entries.is_empty() {
                let _ = writeln!(out, "no trusted projects");
            }
            for e in &entries {
                let status = match project_allow(&e.project) {
                    Ok(allow) => match trust::state(std::slice::from_ref(e), &e.project, &allow) {
                        State::Trusted => "matches",
                        _ => "rules changed since trusted",
                    },
                    Err(_) => "project policy not found",
                };
                let _ = writeln!(out, "{}  {}  {status}", e.project, e.at);
            }
        }
    }
    0
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;
    use std::path::PathBuf;

    use super::*;

    fn setup(rules: &[&str]) -> (tempfile::TempDir, Opts) {
        let d = tempfile::tempdir().unwrap();
        let proj = d.path().join("proj");
        std::fs::create_dir_all(proj.join(".callguard")).unwrap();
        let body = serde_json::json!({"policy_version": 1, "permissions": {"allow": rules}});
        std::fs::write(proj.join(".callguard/policy.json"), body.to_string()).unwrap();
        let cfg = d.path().join("cfg");
        let o = Opts {
            project: proj.to_string_lossy().into_owned(),
            user_config_dir: cfg.to_string_lossy().into_owned(),
            list: false,
            revoke: false,
        };
        (d, o)
    }

    fn go(o: &Opts, interactive: bool, answer: &str) -> (i32, String, String) {
        let (mut out, mut err) = (Vec::new(), Vec::new());
        let code = flow(
            o,
            interactive,
            &mut Cursor::new(answer.to_owned()),
            &mut out,
            &mut err,
        );
        (
            code,
            String::from_utf8(out).unwrap(),
            String::from_utf8(err).unwrap(),
        )
    }

    fn record(o: &Opts) -> PathBuf {
        trust::record_path(&o.user_config_dir).unwrap()
    }

    #[test]
    fn no_terminal_means_no_record() {
        let (_d, o) = setup(&["Bash(git log *)"]);
        let (code, _, err) = go(&o, false, "y\n");
        assert_eq!(code, 1);
        assert!(err.contains("terminals"), "{err}");
        assert!(!record(&o).exists());
    }

    #[test]
    fn only_y_or_yes_trusts() {
        for (answer, trusted) in [
            ("y\n", true),
            ("YES\n", true),
            ("n\n", false),
            ("\n", false),
            ("yep\n", false),
            ("", false),
        ] {
            let (_d, o) = setup(&["Bash(git log *)"]);
            let (code, out, _) = go(&o, true, answer);
            assert_eq!(record(&o).exists(), trusted, "{answer:?}: {out}");
            assert_eq!(code == 0, trusted, "{answer:?}");
            assert!(out.contains("Trust these rules? [y/N]"), "{out}");
        }
    }

    #[test]
    fn the_rules_are_shown_and_droppable_ones_marked() {
        let (_d, o) = setup(&["Bash(git log *)", "Bash(python *)", "Edit(.git/**)"]);
        let (_, out, _) = go(&o, true, "n\n");
        assert!(out.contains("  Bash(git log *)\n"), "{out}");
        assert!(out.contains("Bash(python *)   (would be dropped"), "{out}");
        assert!(out.contains("Edit(.git/**)   (would be dropped"), "{out}");
    }

    #[test]
    fn control_characters_are_shown_escaped_not_run() {
        let hide = "Bash(ls)\u{1b}[1A\u{1b}[2K\u{202e}";
        let (_d, o) = setup(&["Bash(git log *)", hide]);
        let (_, out, _) = go(&o, true, "n\n");
        assert!(
            !out.contains('\u{1b}') && !out.contains('\u{202e}'),
            "{out:?}"
        );
        assert!(
            out.contains("\\u{001b}[1A") && out.contains("\\u{202e}"),
            "{out:?}"
        );
        assert!(out.contains("would be dropped"), "{out:?}");
    }

    #[test]
    fn no_allow_rules_is_said_and_needs_no_terminal() {
        let (_d, o) = setup(&[]);
        let (code, out, _) = go(&o, false, "");
        assert_eq!(code, 0);
        assert!(out.contains("nothing to trust"), "{out}");
        assert!(!record(&o).exists());
    }

    #[test]
    fn list_and_revoke_need_no_terminal() {
        let (_d, mut o) = setup(&["Bash(git log *)"]);
        assert_eq!(go(&o, true, "y\n").0, 0);
        o.list = true;
        let (code, out, _) = go(&o, false, "");
        assert_eq!(code, 0);
        assert!(out.contains("matches"), "{out}");
        // Editing the rules shows in the list.
        let p = Path::new(&o.project).join(".callguard/policy.json");
        std::fs::write(
            p,
            r#"{"policy_version":1,"permissions":{"allow":["Bash(git log -5)"]}}"#,
        )
        .unwrap();
        assert!(go(&o, false, "").1.contains("changed"));
        o.list = false;
        o.revoke = true;
        let (code, out, _) = go(&o, false, "");
        assert_eq!(code, 0);
        assert!(out.contains("revoked"), "{out}");
        o.list = true;
        o.revoke = false;
        assert!(go(&o, false, "").1.contains("no trusted projects"));
    }
}
