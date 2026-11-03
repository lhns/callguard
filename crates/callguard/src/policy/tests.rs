//! Ports of policy/policy_test.go, plus the policy_rev golden files captured
//! from the Go binary.

use std::fs;
use std::path::Path;

use tempfile::TempDir;

use super::*;

fn write(path: &Path, content: &str) -> String {
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, content).unwrap();
    path.to_string_lossy().into_owned()
}

/// Builds a system file, a user config dir and a project dir.
fn layers(system: &str, user: &str, project: &str) -> (TempDir, LoadOptions) {
    let d = tempfile::tempdir().unwrap();
    let mut o = LoadOptions {
        user_config_dir: "-".into(),
        ..Default::default()
    };
    o.system_policy = write(&d.path().join("system.json"), system);
    if !user.is_empty() {
        let cfg = d.path().join("cfg");
        o.user_config_dir = cfg.to_string_lossy().into_owned();
        write(&cfg.join("callguard").join("policy.json"), user);
    }
    if !project.is_empty() {
        let proj = d.path().join("proj");
        o.project_dir = proj.to_string_lossy().into_owned();
        write(&proj.join(".callguard").join("policy.json"), project);
    }
    (d, o)
}

fn rule_ids(p: &Policy) -> String {
    p.rules
        .iter()
        .map(|r| r.id.as_str())
        .collect::<Vec<_>>()
        .join(",")
}

fn llm(p: &Policy) -> &Llm {
    p.llm.as_ref().unwrap()
}

fn nah(p: &Policy) -> &Nah {
    p.nah.as_ref().unwrap()
}

#[test]
fn default_values() {
    let p = default();
    assert!(p.mode == "enforce" && p.unattended_ask == "deny" && p.deadline_ms == 8000);
    let n = nah(&p);
    assert!(!n.enabled && n.path == "nah" && n.timeout_ms == 2000);
    let l = llm(&p);
    assert!(p.llm_enabled());
    assert!(l.mode == "shadow" && l.backend == "anthropic" && l.timeout_ms == 3000);
    assert_eq!(l.min_confidence, Some(0.7));
    let t = l.transcript.as_ref().unwrap();
    assert!(t.max_messages == 20 && t.max_bytes == 24000);
    let b = &p.backends["anthropic"];
    assert!(b.r#type == "anthropic" && b.model == "claude-haiku-5-5");
    assert!(b.api_key_env == "ANTHROPIC_API_KEY" && b.base_url == "https://api.anthropic.com");
    assert_eq!(b.data_classes.join(","), "open,private");
    let probs = validate(&p, true);
    assert!(probs.is_empty(), "default policy invalid: {probs:?}");
    assert_eq!(llm(&with_defaults(p.clone())).mode, "shadow");
    assert_eq!(rev(&with_defaults(p.clone())), rev(&p), "idempotent");
}

#[test]
fn with_defaults_does_not_mutate() {
    let l = Llm {
        mode: "enforce".into(),
        ..Default::default()
    };
    let p = Policy {
        llm: Some(l.clone()),
        ..Default::default()
    };
    let _ = with_defaults(p.clone());
    assert_eq!(p.llm.as_ref().unwrap(), &l);
    assert!(l.backend.is_empty() && l.transcript.is_none());
}

#[test]
fn merge_system_applies_over_defaults() {
    let (_d, o) = layers(
        r#"{"policy_version":1,"mode":"shadow","unattended_ask":"ask","deadline_ms":500,
        "rules":[{"id":"mine","decision":"allow","match":{"kind":["fetch"]}},{"id":"sudo","decision":"deny","match":{"command":"sudo"}}],
        "nah":{"enabled":true,"path":"/x/nah"},
        "llm":{"mode":"enforce","min_confidence":0.9,"block":["no prod"],"transcript":{"max_messages":5}},
        "backends":{"local":{"type":"openai","model":"m","base_url":"http://x"}},
        "disable_builtin":["fork-bomb"]}"#,
        "",
        "",
    );
    let l = load(&o).unwrap();
    let p = &l.policy;
    assert!(p.mode == "shadow" && p.unattended_ask == "ask" && p.deadline_ms == 500);
    let n = nah(p);
    assert!(n.enabled && n.path == "/x/nah" && n.timeout_ms == 2000);
    let lm = llm(p);
    let t = lm.transcript.as_ref().unwrap();
    assert!(lm.mode == "enforce" && lm.min_confidence == Some(0.9) && t.max_messages == 5);
    assert!(t.max_bytes == 24000 && lm.block.len() == 1 && lm.backend == "anthropic");
    assert!(p.backends.contains_key("local") && !p.backends["anthropic"].model.is_empty());
    assert!(rule_ids(p).ends_with(",mine"), "rules: {}", rule_ids(p));
    for r in &p.rules {
        if r.id == "sudo" {
            assert_eq!(
                r.decision, "deny",
                "system rule with a default's id replaces it"
            );
        }
    }
    assert!(l.warnings.is_empty() && l.problems().is_empty());
}

#[test]
fn defaults_false_drops_default_rules() {
    let (_d, o) = layers(
        r#"{"policy_version":1,"defaults":false,"rules":[{"id":"only","decision":"ask","match":{"kind":["shell"]}}]}"#,
        "",
        "",
    );
    assert_eq!(rule_ids(&load(&o).unwrap().policy), "only");
}

#[test]
fn tighten_only() {
    let user = r#"{"policy_version":1,"mode":"shadow","defaults":false,"unattended_ask":"ask","deadline_ms":1,
        "rules":[{"id":"u-deny","decision":"deny","match":{"command":"x"}},{"id":"u-allow","decision":"allow","match":{"command":"y"}},
                 {"id":"sudo","decision":"ask","match":{"command":"z"}}],
        "nah":{"enabled":true},"backends":{"b":{"type":"fake"}},"deny_streak":{"consecutive":1},"log":{"disabled":true},
        "disable_builtin":["rm-root"],"final":true,
        "llm":{"enabled":false,"mode":"enforce","backend":"b","timeout_ms":1,"environment":["e"],"allow_exceptions":["a"],
               "transcript":{"max_bytes":1},"block":["u-block"],"min_confidence":0.95}}"#;
    let project = r#"{"policy_version":1,"rules":[{"id":"p-ask","decision":"ask","match":{"command":"p"}}],
        "llm":{"block":["p-block"],"min_confidence":0.5}}"#;
    let (_d, o) = layers(
        r#"{"policy_version":1,"llm":{"min_confidence":0.8}}"#,
        user,
        project,
    );
    let l = load(&o).unwrap();
    let p = &l.policy;
    assert!(
        p.mode == "enforce"
            && !nah(p).enabled
            && p.unattended_ask == "deny"
            && p.deadline_ms == 8000
            && !p.r#final
            && p.deny_streak.is_none()
            && p.log.is_none()
            && p.disable_builtin.is_empty()
            && p.backends.len() == 1,
        "loosening leaked through: {p:?}"
    );
    let lm = llm(p);
    assert!(
        p.llm_enabled()
            && lm.mode == "shadow"
            && lm.backend == "anthropic"
            && lm.timeout_ms == 3000
            && lm.environment.is_empty()
            && lm.allow_exceptions.is_empty()
            && lm.transcript.as_ref().unwrap().max_bytes == 24000,
        "llm loosened: {lm:?}"
    );
    assert_eq!(lm.block.join(","), "u-block,p-block");
    assert_eq!(
        lm.min_confidence,
        Some(0.95),
        "raised by the user, not lowered by the project"
    );
    let ids = rule_ids(p);
    assert!(
        ids.contains("u-deny")
            && ids.contains("p-ask")
            && !ids.contains("u-allow")
            && ids.contains("read-in-project"),
        "rules: {ids}"
    );
    assert!(
        p.rules
            .iter()
            .any(|r| r.id == "sudo" && r.r#match.command == SUDO_RE),
        "a user rule with a default's id must not replace the default"
    );
    for key in [
        "mode",
        "defaults",
        "unattended_ask",
        "deadline_ms",
        "final",
        "nah",
        "backends",
        "deny_streak",
        "log",
        "disable_builtin",
        "rules.u-allow",
        "llm.enabled",
        "llm.mode",
        "llm.backend",
        "llm.timeout_ms",
        "llm.environment",
        "llm.allow_exceptions",
        "llm.transcript",
        "llm.min_confidence",
    ] {
        let want = format!("policy.json: {key} ignored");
        assert!(
            l.warnings.iter().any(|w| w.contains(&want)),
            "no warning naming key {key:?} in {:?}",
            l.warnings
        );
    }
}

#[test]
fn final_skips_lower_layers() {
    let (_d, o) = layers(
        r#"{"policy_version":1,"final":true}"#,
        r#"{"policy_version":1,"rules":[{"id":"u","decision":"deny","match":{"command":"x"}}]}"#,
        r#"{"policy_version":1,"this is not json"#,
    );
    let l = load(&o).expect("a final system policy must not read user or project files");
    assert!(!rule_ids(&l.policy).split(',').any(|id| id == "u"));
    assert_eq!(l.files.len(), 1);
}

#[test]
fn load_errors() {
    let d = tempfile::tempdir().unwrap();
    let p = |name: &str| d.path().join(name);
    let lo = |sys: String| LoadOptions {
        system_policy: sys,
        user_config_dir: "-".into(),
        ..Default::default()
    };
    let missing = p("missing.json").to_string_lossy().into_owned();
    assert!(
        load(&lo(missing)).is_err(),
        "explicit missing system policy must fail"
    );
    let bad = write(&p("v2.json"), r#"{"policy_version":2}"#);
    let e = load(&lo(bad)).unwrap_err();
    assert!(e.0.contains("policy_version"), "{e}");
    let none = write(&p("none.json"), "{}");
    assert!(load(&lo(none)).is_err(), "missing policy_version must fail");
    let junk = write(&p("junk.json"), "{");
    assert!(load(&lo(junk)).is_err(), "bad JSON must fail");
    // A bad user file fails too: never ignore a layer silently.
    let (_d2, o) = layers(r#"{"policy_version":1}"#, r#"{"policy_version":7}"#, "");
    assert!(load(&o).is_err(), "bad user version must fail");
    // A BOM is tolerated.
    let bom = write(&p("bom.json"), "\u{feff}{\"policy_version\":1}");
    assert!(load(&lo(bom)).is_ok());
    // The default system path may be absent.
    let l = load(&lo(String::new())).unwrap();
    assert!(l.files.len() <= 1);
}

#[test]
fn unknown_keys_and_warnings() {
    let src = r#"{"policy_version":1,"bogus":1,"rules":[{"id":"a","decision":"ask","match":{"command":"x","nope":1},"extra":2}],
        "llm":{"mode":"shadow","wat":true},"backends":{"b":{"type":"fake","zzz":1}}}"#;
    let got = unknown_keys(src.as_bytes()).join(",");
    assert_eq!(
        got,
        "backends.b.zzz,bogus,llm.wat,rules[0].extra,rules[0].match.nope"
    );
    let (_d, o) = layers(src, "", "");
    let l = load(&o).unwrap();
    assert!(
        l.warnings.len() == 5 && l.warnings[0].contains("unknown key"),
        "warnings: {:?}",
        l.warnings
    );
}

#[test]
fn validate_reports_every_problem() {
    let bad = Policy {
        policy_version: 1,
        mode: "loud".into(),
        unattended_ask: "allow".into(),
        disable_builtin: vec!["nope".into()],
        rules: vec![
            Rule {
                id: "a".into(),
                decision: "ask".into(),
                ..Default::default()
            },
            Rule {
                decision: "ask".into(),
                r#match: Match {
                    kind: vec!["shell".into()],
                    ..Default::default()
                },
                ..Default::default()
            },
            Rule {
                id: "c".into(),
                decision: "permit".into(),
                r#match: Match {
                    kind: vec!["shell".into()],
                    ..Default::default()
                },
                ..Default::default()
            },
        ],
        nah: Some(Nah {
            mode: "x".into(),
            ..Default::default()
        }),
        llm: Some(Llm {
            mode: "y".into(),
            backend: "missing".into(),
            min_confidence: Some(1.5),
            ..Default::default()
        }),
        backends: BTreeMap::from([
            (
                "l".to_owned(),
                Backend {
                    r#type: "anthropic".into(),
                    model: "claude-haiku-latest".into(),
                    ..Default::default()
                },
            ),
            (
                "e".to_owned(),
                Backend {
                    r#type: "exec".into(),
                    ..Default::default()
                },
            ),
            (
                "u".to_owned(),
                Backend {
                    r#type: "weird".into(),
                    ..Default::default()
                },
            ),
        ]),
        deny_streak: Some(DenyStreak {
            consecutive: -1,
            total: 0,
        }),
        ..Default::default()
    };
    let probs = validate(&bad, true).join("\n");
    for want in [
        "mode \"loud\"",
        "unattended_ask",
        "unknown built-in rule",
        "no match conditions",
        "missing id",
        "decision \"permit\"",
        "nah.mode",
        "llm.mode",
        "min_confidence",
        "not defined in backends",
        "moving alias",
        "exec backend needs command",
        "unknown type",
        "deny_streak",
    ] {
        assert!(
            probs.contains(want),
            "missing problem {want:?} in:\n{probs}"
        );
    }
    assert!(
        validate(&bad, false).len() < validate(&bad, true).len(),
        "llm.backend cross-reference only checked for merged policies"
    );
}

#[test]
fn rev_is_stable_and_follows_the_policy() {
    let (a, b) = (rev(&default()), rev(&default()));
    assert!(a == b && a.starts_with("sha256:") && a.len() == 7 + 64);
    let mut p = default();
    p.mode = "shadow".into();
    assert_ne!(rev(&p), a);
}

fn golden(name: &str) -> (Policy, String) {
    let dir = format!("{}/testdata/rev", env!("CARGO_MANIFEST_DIR"));
    let src = fs::read_to_string(format!("{dir}/{name}.src.json")).unwrap();
    let marshal = fs::read_to_string(format!("{dir}/{name}.marshal.json")).unwrap();
    let p: Policy = serde_json::from_str(&src).unwrap();
    (with_defaults(p), marshal)
}

// Revs printed by the Go binary's policy.Rev (go1.26, 2026-11-03) for the
// policies in testdata/rev.
const GO_REVS: &[(&str, &str)] = &[
    (
        "empty",
        "sha256:e774675ef1cdf80c3793c2949248f6f5133731c7a95df2a9518c044929e1ab28",
    ),
    (
        "floats",
        "sha256:759d52855f5ceb17f75d4016715d5d89439ef6da6812a945f184d6dfd457701f",
    ),
    (
        "floats2",
        "sha256:1bd6db2cd46bffec4e4965c6a9a781d3a7d50a514858ca6ef41f5600114908a3",
    ),
    (
        "nah",
        "sha256:269d06b2b39c78c81d653f9902581e1e2c13e2570641b99933b65cd4730548fc",
    ),
    (
        "escapes",
        "sha256:9423d8ca6068dbe3d6ab8a38ffd7b5065a1c65513df486ffee228274855a17ed",
    ),
];

#[test]
fn rev_matches_the_go_binary() {
    for (name, want) in GO_REVS {
        let (p, marshal) = golden(name);
        assert_eq!(
            canonical_json(&p),
            marshal.trim_end(),
            "{name}: canonical JSON"
        );
        assert_eq!(rev(&p), *want, "{name}");
    }
}

#[test]
fn default_policy_rev_matches_the_go_binary() {
    assert_eq!(
        rev(&default()),
        "sha256:11ed5b44df9c3d7eeae631048919c5a45c4e2b33348314d023bb5455992ac775"
    );
}

#[test]
fn go_float_formatting() {
    for (v, want) in [
        (1.0, "1"),
        (0.0, "0"),
        (0.7, "0.7"),
        (0.85, "0.85"),
        (3.45, "3.45"),
        (100.0, "100"),
        (5e-7, "5e-7"),
        (1.5e-9, "1.5e-9"),
        (1e21, "1e+21"),
        (0.00001, "0.00001"),
    ] {
        assert_eq!(go_f64(v), want);
    }
}

#[test]
fn go_quote_matches_percent_q() {
    assert_eq!(go_quote("a\"b\\c\n"), r#""a\"b\\c\n""#);
    assert_eq!(go_quote("é\u{1}"), "\"é\\x01\"");
}

#[test]
fn default_rules_all_have_descriptions() {
    for r in default_rules() {
        assert!(
            !r.description.is_empty(),
            "default rule {} has no description",
            r.id
        );
    }
}
