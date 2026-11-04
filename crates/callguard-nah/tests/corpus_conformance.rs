//! nah's own corpus through our engine, with a 60 s analysis budget.
//!
//! The corpus is `corpus/` of the pinned nah fork, located through `cargo
//! metadata`. Each row is a tool call, a fixture (files, links, a git state,
//! environment variables) and nah's expected verdict and guard. Fixtures are
//! built in a temp dir; roots the fixtures own (`/workspace`, `/home`, ...) are
//! moved under it. A row agrees when our engine gives the expected verdict and,
//! if the row names a guard, that guard is among the attributions.
//!
//! The test fails when agreement drops below the known baseline of the OS.
//! Run it with `cargo test -p callguard-nah --test corpus_conformance -- --ignored`;
//! Linux takes about ten minutes. No official-binary comparison: the spike
//! (`29a22b7`) showed the official binary agrees wherever it answers in time.

// std::env::set_var is unsafe since edition 2024. This is the only test in the
// binary, it runs one row at a time, and the engine's threads end before the
// next row's environment is set.
#![allow(unsafe_code)]

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::mpsc;
use std::time::Duration;

use callguard::nah::{NahEngine, NahRequest, NahVerdict};
use callguard_nah::RealEngine;
use serde_json::{Value, json};

/// (OS, rows that agree, rows compared) on a full run.
/// Linux: 8,598 of 8,858 (Phase 0, 60 s budget). Windows: 217 of 238 in a
/// release run, 215 in a debug one; the two root walks that may or may not
/// answer within the 90 s row limit decide the difference, so 215 is the floor.
/// macOS has none yet.
const BASELINES: &[(&str, usize, usize)] = &[("linux", 8598, 8858), ("windows", 215, 238)];

const BUDGET_MS: u64 = 60_000;
/// A row that takes longer than this counts as a failure and the run moves on.
const ROW_LIMIT: Duration = Duration::from_secs(90);

fn nah_corpus_dir() -> PathBuf {
    let out = Command::new(env!("CARGO"))
        .args(["metadata", "--format-version", "1", "--locked"])
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .expect("cargo metadata");
    assert!(out.status.success(), "cargo metadata failed");
    let meta: Value = serde_json::from_slice(&out.stdout).unwrap();
    let manifest = meta["packages"]
        .as_array()
        .unwrap()
        .iter()
        .find(|p| p["name"] == "nah-cli")
        .and_then(|p| p["manifest_path"].as_str())
        .expect("nah-cli in the dependency graph");
    Path::new(manifest)
        .ancestors()
        .map(|a| a.join("corpus"))
        .find(|c| c.join("FIXTURES.json").is_file())
        .expect("corpus/ in the nah checkout")
}

fn str_of<'a>(v: &'a Value, key: &str) -> &'a str {
    v[key].as_str().unwrap_or("")
}

type Rewrite = Box<dyn Fn(&str) -> String>;

/// Rewrites the fixture-owned roots to the same path under `root`.
fn relocator(root: &str, platform: &str) -> Rewrite {
    if platform == "windows" {
        let fwd = root.replace('\\', "/");
        let back = root.replace('/', "\\");
        let pairs = [
            (r"C:\workspace".to_owned(), format!(r"{back}\workspace")),
            ("C:/workspace".to_owned(), format!("{fwd}/workspace")),
            (r"C:\Users\test".to_owned(), format!(r"{back}\Users\test")),
            ("C:/Users/test".to_owned(), format!("{fwd}/Users/test")),
        ];
        return Box::new(move |s| {
            let mut out = s.to_owned();
            for (from, to) in &pairs {
                out = out.replace(from.as_str(), to);
            }
            out
        });
    }
    const ROOTS: [&str; 9] = [
        "/workspace",
        "/home",
        "/srv",
        "/opt",
        "/mnt",
        "/backup",
        "/repo",
        "/ws",
        "/tools",
    ];
    let word = |c: u8| c == b'_' || c == b'-' || c.is_ascii_alphanumeric();
    let path_char = move |c: u8| word(c) || c == b'.' || c == b'/' || c == b'~';
    let root = root.to_owned();
    Box::new(move |s| {
        let b = s.as_bytes();
        let mut out = String::with_capacity(s.len() + 32);
        let mut i = 0;
        while i < b.len() {
            if b[i] == b'/' && (i == 0 || !path_char(b[i - 1])) {
                let hit = ROOTS.iter().find(|r| {
                    s[i..].starts_with(*r) && (i + r.len() == b.len() || !word(b[i + r.len()]))
                });
                if let Some(r) = hit {
                    out.push_str(&root);
                    out.push_str(r);
                    i += r.len();
                    continue;
                }
            }
            // Copy one whole character.
            let n = s[i..].chars().next().map_or(1, char::len_utf8);
            out.push_str(&s[i..i + n]);
            i += n;
        }
        out
    })
}

struct Materializer<'a> {
    root: String,
    rw: &'a dyn Fn(&str) -> String,
}

impl Materializer<'_> {
    fn owned(&self, p: &str) -> bool {
        !p.is_empty() && p.replace('\\', "/").starts_with(&format!("{}/", self.root))
    }

    fn mkdir(&self, p: &str) {
        if self.owned(p) {
            let _ = std::fs::create_dir_all(p);
        }
    }

    fn write_file(&self, p: &str, contents: Option<&str>, executable: bool) {
        if !self.owned(p) {
            return;
        }
        if let Some(parent) = Path::new(p).parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        if std::fs::symlink_metadata(p).is_ok_and(|m| m.is_dir()) {
            return;
        }
        let data = contents.map(|c| (self.rw)(c)).unwrap_or_default();
        let _ = std::fs::write(p, data);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = if executable { 0o755 } else { 0o644 };
            let _ = std::fs::set_permissions(p, std::fs::Permissions::from_mode(mode));
        }
        #[cfg(not(unix))]
        let _ = executable;
    }

    fn symlink(&self, target: &str, at: &str) {
        if let Some(parent) = Path::new(at).parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let _ = std::fs::remove_file(at);
        #[cfg(unix)]
        let _ = std::os::unix::fs::symlink(target, at);
        // Windows may refuse without the privilege; the few rows that need a link
        // then simply disagree, as they did in the spike.
        #[cfg(windows)]
        let _ = std::os::windows::fs::symlink_file(target, at);
    }

    fn mkfifo(&self, p: &str) {
        if !self.owned(p) {
            return;
        }
        if let Some(parent) = Path::new(p).parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        #[cfg(unix)]
        let _ = Command::new("mkfifo").arg(p).output();
    }

    fn git(&self, dir: &str, args: &[&str]) {
        let _ = Command::new("git")
            .arg("-C")
            .arg(dir)
            .args(args)
            .env("GIT_AUTHOR_NAME", "t")
            .env("GIT_AUTHOR_EMAIL", "t@t")
            .env("GIT_COMMITTER_NAME", "t")
            .env("GIT_COMMITTER_EMAIL", "t@t")
            .output();
    }

    fn init_repo(&self, dir: &str) {
        if !self.owned(dir) {
            return;
        }
        self.mkdir(dir);
        if !Path::new(dir).join(".git").exists() {
            self.git(dir, &["init", "-q"]);
        }
    }

    fn run(&self, fx: &Value) {
        let rw = self.rw;
        self.mkdir(&rw(str_of(fx, "cwd")));
        if let Some(h) = fx["env"]["HOME"].as_str() {
            self.mkdir(&rw(h));
        }
        let paths = fx["paths"].as_array().cloned().unwrap_or_default();
        let mut links = Vec::new();
        for p in &paths {
            if p["exists"] != true {
                continue;
            }
            let mut real = rw(str_of(p, "realpath"));
            if real.is_empty() {
                real = rw(str_of(p, "resolved"));
            }
            let executable = p["executable"] == true;
            match str_of(p, "kind") {
                "file" => self.write_file(&real, p["contents"].as_str(), executable),
                "directory" => {
                    self.mkdir(&real);
                    // Entries that prefix the next one are directories, the rest files.
                    let mut ds: Vec<String> = p["descendants"]
                        .as_array()
                        .into_iter()
                        .flatten()
                        .filter_map(|d| d.as_str().map(str::to_owned))
                        .collect();
                    ds.sort();
                    for (i, d) in ds.iter().enumerate() {
                        let d = rw(d);
                        let next_inside = ds
                            .get(i + 1)
                            .is_some_and(|n| rw(n).starts_with(&format!("{d}/")));
                        if next_inside {
                            self.mkdir(&d);
                        } else {
                            self.write_file(&d, None, false);
                        }
                    }
                }
                "symlink" => links.push(p),
                "fifo" => self.mkfifo(&real),
                _ => {}
            }
        }
        for p in links {
            let at = rw(str_of(p, "resolved"));
            let target = rw(str_of(p, "realpath"));
            if !self.owned(&at) || target.is_empty() {
                continue;
            }
            let executable = p["executable"] == true;
            match str_of(p, "target_kind") {
                "file" => self.write_file(&target, p["contents"].as_str(), executable),
                "directory" => self.mkdir(&target),
                _ => {}
            }
            self.symlink(&target, &at);
        }
        for p in &paths {
            for l in p["links"].as_array().into_iter().flatten() {
                let at = rw(l[0].as_str().unwrap_or(""));
                if self.owned(&at) {
                    self.symlink(&rw(l[1].as_str().unwrap_or("")), &at);
                }
            }
        }
        for r in fx["roots"].as_array().into_iter().flatten() {
            if r["kind"] == "project" {
                self.init_repo(&rw(str_of(r, "path")));
            }
        }
        for g in fx["git_state"].as_array().into_iter().flatten() {
            let mut top = rw(str_of(g, "path"));
            if !str_of(g, "top_level").is_empty() {
                top = rw(str_of(g, "top_level"));
            }
            if !self.owned(&top) {
                continue;
            }
            self.init_repo(&top);
            let base = rw(str_of(g, "path"));
            self.mkdir(&base);
            let tracked_changes = g["tracked_changes"] == true;
            let stash = g["stash_entries"] == true;
            if tracked_changes || stash {
                let tracked = Path::new(&top).join("tracked.txt");
                let _ = std::fs::write(&tracked, "v1\n");
                self.git(&top, &["add", "tracked.txt"]);
                self.git(&top, &["commit", "-q", "-m", "init"]);
                if stash {
                    let _ = std::fs::write(&tracked, "stash\n");
                    self.git(&top, &["stash", "-q"]);
                }
                if tracked_changes {
                    let _ = std::fs::write(&tracked, "v2\n");
                }
            }
            let names = |key: &str| -> Vec<String> {
                g[key]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .filter_map(|x| x.as_str().map(str::to_owned))
                    .collect()
            };
            let join = |rel: &str| Path::new(&base).join(rel).to_string_lossy().into_owned();
            for u in names("untracked") {
                if u.ends_with('/') {
                    self.mkdir(&join(&u));
                    self.write_file(&join(&format!("{u}file")), None, false);
                } else {
                    self.write_file(&join(&u), None, false);
                }
            }
            let ignored = names("ignored");
            if !ignored.is_empty() {
                let _ = std::fs::write(join(".gitignore"), ignored.join("\n") + "\n");
                for ig in ignored {
                    if ig.ends_with('/') {
                        self.write_file(&join(&format!("{ig}file")), None, false);
                    } else {
                        self.write_file(&join(&ig), None, false);
                    }
                }
            }
        }
    }
}

/// Our overrides of nah's factory guard states for a context fixture's posture.
fn posture(raw: &Value, defaults: &BTreeMap<String, bool>) -> BTreeMap<String, bool> {
    let mut want: BTreeMap<String, bool> = BTreeMap::new();
    if let Some(named) = raw.as_str() {
        match named {
            "factory-defaults" => return BTreeMap::new(),
            "factory-defaults-without-secrets-store-read" => {
                return BTreeMap::from([("secrets-store-read".to_owned(), false)]);
            }
            "all-enabled" => defaults.keys().for_each(|n| {
                want.insert(n.clone(), true);
            }),
            "all-disabled" => defaults.keys().for_each(|n| {
                want.insert(n.clone(), false);
            }),
            other => panic!("unknown posture {other:?}"),
        }
    } else {
        defaults.keys().for_each(|n| {
            want.insert(n.clone(), false);
        });
        for s in raw["states"].as_array().into_iter().flatten() {
            want.insert(str_of(s, "name").to_owned(), s["enabled"] == true);
        }
    }
    want.into_iter()
        .filter(|(n, on)| defaults.get(n).is_some_and(|d| d != on))
        .collect()
}

fn set_env(env: &Value, rw: &dyn Fn(&str) -> String) -> Vec<(String, Option<String>)> {
    let mut saved = Vec::new();
    for (name, v) in env.as_object().into_iter().flatten() {
        saved.push((name.clone(), std::env::var(name).ok()));
        // SAFETY: see the file header.
        unsafe {
            match v.as_str() {
                Some(v) => std::env::set_var(name, rw(v)),
                None => std::env::remove_var(name),
            }
        }
    }
    saved
}

fn restore_env(saved: Vec<(String, Option<String>)>) {
    for (name, old) in saved {
        // SAFETY: see the file header.
        unsafe {
            match old {
                Some(v) => std::env::set_var(name, v),
                None => std::env::remove_var(name),
            }
        }
    }
}

/// One row through the engine, in its own thread so a hang costs `ROW_LIMIT`.
fn decide(req: NahRequest) -> Result<(NahVerdict, Vec<String>), String> {
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let r = RealEngine.decide(&req).map(|r| {
            let guards = r.facts.map(|f| f.guards).unwrap_or_default();
            (r.verdict, guards)
        });
        let _ = tx.send(r.map_err(|e| e.to_string()));
    });
    rx.recv_timeout(ROW_LIMIT)
        .unwrap_or_else(|_| Err("no answer within the row limit".into()))
}

#[test]
#[ignore = "runs nah's whole corpus: about ten minutes on Linux"]
fn corpus_conformance() {
    let corpus = nah_corpus_dir();
    let fixtures: Value =
        serde_json::from_slice(&std::fs::read(corpus.join("FIXTURES.json")).unwrap()).unwrap();
    let platform = std::env::consts::OS;

    let defaults: BTreeMap<String, bool> = nah_cli::shipped_guard_states()
        .iter()
        .map(|s| (s.name().to_owned(), s.enabled()))
        .collect();

    let mut files: Vec<_> = std::fs::read_dir(&corpus)
        .unwrap()
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().is_some_and(|x| x == "jsonl"))
        .collect();
    files.sort();
    let mut by_fixture: BTreeMap<String, Vec<Value>> = BTreeMap::new();
    for f in files {
        for line in std::fs::read_to_string(&f).unwrap().lines() {
            if line.trim().is_empty() {
                continue;
            }
            let row: Value = serde_json::from_str(line).unwrap();
            by_fixture
                .entry(str_of(&row, "observation_fixture").to_owned())
                .or_default()
                .push(row);
        }
    }

    let (mut compared, mut agree) = (0usize, 0usize);
    let mut disagreements = Vec::new();
    for (name, rows) in &by_fixture {
        let fx = &fixtures["observation_fixtures"][name];
        if str_of(fx, "platform") != platform {
            continue;
        }
        let dir = tempfile::tempdir().unwrap();
        let mut root = std::fs::canonicalize(dir.path())
            .unwrap()
            .to_string_lossy()
            .into_owned();
        if let Some(plain) = root.strip_prefix(r"\\?\") {
            root = plain.to_owned();
        }
        let root_slash = root.replace('\\', "/");
        let rw = relocator(&root, platform);
        Materializer {
            root: root_slash,
            rw: &rw,
        }
        .run(fx);
        let saved = set_env(&fx["env"], &rw);

        for r in rows {
            let ctx = &fixtures["ctx_fixtures"][str_of(r, "ctx_fixture")];
            if !str_of(ctx, "enforcement").is_empty()
                || str_of(ctx, "platform") != platform
                || !str_of(r, "code").is_empty()
            {
                continue;
            }
            let guards = posture(&ctx["shipped_guards"], &defaults);
            let home = rw(str_of(ctx, "home"));
            // SAFETY: see the file header.
            unsafe {
                std::env::set_var("HOME", &home);
                std::env::set_var("USERPROFILE", &home);
            }
            let (tool, input) = if let Some(cmd) = r["command"].as_str().filter(|c| !c.is_empty()) {
                ("Bash".to_owned(), json!({ "command": rw(cmd) }))
            } else {
                (
                    str_of(r, "tool").to_owned(),
                    relocate_json(&r["input"], &rw),
                )
            };
            let cwd = rw(str_of(fx, "cwd"));
            let process_cwd = if Path::new(&cwd).is_dir() {
                PathBuf::from(&cwd)
            } else {
                std::env::temp_dir()
            };
            let _ = std::env::set_current_dir(process_cwd);
            let req = NahRequest {
                tool,
                input: serde_json::value::to_raw_value(&input).unwrap(),
                cwd: cwd.clone(),
                project_dir: cwd,
                guards,
                budget_ms: BUDGET_MS,
                timeout_ms: 80_000,
            };
            let id = str_of(r, "id").to_owned();
            let want = str_of(&r["expected"], "verdict");
            let want_guard = str_of(&r["expected"], "guard");
            compared += 1;
            match decide(req) {
                Ok((verdict, attributions)) => {
                    let got = match verdict {
                        NahVerdict::Block => "block",
                        NahVerdict::Delegate => "delegate",
                    };
                    if got == want
                        && (want_guard.is_empty() || attributions.iter().any(|a| a == want_guard))
                    {
                        agree += 1;
                    } else {
                        disagreements.push(format!(
                            "{id}: want {want} {want_guard}, got {got} {attributions:?}"
                        ));
                    }
                }
                Err(e) => disagreements.push(format!("{id}: want {want}, error: {e}")),
            }
        }
        restore_env(saved);
    }

    let first: Vec<_> = disagreements.iter().take(40).collect();
    println!(
        "corpus on {platform}: {agree} of {compared} agree with the corpus's expected verdict"
    );
    println!("first disagreements: {first:#?}");
    match BASELINES.iter().find(|b| b.0 == platform) {
        Some(&(_, base_agree, base_total)) => {
            assert!(
                compared >= base_total,
                "compared {compared} rows, the baseline run compared {base_total}"
            );
            assert!(
                agree >= base_agree,
                "{agree} of {compared} agree, below the baseline of {base_agree} of {base_total}"
            );
        }
        None => println!("no baseline is set for {platform}; record the number above"),
    }
}

fn relocate_json(v: &Value, rw: &dyn Fn(&str) -> String) -> Value {
    match v {
        Value::String(s) => Value::String(rw(s)),
        Value::Array(a) => Value::Array(a.iter().map(|x| relocate_json(x, rw)).collect()),
        Value::Object(m) => Value::Object(
            m.iter()
                .map(|(k, x)| (k.clone(), relocate_json(x, rw)))
                .collect(),
        ),
        other => other.clone(),
    }
}
