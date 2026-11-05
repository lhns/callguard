//! The decision log: one JSON line per decision.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;

use crate::json_text;
use crate::serde_util::{is_false, is_zero, nullable, raw_some, whole_float};

/// How much of the log's end the deny-streak reader looks at.
pub(crate) const TAIL_BYTES: u64 = 1 << 20;

/// One log line. It never holds transcript text. `reason` is empty for llm
/// verdicts unless input logging is on, because it can quote arguments.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Entry {
    #[serde(deserialize_with = "nullable")]
    pub ts: String,
    #[serde(deserialize_with = "nullable")]
    pub id: String,
    #[serde(
        skip_serializing_if = "String::is_empty",
        deserialize_with = "nullable"
    )]
    pub session_id: String,
    #[serde(
        skip_serializing_if = "String::is_empty",
        deserialize_with = "nullable"
    )]
    pub tool_use_id: String,
    #[serde(
        skip_serializing_if = "String::is_empty",
        deserialize_with = "nullable"
    )]
    pub harness: String,
    #[serde(deserialize_with = "nullable")]
    pub tool: String,
    #[serde(deserialize_with = "nullable")]
    pub kind: String,
    #[serde(deserialize_with = "nullable")]
    pub input_sha256: String,
    #[serde(deserialize_with = "nullable")]
    pub decision: String,
    #[serde(deserialize_with = "nullable")]
    pub enforced: bool,
    #[serde(deserialize_with = "nullable")]
    pub layer: String,
    #[serde(
        skip_serializing_if = "String::is_empty",
        deserialize_with = "nullable"
    )]
    pub rule: String,
    #[serde(serialize_with = "whole_float", deserialize_with = "nullable")]
    pub confidence: f64,
    #[serde(
        skip_serializing_if = "String::is_empty",
        deserialize_with = "nullable"
    )]
    pub backend: String,
    #[serde(
        skip_serializing_if = "String::is_empty",
        deserialize_with = "nullable"
    )]
    pub policy_rev: String,
    #[serde(deserialize_with = "nullable")]
    pub latency_ms: i64,
    #[serde(skip_serializing_if = "is_false", deserialize_with = "nullable")]
    pub unattended: bool,
    #[serde(skip_serializing_if = "is_zero", deserialize_with = "nullable")]
    pub input_tokens: i64,
    #[serde(skip_serializing_if = "is_zero", deserialize_with = "nullable")]
    pub output_tokens: i64,
    /// An llm deny turned into ask by the deny streak.
    #[serde(skip_serializing_if = "is_false", deserialize_with = "nullable")]
    pub escalated: bool,
    /// Verdicts of layers in shadow mode that did not end the pipeline.
    #[serde(skip_serializing_if = "Vec::is_empty", deserialize_with = "nullable")]
    pub shadow: Vec<ShadowVerdict>,
    #[serde(
        skip_serializing_if = "String::is_empty",
        deserialize_with = "nullable"
    )]
    pub reason: String,
    #[serde(skip_serializing_if = "Option::is_none", deserialize_with = "raw_some")]
    pub input: Option<Box<RawValue>>,
}

/// What a layer in shadow mode would have decided. It has no reason text:
/// that can quote arguments.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub(crate) struct ShadowVerdict {
    #[serde(deserialize_with = "nullable")]
    pub layer: String,
    #[serde(deserialize_with = "nullable")]
    pub decision: String,
    #[serde(
        skip_serializing_if = "String::is_empty",
        deserialize_with = "nullable"
    )]
    pub rule: String,
}

/// `<state dir>/callguard/decisions.jsonl`; None if the state directory cannot
/// be told (no home). A relative path would put the log in the working
/// directory, where the agent can write forged entries.
pub(crate) fn default_path() -> Option<String> {
    default_path_with(&|k| std::env::var(k).ok(), std::env::consts::OS)
}

/// [`default_path`] with the environment and OS name given.
fn default_path_with(env: &dyn Fn(&str) -> Option<String>, os: &str) -> Option<String> {
    let get = |k: &str| env(k).filter(|v| !v.is_empty());
    let file = |base: PathBuf| {
        Some(
            base.join("callguard")
                .join("decisions.jsonl")
                .to_string_lossy()
                .into_owned(),
        )
    };
    if let Some(x) = get("XDG_STATE_HOME") {
        return file(PathBuf::from(x));
    }
    if os == "windows"
        && let Some(local) = get("LocalAppData")
    {
        return file(PathBuf::from(local));
    }
    // USERPROFILE on Windows, HOME elsewhere.
    let home = PathBuf::from(get(if os == "windows" {
        "USERPROFILE"
    } else {
        "HOME"
    })?);
    match os {
        "windows" => file(home.join("AppData").join("Local")),
        "macos" => file(home.join("Library").join("Application Support")),
        _ => file(home.join(".local").join("state")),
    }
}

/// Appends entries to one file. Safe for concurrent use.
#[derive(Debug)]
pub(crate) struct Logger {
    path: String,
    lock: Mutex<()>,
}

impl Logger {
    /// The file and its directory are created on the first append (dir 0700,
    /// file 0600 on Unix).
    pub fn new(path: &str) -> Logger {
        Logger {
            path: path.to_owned(),
            lock: Mutex::new(()),
        }
    }

    pub fn path(&self) -> &str {
        &self.path
    }

    /// Writes `e` as one line, in a single write.
    pub fn append(&self, e: &Entry) -> io::Result<()> {
        let mut line = json_text::to_string(e).map_err(io::Error::other)?;
        line.push('\n');
        let _guard = self.lock.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(dir) = Path::new(&self.path).parent()
            && !dir.as_os_str().is_empty()
        {
            let mut b = fs::DirBuilder::new();
            b.recursive(true);
            #[cfg(unix)]
            std::os::unix::fs::DirBuilderExt::mode(&mut b, 0o700);
            b.create(dir)?;
        }
        let mut o = OpenOptions::new();
        o.create(true).append(true);
        #[cfg(unix)]
        std::os::unix::fs::OpenOptionsExt::mode(&mut o, 0o600);
        refuse_fifo(&self.path)?;
        // One write: concurrent processes do not interleave lines.
        o.open(&self.path)?.write_all(line.as_bytes())
    }
}

/// Opening a FIFO blocks until another process opens its other end, past the
/// hook's deadline. Other special files (`/dev/null`) are fine.
fn refuse_fifo(path: &str) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::FileTypeExt;
        if fs::metadata(path).is_ok_and(|m| m.file_type().is_fifo()) {
            return Err(io::Error::other(format!("{path} is a FIFO")));
        }
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

/// The entries of `session_id` within the last [`TAIL_BYTES`] of the file,
/// oldest first. A missing file is no entries. Unparseable lines (a cut first
/// line, a corrupt line) are skipped.
pub(crate) fn read_tail(path: &str, session_id: &str) -> io::Result<Vec<Entry>> {
    refuse_fifo(path)?;
    let f = match File::open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e),
    };
    let data = crate::io_util::read_tail(f, TAIL_BYTES)?;
    let mut out = Vec::new();
    for line in data.split(|&b| b == b'\n') {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        if let Ok(e) = serde_json::from_slice::<Entry>(line)
            && e.session_id == session_id
        {
            out.push(e);
        }
    }
    Ok(out)
}

/// Counts the session's enforced llm-layer denies: those in a row at the end
/// of the llm-layer history (consecutive) and all of them (total). Entries of
/// other layers neither count nor break the run, and neither do escalated
/// denies (shown to a human as ask), so an escalation stays in force until the
/// judge allows something.
pub(crate) fn llm_denies(entries: &[Entry]) -> (usize, usize) {
    let (mut consecutive, mut total) = (0, 0);
    let mut run = true;
    for e in entries.iter().rev() {
        if e.layer != "llm" || e.escalated {
            continue;
        }
        if e.decision == "deny" && e.enforced {
            total += 1;
            if run {
                consecutive += 1;
            }
        } else {
            run = false;
        }
    }
    (consecutive, total)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn raw(s: &str) -> Option<Box<RawValue>> {
        Some(RawValue::from_string(s.into()).unwrap())
    }

    fn json(e: &Entry) -> String {
        serde_json::to_string(e).unwrap()
    }

    #[test]
    fn round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir
            .path()
            .join("state")
            .join("callguard")
            .join("decisions.jsonl");
        let path = path.to_str().unwrap();
        let l = Logger::new(path);
        let input = Entry {
            ts: "2026-11-02T10:00:00.123456789Z".into(),
            id: "abc".into(),
            session_id: "s1".into(),
            harness: "claude".into(),
            tool: "Bash".into(),
            kind: "shell".into(),
            input_sha256: "ff".into(),
            decision: "deny".into(),
            enforced: true,
            layer: "llm".into(),
            rule: "r".into(),
            confidence: 0.9,
            backend: "fake:x".into(),
            policy_rev: "sha256:1".into(),
            latency_ms: 12,
            unattended: true,
            input_tokens: 100,
            output_tokens: 5,
            reason: "why <b>".into(),
            input: raw(r#"{"command":"x"}"#),
            ..Default::default()
        };
        l.append(&input).unwrap();
        l.append(&Entry {
            id: "b".into(),
            session_id: "other".into(),
            layer: "rules".into(),
            ..Default::default()
        })
        .unwrap();
        let got = read_tail(path, "s1").unwrap();
        assert_eq!(got.len(), 1);
        assert_eq!(json(&got[0]), json(&input));
        let data = std::fs::read_to_string(path).unwrap();
        assert_eq!(
            data.matches('\n').count(),
            2,
            "one line per entry: {data:?}"
        );
        // `<` is escaped, so the file never holds markup.
        assert!(!data.contains('<'), "{data}");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode(Path::new(path)), 0o600);
            assert_eq!(mode(Path::new(path).parent().unwrap()), 0o700);
        }
        // Optional fields stay out of the line when empty.
        let line = data.split('\n').nth(1).unwrap();
        for k in ["\"reason\"", "\"input\"", "\"backend\""] {
            assert!(!line.contains(k), "{k} should be omitted: {line}");
        }
    }

    #[test]
    fn confidence_is_written_without_a_fraction_when_whole() {
        let e = Entry {
            confidence: 1.0,
            ..Default::default()
        };
        assert!(json(&e).contains(r#""confidence":1,"#), "{}", json(&e));
    }

    #[test]
    fn read_tail_missing_and_corrupt() {
        let d = tempfile::tempdir().unwrap();
        let missing = d.path().join("none");
        assert!(
            read_tail(missing.to_str().unwrap(), "s")
                .unwrap()
                .is_empty()
        );
        let p = d.path().join("log");
        std::fs::write(
            &p,
            "garbage\n{\"id\":\"1\",\"session_id\":\"s\"}\n{\"id\":\n",
        )
        .unwrap();
        let e = read_tail(p.to_str().unwrap(), "s").unwrap();
        assert!(
            e.len() == 1 && e[0].id == "1",
            "corrupt lines skipped: {e:?}"
        );
    }

    #[test]
    fn read_tail_bounded() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("log");
        // ~250 byte lines: 8000 of them exceed the 1 MiB tail.
        let pad = "x".repeat(150);
        let mut b = String::new();
        for i in 0..8000 {
            let e = Entry {
                id: i.to_string(),
                session_id: "s".into(),
                reason: pad.clone(),
                ..Default::default()
            };
            b.push_str(&json(&e));
            b.push('\n');
        }
        std::fs::write(&p, b).unwrap();
        let e = read_tail(p.to_str().unwrap(), "s").unwrap();
        assert!(
            !e.is_empty() && e.len() < 8000,
            "tail should be a bounded suffix, got {}",
            e.len()
        );
        assert_eq!(e.last().unwrap().id, "7999", "newest entry missing");
        assert_ne!(e[0].id, "0", "oldest entry should be cut");
    }

    fn d(layer: &str, dec: &str, enforced: bool) -> Entry {
        Entry {
            layer: layer.into(),
            decision: dec.into(),
            enforced,
            ..Default::default()
        }
    }

    #[test]
    fn llm_denies_counts() {
        let escalated = Entry {
            escalated: true,
            ..d("llm", "ask", true)
        };
        let tests: Vec<(&str, Vec<Entry>, usize, usize)> = vec![
            ("empty", vec![], 0, 0),
            (
                "three in a row",
                vec![
                    d("llm", "deny", true),
                    d("llm", "deny", true),
                    d("llm", "deny", true),
                ],
                3,
                3,
            ),
            (
                "allow breaks the run",
                vec![
                    d("llm", "deny", true),
                    d("llm", "deny", true),
                    d("llm", "allow", true),
                    d("llm", "deny", true),
                ],
                1,
                3,
            ),
            (
                "other layers neither count nor break",
                vec![
                    d("llm", "deny", true),
                    d("rules", "deny", true),
                    d("builtin", "allow", true),
                    d("llm", "deny", true),
                ],
                2,
                2,
            ),
            (
                "shadow denies do not count and break the run",
                vec![d("llm", "deny", true), d("llm", "deny", false)],
                0,
                1,
            ),
            (
                "escalated ask neither counts nor breaks",
                vec![
                    d("llm", "deny", true),
                    d("llm", "deny", true),
                    d("llm", "deny", true),
                    escalated,
                ],
                3,
                3,
            ),
            (
                "ask breaks",
                vec![d("llm", "deny", true), d("llm", "ask", true)],
                0,
                1,
            ),
        ];
        for (name, entries, cons, total) in tests {
            assert_eq!(llm_denies(&entries), (cons, total), "{name}");
        }
    }

    #[test]
    fn default_path_per_platform() {
        let env = |pairs: &'static [(&'static str, &'static str)]| {
            move |k: &str| {
                pairs
                    .iter()
                    .find(|(n, _)| *n == k)
                    .map(|(_, v)| (*v).to_owned())
            }
        };
        let p = |path: Option<String>| path.map(|p| p.replace(std::path::MAIN_SEPARATOR, "/"));
        assert_eq!(
            p(default_path_with(
                &env(&[("XDG_STATE_HOME", "/x/state")]),
                "linux"
            )),
            Some("/x/state/callguard/decisions.jsonl".into())
        );
        assert_eq!(
            p(default_path_with(&env(&[("HOME", "/h")]), "linux")),
            Some("/h/.local/state/callguard/decisions.jsonl".into())
        );
        assert_eq!(
            p(default_path_with(&env(&[("HOME", "/h")]), "macos")),
            Some("/h/Library/Application Support/callguard/decisions.jsonl".into())
        );
        assert_eq!(
            p(default_path_with(
                &env(&[("USERPROFILE", "C:/U"), ("LocalAppData", "C:/L")]),
                "windows"
            )),
            Some("C:/L/callguard/decisions.jsonl".into())
        );
        assert_eq!(
            p(default_path_with(
                &env(&[("USERPROFILE", "C:/U")]),
                "windows"
            )),
            Some("C:/U/AppData/Local/callguard/decisions.jsonl".into())
        );
        // An empty XDG_STATE_HOME counts as unset.
        assert_eq!(
            p(default_path_with(
                &env(&[("XDG_STATE_HOME", ""), ("HOME", "/h")]),
                "linux"
            )),
            Some("/h/.local/state/callguard/decisions.jsonl".into())
        );
    }

    #[test]
    fn no_home_means_no_default_path() {
        let none = |_: &str| None;
        for os in ["linux", "macos", "windows"] {
            assert_eq!(default_path_with(&none, os), None, "{os}");
            let empty = |_: &str| Some(String::new());
            assert_eq!(default_path_with(&empty, os), None, "{os}");
        }
    }

    /// A FIFO as the log must fail at once, not hang the hook; `/dev/null`
    /// still works.
    #[cfg(unix)]
    #[test]
    fn a_fifo_log_is_refused_and_dev_null_is_not() {
        let d = tempfile::tempdir().unwrap();
        let fifo = d.path().join("log");
        assert!(
            std::process::Command::new("mkfifo")
                .arg(&fifo)
                .status()
                .unwrap()
                .success()
        );
        let path = fifo.to_string_lossy().into_owned();
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let append = Logger::new(&path).append(&Entry::default()).is_err();
            let _ = tx.send((append, read_tail(&path, "s").is_err()));
        });
        assert_eq!(
            rx.recv_timeout(std::time::Duration::from_secs(5)),
            Ok((true, true))
        );
        Logger::new("/dev/null").append(&Entry::default()).unwrap();
        assert!(read_tail("/dev/null", "s").unwrap().is_empty());
    }
}
