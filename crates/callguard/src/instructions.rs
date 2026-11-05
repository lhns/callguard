//! The Claude Code instruction bridge. Claude's PreToolUse payload carries no
//! instructions, but its `InstructionsLoaded` event fires once per loaded file
//! (imports included, with Claude's own discovery and approvals applied). The
//! hook records each path in a per-session file; PreToolUse reads the recorded
//! files and hands their text to the judge as `Request.instructions`.
//!
//! Known limits:
//! - The event is asynchronous, so the first PreToolUse calls of a session may
//!   run before any file is recorded.
//! - It does not fire when Claude reads `AGENTS.md` (or any file) directly.
//! - Only absolute `.md` paths without `..` are read, up to 64 KiB each, so a
//!   tampered state file can at most send such files to the judge provider.
//!   The state directory is protected by the self-protection built-in.
//!
//! Session files live in `<state dir>/callguard/instructions/<session>.txt`,
//! beside the decision log's default place, whatever `--log` says.

use sha2::Digest;
use std::fs;
use std::io::{self, Read, Write};
use std::path::{Component, Path, PathBuf};
use std::time::{Duration, SystemTime};

/// The most of one instruction file that is read.
const MAX_FILE_BYTES: u64 = 64 << 10;
/// The most the state file may hold; later paths are not recorded.
const MAX_STATE_BYTES: u64 = 64 << 10;
/// Collection stops once this much text is gathered: the engine keeps 8 KiB.
const MAX_COLLECTED: usize = 16 << 10;
const MAX_AGE: Duration = Duration::from_secs(7 * 24 * 3600);
/// The directory name self-protection looks for.
pub(crate) const DIR_NAME: &str = "instructions";

/// The directory of the per-session files; None if the state directory cannot
/// be told (no home).
pub fn default_dir() -> Option<PathBuf> {
    let log = crate::declog::default_path()?;
    Path::new(&log).parent().map(|p| p.join(DIR_NAME))
}

/// The state file for a session. The id is reduced to `[A-Za-z0-9_-]` (at
/// most 100 characters), so it cannot name another directory; None if nothing
/// is left.
fn session_file(dir: &Path, session_id: &str) -> Option<PathBuf> {
    let id: String = session_id
        .chars()
        .take(100)
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect();
    if id.is_empty() {
        return None;
    }
    // Two ids that reduce to the same name must not share a file.
    if id != session_id {
        let sum = hex::encode(sha2::Sha256::digest(session_id.as_bytes()));
        return Some(dir.join(format!("{id}-{}.txt", &sum[..8])));
    }
    Some(dir.join(format!("{id}.txt")))
}

/// Appends `file_path` to the session's file unless it is there already, and
/// deletes session files older than 7 days.
pub(crate) fn record(dir: &Path, session_id: &str, file_path: &str) -> io::Result<()> {
    let bad = |c: char| c == '\n' || c == '\r' || c == '\0';
    let Some(file) = session_file(dir, session_id) else {
        return Ok(());
    };
    if file_path.is_empty() || file_path.contains(bad) {
        return Ok(());
    }
    create_private_dir(dir)?;
    prune(dir);
    let known = read_limited(&file, MAX_STATE_BYTES).unwrap_or_default();
    if known.lines().any(|l| l == file_path) || known.len() as u64 >= MAX_STATE_BYTES {
        return Ok(());
    }
    let mut f = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&file)?;
    f.write_all(format!("{file_path}\n").as_bytes())
}

fn create_private_dir(dir: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)
    }
    #[cfg(not(unix))]
    {
        fs::create_dir_all(dir)
    }
}

/// Removes session files not written for 7 days. Failures are ignored.
fn prune(dir: &Path) {
    let Ok(rd) = fs::read_dir(dir) else { return };
    let now = SystemTime::now();
    for e in rd.flatten() {
        let p = e.path();
        let old = p.extension().is_some_and(|x| x == "txt")
            && e.metadata()
                .and_then(|m| m.modified())
                .is_ok_and(|t| now.duration_since(t).is_ok_and(|age| age > MAX_AGE));
        if old {
            let _ = fs::remove_file(&p);
        }
    }
}

/// At most `max` bytes of a regular file, as lossy text. Anything else (a
/// pipe, a device, a directory) reads as an error, so a planted path cannot
/// block the hook.
fn read_limited(path: &Path, max: u64) -> io::Result<String> {
    let f = fs::File::open(path)?;
    if !f.metadata()?.is_file() {
        return Err(io::Error::other("not a regular file"));
    }
    let mut b = Vec::new();
    f.take(max).read_to_end(&mut b)?;
    Ok(String::from_utf8_lossy(&b).into_owned())
}

/// Whether a recorded path may be read: absolute, `.md` (any case), no `..`.
fn readable(p: &str) -> bool {
    let path = Path::new(p);
    path.is_absolute()
        && path
            .extension()
            .is_some_and(|x| x.eq_ignore_ascii_case("md"))
        && !path.components().any(|c| c == Component::ParentDir)
}

/// The recorded files' text, a `## <path>` header before each, in the order
/// Claude loaded them. A missing or unreadable file is skipped. Reading starts
/// from the last file and stops once enough text is gathered, because the
/// engine keeps the end.
pub(crate) fn collect(dir: &Path, session_id: &str) -> String {
    let Some(state) = session_file(dir, session_id) else {
        return String::new();
    };
    let Ok(list) = read_limited(&state, MAX_STATE_BYTES) else {
        return String::new();
    };
    let mut seen = std::collections::HashSet::new();
    let paths: Vec<&str> = list
        .lines()
        .filter(|l| readable(l) && seen.insert(*l))
        .collect();
    let mut sections: Vec<String> = Vec::new();
    let mut total = 0;
    for p in paths.into_iter().rev() {
        let Ok(text) = read_limited(Path::new(p), MAX_FILE_BYTES) else {
            continue;
        };
        let text = strip_html_comments(&text);
        let text = text.trim();
        if text.is_empty() {
            continue;
        }
        let section = format!("## {p}\n{text}");
        total += section.len();
        sections.push(section);
        if total >= MAX_COLLECTED {
            break;
        }
    }
    sections.reverse();
    sections.join("\n\n")
}

/// What follows a closing `-->` on its line stays.
fn keep_after<'a>(out: &mut Vec<&'a str>, rest: &'a str) {
    let rest = rest.trim();
    if !rest.is_empty() {
        out.push(rest);
    }
}

/// Removes block-level HTML comments (a comment that starts a line) outside
/// code fences, as Claude Code does before it injects a file. A comment in
/// the middle of a line stays, as it does for Claude.
pub(crate) fn strip_html_comments(text: &str) -> String {
    let mut out: Vec<&str> = Vec::new();
    let mut fence: Option<char> = None;
    let mut in_comment = false;
    for line in text.lines() {
        let t = line.trim_start();
        if in_comment {
            if let Some(i) = line.find("-->") {
                in_comment = false;
                keep_after(&mut out, &line[i + 3..]);
            }
        } else if let Some(f) = fence {
            if t.starts_with(&f.to_string().repeat(3)) {
                fence = None;
            }
            out.push(line);
        } else if t.starts_with("```") || t.starts_with("~~~") {
            fence = t.chars().next();
            out.push(line);
        } else if t.starts_with("<!--") {
            match t.find("-->") {
                Some(i) => keep_after(&mut out, &t[i + 3..]),
                None => in_comment = true,
            }
        } else {
            out.push(line);
        }
    }
    out.join(
        "
",
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write(p: &Path, s: &str) {
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::write(p, s).unwrap();
    }

    #[test]
    fn session_ids_cannot_leave_the_directory() {
        let d = Path::new("/state/instructions");
        for id in ["../../etc/passwd", "a/b", "a\\b", "..", "x\0y", "é"] {
            let f = session_file(d, id).unwrap();
            assert_eq!(f.parent(), Some(d), "{id:?} -> {f:?}");
            assert!(f.to_string_lossy().ends_with(".txt"));
        }
        assert_eq!(session_file(d, ""), None);
        // Ids that reduce to the same name get different files; a clean id
        // keeps its plain name.
        assert_ne!(session_file(d, "a/b"), session_file(d, "a\x5cb"));
        assert_ne!(
            session_file(d, &"a".repeat(150)),
            session_file(d, &"a".repeat(160))
        );
        assert_eq!(session_file(d, "abc-1").unwrap(), d.join("abc-1.txt"));
        let long = "a".repeat(500);
        assert!(session_file(d, &long).unwrap().to_string_lossy().len() < 140);
    }

    #[test]
    fn record_dedups_ignores_bad_input_and_collect_reads_in_order() {
        let t = tempfile::tempdir().unwrap();
        let dir = t.path().join("instructions");
        let proj = t.path().join("p");
        let (a, b) = (proj.join("CLAUDE.md"), proj.join("sub").join("NOTES.MD"));
        write(&a, "use pnpm\n");
        write(&b, "<!-- hidden -->\nkeep tabs\n");
        let secret = proj.join("secret.txt");
        write(&secret, "TOP SECRET");
        for p in [&a, &b, &a, &secret] {
            record(&dir, "abc123", &p.to_string_lossy()).unwrap();
        }
        record(&dir, "abc123", "relative/CLAUDE.md").unwrap();
        record(&dir, "abc123", "/x/../CLAUDE.md\n/etc/passwd.md").unwrap();
        record(&dir, "", "/x.md").unwrap();
        let state = fs::read_to_string(dir.join("abc123.txt")).unwrap();
        assert_eq!(state.lines().count(), 4, "{state}");
        let got = collect(&dir, "abc123");
        let want = format!(
            "## {}\nuse pnpm\n\n## {}\nkeep tabs",
            a.display(),
            b.display()
        );
        assert_eq!(got, want);
        assert!(!got.contains("TOP SECRET") && !got.contains("hidden"));
        assert_eq!(collect(&dir, "other"), "");
    }

    #[test]
    fn a_missing_file_is_skipped_and_a_traversal_path_is_not_read() {
        let t = tempfile::tempdir().unwrap();
        let dir = t.path().join("i");
        let real = t.path().join("CLAUDE.md");
        write(&real, "real");
        // Written by hand, as a tampered state file would be.
        let sneaky = format!("{}/sub/../CLAUDE.md", t.path().display());
        write(
            &dir.join("s.txt"),
            &format!(
                "{}\n{}\n{}\n",
                t.path().join("gone.md").display(),
                sneaky,
                real.display()
            ),
        );
        assert_eq!(collect(&dir, "s"), format!("## {}\nreal", real.display()));
    }

    #[test]
    fn old_session_files_are_pruned_on_write() {
        let t = tempfile::tempdir().unwrap();
        let dir = t.path().join("i");
        write(&dir.join("old.txt"), "/x.md\n");
        write(&dir.join("keep.log"), "x");
        let old = SystemTime::now() - Duration::from_secs(8 * 24 * 3600);
        for n in ["old.txt", "keep.log"] {
            fs::File::options()
                .write(true)
                .open(dir.join(n))
                .unwrap()
                .set_modified(old)
                .unwrap();
        }
        write(&dir.join("fresh.txt"), "/y.md\n");
        record(&dir, "new", &t.path().join("a.md").to_string_lossy()).unwrap();
        assert!(!dir.join("old.txt").exists());
        assert!(dir.join("fresh.txt").exists() && dir.join("keep.log").exists());
    }

    #[test]
    fn html_comments_go_except_in_code_fences_and_mid_line() {
        let src = "a\n<!-- one -->\nb\n<!--\nmulti\nline\n--> tail\n```\n<!-- keep -->\n```\nc <!-- inline --> d\n  <!-- x --> after\n";
        assert_eq!(
            strip_html_comments(src),
            "a\nb\ntail\n```\n<!-- keep -->\n```\nc <!-- inline --> d\nafter"
        );
    }

    #[test]
    fn a_pipe_or_directory_named_md_is_not_read() {
        let t = tempfile::tempdir().unwrap();
        let d = t.path().join("dir.md");
        fs::create_dir_all(&d).unwrap();
        assert!(read_limited(&d, 10).is_err());
    }
}
