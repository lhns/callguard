//! The `rm-critical` check: deleting something whose loss no project can
//! afford (a root, home, drive, the working directory or a parent of it) must
//! be confirmed by a human. Pure over the words of the call.

use super::builtin::removal;
use super::*;
use crate::hostmeta::rough_argvs;

/// `NAME=$(pwd)`, `` NAME=`git rev-parse --show-toplevel` ``, `NAME=$PWD`: a
/// variable that holds the working or project directory. A `${NAME:?}` guard
/// only stops it being empty.
static TAINT: LazyLock<Regex> = LazyLock::new(|| {
    builtin_regex(concat!(
        r#"(?:^|[\s;&|(])([A-Za-z_][A-Za-z0-9_]*)=["']?"#,
        r"(?:\$\(\s*(?:pwd|git\s+rev-parse\s+--show-toplevel)\s*\)",
        r"|`\s*(?:pwd|git\s+rev-parse\s+--show-toplevel)\s*`",
        r"|\$PWD\b|\$\{PWD\})"
    ))
});

/// The home directory as a shell, cmd or PowerShell writes it, and what
/// follows the `/`.
static HOME_FORM: LazyLock<Regex> = LazyLock::new(|| {
    builtin_regex(
        r"(?i)^(?:~|\$home|\$\{home\}|\$env:(?:userprofile|home)|%userprofile%)(?:/(.*))?$",
    )
});

/// A leading `$NAME`, `${...}` or `$1`/`$@`, and the rest of the word.
static VAR_FORM: LazyLock<Regex> = LazyLock::new(|| {
    builtin_regex(r"^\$(?:\{([^}]*)\}|([A-Za-z_][A-Za-z0-9_]*|[0-9@*#?$!-]))(.*)$")
});

/// The top-level directories a script author writes after a variable.
const TOP_NAMES: [&str; 9] = [
    "mnt", "tmp", "usr", "users", "etc", "bin", "var", "home", "opt",
];

/// A command substitution with its text replaced, so a word keeps its shape.
/// It holds no character the rough splitter cuts at.
const SUB: &str = "\u{1}";

/// `s` with each `$(...)` and backtick pair replaced by a placeholder. An
/// unclosed one stays as written.
fn collapse_substitutions(s: &str) -> String {
    let c: Vec<char> = s.chars().collect();
    let mut out = String::new();
    let mut i = 0;
    while i < c.len() {
        if c[i] == '$' && c.get(i + 1) == Some(&'(') {
            let mut depth = 0;
            let mut j = i + 1;
            while j < c.len() {
                match c[j] {
                    '(' => depth += 1,
                    ')' => {
                        depth -= 1;
                        if depth == 0 {
                            break;
                        }
                    }
                    _ => {}
                }
                j += 1;
            }
            if j < c.len() {
                out.push_str(SUB);
                i = j + 1;
                continue;
            }
        } else if c[i] == '`'
            && let Some(k) = c[i + 1..].iter().position(|&x| x == '`')
        {
            out.push_str(SUB);
            i += k + 2;
            continue;
        }
        out.push(c[i]);
        i += 1;
    }
    out
}

/// The names in a slash path, `.` dropped and `..` resolved.
fn segments(p: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for seg in p.split('/') {
        match seg {
            "" | "." => {}
            ".." => {
                out.pop();
            }
            s => out.push(s.to_owned()),
        }
    }
    out
}

/// The drive letter and the segments below it of a Windows spelling of a
/// drive path: `C:/x`, `//?/C:/x`, `//./C:/x`, `//localhost/C$/x`, and (on a
/// Windows host) git-bash's `/c/x`.
fn drive_parts(p: &str, windows: bool) -> Option<(char, Vec<String>)> {
    let lower = p.to_ascii_lowercase();
    let s = if lower.starts_with("//?/") || lower.starts_with("//./") {
        &p[4..]
    } else {
        p
    };
    let b = s.as_bytes();
    let drive_at = |o: usize| {
        b.get(o).is_some_and(u8::is_ascii_alphabetic)
            && match b.get(o + 1) {
                Some(b':') if o == 0 => matches!(b.get(2), None | Some(b'/')),
                Some(b'/') if o == 1 => true,
                None if o == 1 => true,
                _ => false,
            }
    };
    if drive_at(0) {
        return Some((b[0] as char, segments(&s[2..])));
    }
    if windows && s.starts_with('/') && drive_at(1) {
        return Some((b[1] as char, segments(&s[2..])));
    }
    // The local machine's administrative share: //localhost/C$/x.
    let share = s.strip_prefix("//")?;
    let (host, tail) = share.split_once('/').unwrap_or((share, ""));
    let (head, below) = tail.split_once('/').unwrap_or((tail, ""));
    let hb = head.as_bytes();
    let local = host.eq_ignore_ascii_case("localhost") || host == "127.0.0.1";
    (local && hb.len() == 2 && hb[0].is_ascii_alphabetic() && hb[1] == b'$')
        .then(|| (hb[0] as char, segments(below)))
}

struct Scan<'a> {
    env: &'a Env,
    cwd: &'a str,
    project: &'a str,
    /// Variables assigned the working or project directory in the command.
    tainted: Vec<String>,
}

/// Why `commands` (raw text) or `nah` (the argv nah found, nested ones
/// included) delete something critical, if they do. Relative targets resolve
/// against `cwd`. The raw text is read without a shell parse, so a form it
/// cannot spell is not found there; Windows 8.3 short names (`USERNA~1`) are
/// not expanded at all.
pub(crate) fn find(
    env: &Env,
    cwd: &str,
    project: &str,
    nah: &[Vec<String>],
    commands: &[&str],
) -> Option<String> {
    let tainted = commands
        .iter()
        .flat_map(|c| TAINT.captures_iter(c).map(|m| m[1].to_owned()))
        .collect();
    let scan = Scan {
        env,
        cwd,
        project,
        tainted,
    };
    // `bash -c 'rm -rf /usr'` hands the script over as one word.
    let mut argvs = nah.to_vec();
    for argv in nah {
        let flag = argv
            .iter()
            .position(|w| matches!(w.to_ascii_lowercase().as_str(), "-c" | "/c" | "-command"));
        if let Some(script) = flag.and_then(|i| argv.get(i + 1)) {
            argvs.extend(rough_argvs(script));
        }
    }
    if let Some(why) = scan.run(&argvs, false) {
        return Some(why);
    }
    for c in commands {
        // The rough splitter cuts a substitution into pieces, which leaves a
        // target that is only `$` or empty; the collapsed text tells that
        // form apart from `"$(pwd)/build"`.
        if let Some(why) = scan.run(&rough_argvs(c), true) {
            return Some(why);
        }
        if (c.contains("$(") || c.contains('`'))
            && let Some(why) = scan.run(&rough_argvs(&collapse_substitutions(c)), false)
        {
            return Some(why);
        }
    }
    None
}

impl Scan<'_> {
    /// The commands in order. `lenient` drops the targets the rough splitter
    /// may have cut out of a substitution.
    fn run(&self, argvs: &[Vec<String>], lenient: bool) -> Option<String> {
        let mut cd = false;
        for argv in argvs {
            let words: Vec<String> = argv.iter().map(|w| w.replace(['"', '\''], "")).collect();
            let toks: Vec<&str> = words.iter().map(String::as_str).collect();
            let Some(first) = toks.first() else { continue };
            if matches!(
                prog_name(first, true).as_str(),
                "cd" | "pushd" | "chdir" | "set-location" | "sl"
            ) {
                cd = true;
                continue;
            }
            let Some(r) = removal(&toks) else { continue };
            for t in r.targets {
                if let Some(why) = self.target(t, r.recursive, cd, lenient) {
                    return Some(format!("{t} is {why}"));
                }
            }
        }
        None
    }

    fn target(&self, t: &str, recursive: bool, cd: bool, lenient: bool) -> Option<&'static str> {
        const SUBST: &str = "only the output of a command";
        if t.is_empty() {
            return (!lenient && recursive).then_some(SUBST);
        }
        if t.chars().all(|c| c == '\\') {
            return Some("made only of backslashes");
        }
        let t = collapse_substitutions(&t.replace('\\', "/"));
        if t == SUB {
            return recursive.then_some(SUBST);
        }
        if lenient && (t == "$" || t.ends_with("/$")) {
            return None;
        }
        // `~/$(cmd)`: the command may print nothing.
        if let Some(prefix) = t.strip_suffix(SUB) {
            return self.path_target(prefix, cd);
        }
        self.path_target(&t, cd)
    }

    fn path_target(&self, t: &str, cd: bool) -> Option<&'static str> {
        // `logs/*/*` and `logs/*/` reach every directory of the first glob.
        if t.strip_suffix("/*")
            .or_else(|| t.strip_suffix('/'))
            .is_some_and(|body| body.contains('*'))
        {
            return Some("a glob below a glob");
        }
        // `cd logs && rm -rf a/*`: a glob below a directory the call chose.
        if cd && t.ends_with("/*") {
            return Some("a glob after a cd");
        }
        // The directory a trailing glob or slash is directly under.
        let base = match t {
            "*" => ".",
            "/*" => "/",
            _ => t.strip_suffix("/*").unwrap_or(t),
        };
        let base = if base.len() > 1 {
            base.trim_end_matches('/')
        } else {
            base
        };
        let mut base = if base.is_empty() { "/" } else { base }.to_owned();
        if let Some(caps) = HOME_FORM.captures(&base) {
            let rest = caps.get(1).map_or("", |m| m.as_str());
            if self.env.home.is_empty() {
                let c = path_clean(if rest.is_empty() { "." } else { rest });
                return (c == "." || c.starts_with("..")).then_some("the home directory");
            }
            let home = self.env.slash(&self.env.home);
            base = if rest.is_empty() {
                home
            } else {
                format!("{}/{rest}", home.trim_end_matches('/'))
            };
        } else if t.starts_with('$') {
            return self.variable(t);
        }
        self.path(&base)
    }

    /// A target that starts with a variable.
    fn variable(&self, t: &str) -> Option<&'static str> {
        let caps = VAR_FORM.captures(t)?;
        let braced = caps.get(1).map(|m| m.as_str());
        let name = braced.unwrap_or_else(|| caps.get(2).map_or("", |m| m.as_str()));
        let name = name
            .split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
            .next()
            .unwrap_or_default();
        let guarded = braced.is_some_and(|b| b.contains('?'));
        let rest = caps.get(3).map_or("", |m| m.as_str());
        if matches!(rest, "" | "/" | "/*") && self.tainted.iter().any(|v| v == name) {
            return Some("the working directory, set from a variable");
        }
        if guarded {
            return None;
        }
        if matches!(rest, "/" | "/*") {
            return Some("directly below a variable");
        }
        let body = rest.strip_prefix('/')?;
        let body = body
            .strip_suffix("/*")
            .unwrap_or(body)
            .trim_end_matches('/');
        TOP_NAMES
            .contains(&body.to_lowercase().as_str())
            .then_some("a top-level directory below a variable")
    }

    /// A literal path.
    fn path(&self, base: &str) -> Option<&'static str> {
        let env = self.env;
        let lower = base.to_ascii_lowercase();
        if lower.starts_with("//?/volume{") || lower.starts_with("//./volume{") {
            return Some("a volume");
        }
        let mut p = base.to_owned();
        for pass in 0..2 {
            if let Some((letter, segs)) = drive_parts(&p, env.windows) {
                if segs.len() <= 1 {
                    return Some("a drive or a directory directly on it");
                }
                p = format!("{letter}:/{}", segs.join("/"));
                break;
            }
            if pass == 0 {
                p = env.normalize(&p, self.cwd);
            }
        }
        if !env.is_abs(&p) {
            let c = path_clean(&p);
            return (c == "." || c.starts_with("..")).then_some("the working directory or above");
        }
        let at = env.fold(p.trim_end_matches('/'));
        if p.starts_with('/') && !p.starts_with("//") && at.matches('/').count() <= 1 {
            return Some("the root or a directory directly in it");
        }
        let norm = |d: &str| env.fold(env.normalize(d, "").trim_end_matches('/'));
        if !env.home.is_empty() && at == norm(&env.home) {
            return Some("the home directory");
        }
        for d in [self.cwd, self.project] {
            if d.is_empty() {
                continue;
            }
            let d = norm(d);
            if d == at || d.starts_with(&format!("{at}/")) {
                return Some("the working or project directory, or one above it");
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    type Host = (Env, &'static str, &'static str);

    fn unix() -> Host {
        let env = Env {
            home: "/home/u".into(),
            ..Default::default()
        };
        (env, "/w/p/src", "/w/p")
    }

    fn win() -> Host {
        let env = Env {
            home: "C:/Users/u".into(),
            windows: true,
            ..Default::default()
        };
        (env, "C:/w/p/src", "C:/w/p")
    }

    fn crit(e: &Host, cmd: &str) -> bool {
        find(&e.0, e.1, e.2, &[], &[cmd]).is_some()
    }

    fn crit_nah(e: &Host, cmd: &str, nah: &[&[&str]]) -> bool {
        let nah: Vec<Vec<String>> = nah
            .iter()
            .map(|a| a.iter().map(|s| (*s).to_owned()).collect())
            .collect();
        find(&e.0, e.1, e.2, &nah, &[cmd]).is_some()
    }

    /// Forms that mean the same on either host.
    const BOTH: &[&str] = &[
        // root and its children
        "rm -rf /",
        "rm /usr",
        "rm -rf /usr",
        "rm -rf /usr/",
        "rm -rf /usr/*",
        "rm -rf /*",
        "rm -rf /data",
        "rmdir /etc",
        "sudo rm -rf /etc",
        "rm -rf -- /usr",
        // home
        "rm -rf ~",
        "rm -rf ~/",
        "rm -rf ~/*",
        "rm -rf $HOME",
        "rm -rf \"$HOME\"",
        "rm -rf ${HOME}/",
        "rm -rf $HOME/*",
        "rm -rf '%USERPROFILE%'",
        "rm -rf $env:USERPROFILE",
        "rm -rf ~/.",
        // cwd, project and their parents
        "rm -rf .",
        "rm -rf ./",
        "rm -rf ..",
        "rm -rf ../..",
        "rm -rf ../",
        "rm -rf ./*",
        "rm -rf *",
        "rm -rf ../*",
        "rm -rf ./../src",
        "rm -rf sub/..",
        // shell forms
        "rm -rf \"$DIR\"/*",
        "rm -rf $DIR/",
        "rm -rf \"$1\"/*",
        "rm -rf \"$@\"/",
        "rm -rf \"$DIR/usr\"",
        "rm -rf $DIR/Users",
        "rm -rf ${DIR}/tmp/",
        "D=$(pwd); rm -rf \"$D\"",
        "D=`pwd`; rm -rf $D",
        "ROOT=$(git rev-parse --show-toplevel) && rm -rf \"${ROOT:?}\"",
        "D=$PWD; rm -rf \"$D/\"",
        "rm -rf \"$(pwd)\"",
        "rm -rf `pwd`",
        "rm -rf $(dirname x)",
        "rm -rf ~/$(cmd)",
        "rm -rf ~/`cmd`",
        "rm -rf /usr/$(cmd)",
        "rm -rf \"\\\\\"",
        "rm -rf logs/*/*",
        "rm -rf logs/*/",
        "cd logs && rm -rf a/*",
        // wrappers and nesting
        "(rm -rf ~)",
        "echo \"$(rm -rf ~)\"",
        "bash -c 'rm -rf /usr'",
        "timeout 5 rm -rf /usr",
        "FOO=1 rm -rf /usr",
        "rm -rf build /usr",
        "ls; rm -rf /usr",
    ];

    const NEITHER: &[&str] = &[
        "rm -rf sub",
        "rm -rf ./build",
        "rm a.txt",
        "rm -rf /tmp/x",
        "rm -rf build/*",
        "rm -rf \"${DIR:?}\"/*",
        "rm -rf \"${DIR:?}/usr\"",
        "rm -rf $DIR",
        "rm -rf \"$DIR/build\"",
        "rm -rf $DIR/sub/*",
        "rm -rf ~/x",
        "rm -rf ~/.cache",
        "rm -rf $HOME/x",
        "rm -rf /w/p/src/build",
        "rm -rf /w/p/other",
        "rm -rf ../other",
        "rm -rf \"$(pwd)/build\"",
        "rm -rf \"$(pwd)\"/build",
        "rm -f \"$(pwd)\"",
        "rm -rf ~/$HOME",
        "git rm x",
        "git rm -rf /usr",
        "echo rm -rf /usr",
        "grep rm /usr",
        "ls /usr",
        "cd logs && rm -rf a",
        "D=$(date); rm -rf \"$D\"",
        "rm -rf a/*/b",
    ];

    #[test]
    fn critical_targets_on_unix_and_windows() {
        for e in [unix(), win()] {
            for c in BOTH {
                assert!(
                    crit(&e, c),
                    "windows={}: {c} should be critical",
                    e.0.windows
                );
            }
            for c in NEITHER {
                assert!(!crit(&e, c), "windows={}: {c} should pass", e.0.windows);
            }
        }
    }

    #[test]
    fn the_working_and_project_directories_by_absolute_spelling() {
        let u = unix();
        for c in [
            "rm -rf /w/p/src",
            "rm -rf /w/p/src/",
            "rm -rf /w/p",
            "rm -rf /w/p/*",
            "rm -rf /w",
            "rm -rf /w/p/src/../../p",
        ] {
            assert!(crit(&u, c), "{c}");
        }
        let w = win();
        for c in [
            r"rm -rf C:\w\p\src",
            r"rm -rf C:\w\p",
            r"rm -rf c:/W/P/SRC/",
            r"rm -rf /c/w/p",
            r"Remove-Item -Recurse -Force C:\w",
            r"rm -rf C:\w\p\*",
        ] {
            assert!(crit(&w, c), "{c}");
        }
        assert!(!crit(&w, r"rm -rf C:\w\p\src\build"));
        assert!(!crit(&w, r"rm -rf C:\w\q"));
        // Windows folds case, Unix does not.
        assert!(!crit(&u, "rm -rf /W/P/SRC"));
    }

    #[test]
    fn windows_drives_and_their_children() {
        let w = win();
        for c in [
            r"rm -rf C:\",
            "rm -rf C:/",
            "rm -rf C:",
            r"rm -rf C:\Windows",
            r"rm -rf C:\Windows\",
            r"rm -rf C:\*",
            r"rm -rf C:\Windows\*",
            r"rm -rf d:\data",
            "rm -rf /c/",
            "rm -rf /c",
            "rm -rf /c/Windows",
            r"rm -rf \\?\C:\",
            r"rm -rf \\?\C:\Windows",
            r"rm -rf \\localhost\C$",
            r"rm -rf \\localhost\C$\Windows",
            r"rm -rf \\?\Volume{12345678-1234-1234-1234-123456789abc}\a\b\c",
            r"rd /s /q C:\Windows",
            r"del /f /s /q C:\*",
            r"Remove-Item -Recurse -Force C:\",
            r"Remove-Item -Recurse $env:USERPROFILE",
            r"Remove-Item -Recurse %USERPROFILE%",
            r"rm -rf C:\Users\u",
            r"rm -rf C:\Users\u\*",
            r"rm -rf C:\Users",
        ] {
            assert!(crit(&w, c), "{c}");
        }
        for c in [
            r"rm -rf C:\Windows\System32",
            r"rm -rf C:\Users\u\x",
            r"rd /s /q build",
            r"Remove-Item -Recurse build",
            r"rm -rf \\host\share",
            r"rm -rf \\localhost\C$\a\b",
        ] {
            assert!(!crit(&w, c), "{c}");
        }
        // The spellings count on a Unix host too.
        let u = unix();
        for c in [r"rm -rf C:\", r"rm -rf \\?\C:\", r"rm -rf C:/Windows"] {
            assert!(crit(&u, c), "{c}");
        }
        // But `/c` is an ordinary directory there, and a child of root anyway.
        assert!(!crit(&u, "rm -rf /c/Windows"));
    }

    #[test]
    fn windows_8_3_short_home_names_are_out_of_scope() {
        // C:\Users\USERNA~1 is the home directory; nothing here expands it.
        assert!(!crit(&win(), r"rm -rf C:\Users\USERNA~1"));
    }

    #[test]
    fn nah_finds_what_the_rough_words_cannot() {
        let u = unix();
        // The rough splitter sees one word for the quoted script.
        assert!(crit_nah(&u, "x", &[&["bash", "-c", "rm -rf /usr"]]));
        assert!(crit_nah(&u, "x", &[&["bash", "-c", "ls; rm -rf /usr"]]));
        assert!(crit_nah(&u, "x", &[&["sudo", "rm", "-rf", "~"]]));
        assert!(crit_nah(&u, "x", &[&["cd", "logs"], &["rm", "-rf", "a/*"]]));
        assert!(crit_nah(&u, "x", &[&["rm", "-rf", "$(pwd)"]]));
        assert!(!crit_nah(&u, "x", &[&["rm", "-rf", "build"]]));
        assert!(!crit_nah(&u, "x", &[&["git", "rm", "/usr"]]));
        assert!(!crit_nah(&u, "x", &[&["rm", "-f", "$(pwd)"]]));
    }

    #[test]
    fn the_reason_names_the_target() {
        let u = unix();
        let why = find(&u.0, u.1, u.2, &[], &["rm -rf /usr"]).unwrap();
        assert!(why.contains("/usr"), "{why}");
    }
}
