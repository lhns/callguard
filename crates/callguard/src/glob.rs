//! The one path glob compiler. Two dialects exist because two kinds of rule
//! mean different things by a glob; both compile to a `Regex` over a
//! slash-separated absolute path.

use regex::Regex;

use crate::rules::{RulesError, compile_regex};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Dialect {
    /// Policy rules (`match.path`, protected paths). `*` and `?` stay in a
    /// segment; `**` crosses segments (`a**b` too), `**/` also matches nothing
    /// and a trailing `/**` also matches the directory itself. `[...]` is a
    /// regex class (`[!a]` can match `/`); an unclosed `[` is an error.
    Policy { caseless: bool },
    /// Permission rules (`Read(path)`, `Edit(path)`), segment by segment. A
    /// `**` segment is zero or more segments, `**` inside a segment is `*`,
    /// `*` and `?` stay in a segment. With `classes`, a segment that holds a
    /// `[...]` class matches as the class or as the letters; without, `[` is
    /// a letter, so a name like `[id].tsx` works and cannot widen. Case is the
    /// caller's to fold.
    PathRule { classes: bool },
}

/// Compiles `pattern` for `dialect`. The error gives only the reason: `pattern`
/// may be expanded, and the caller knows the text the user wrote.
pub(crate) fn compile(pattern: &str, dialect: Dialect) -> Result<Regex, RulesError> {
    match dialect {
        Dialect::Policy { caseless } => policy(pattern, caseless),
        Dialect::PathRule { classes } => path_rule(pattern, classes),
    }
}

fn policy(g: &str, caseless: bool) -> Result<Regex, RulesError> {
    // `(?s)`: a file name may hold a newline, which `.` would not cross.
    let mut b = String::from("(?s)");
    if caseless {
        b.push_str("(?i)");
    }
    b.push('^');
    let bytes = g.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let c = bytes[i];
        if c == b'/' && &g[i..] == "/**" {
            b.push_str("(?:/.*)?");
            i += 3;
        } else if c == b'*' && bytes.get(i + 1) == Some(&b'*') {
            let mut j = i;
            while j < bytes.len() && bytes[j] == b'*' {
                j += 1;
            }
            if j < bytes.len() && bytes[j] == b'/' && (i == 0 || bytes[i - 1] == b'/') {
                b.push_str("(?:.*/)?");
                j += 1;
            } else {
                b.push_str(".*");
            }
            i = j;
        } else if c == b'*' {
            b.push_str("[^/]*");
            i += 1;
        } else if c == b'?' {
            b.push_str("[^/]");
            i += 1;
        } else if c == b'[' {
            let Some(end) = g[i..].find(']') else {
                return Err(RulesError("unclosed [".to_owned()));
            };
            let class = &g[i + 1..i + end];
            let class = match class.strip_prefix('!') {
                Some(rest) => format!("^{rest}"),
                None => class.to_owned(),
            };
            b.push_str(&format!("[{class}]"));
            i += end + 1;
        } else {
            let ch = g[i..].chars().next().unwrap_or('\u{fffd}');
            b.push_str(&regex::escape(&ch.to_string()));
            i += ch.len_utf8();
        }
    }
    b.push('$');
    compile_regex(&b)
}

fn path_rule(pattern: &str, classes: bool) -> Result<Regex, RulesError> {
    // None is a `**` segment; neighbouring ones are one.
    let mut items: Vec<Option<String>> = Vec::new();
    for seg in pattern.split('/') {
        if seg == "**" {
            if items.last() != Some(&None) {
                items.push(None);
            }
        } else {
            items.push(Some(segment(seg, classes)));
        }
    }
    let mut b = String::from("(?s)^");
    for (i, item) in items.iter().enumerate() {
        match item {
            // The only item: any path.
            None if items.len() == 1 => b.push_str("[^/]*(?:/[^/]*)*"),
            // Leading: each skipped segment brings its slash.
            None if i == 0 => b.push_str("(?:[^/]*/)*"),
            None => b.push_str("(?:/[^/]*)*"),
            Some(seg) => {
                // After a leading `**` the slash is already there.
                if i > 0 && !(i == 1 && items[0].is_none()) {
                    b.push('/');
                }
                b.push_str(seg);
            }
        }
    }
    b.push('$');
    regex::Regex::new(&b).map_err(|e| RulesError(e.to_string()))
}

/// One path segment as regex text.
fn segment(seg: &str, classes: bool) -> String {
    let seg = seg.replace("**", "*");
    let p: Vec<char> = seg.chars().collect();
    let letters = build(&p, false);
    if classes && has_class(&p) {
        format!("(?:{letters}|{})", build(&p, true))
    } else {
        letters
    }
}

fn has_class(p: &[char]) -> bool {
    (0..p.len()).any(|k| p[k] == '[' && class(&p[k..]).is_some())
}

fn build(p: &[char], classes: bool) -> String {
    let mut out = String::new();
    let mut k = 0;
    while k < p.len() {
        match p[k] {
            '*' => out.push_str("[^/]*"),
            '?' => out.push_str("[^/]"),
            '[' if classes => {
                if let Some((ranges, negated, len)) = class(&p[k..]) {
                    out.push_str(&class_regex(&ranges, negated));
                    k += len;
                    continue;
                }
                out.push_str(r"\[");
            }
            c => out.push_str(&regex::escape(&c.to_string())),
        }
        k += 1;
    }
    out
}

/// The ranges of a `[...]` class; a single character is a range of one.
type Ranges = Vec<(char, char)>;

/// Reads `[...]` at the start of `p`: its ranges, whether it is negated, and
/// the characters it spans. None if it is not closed (then `[` is a letter).
fn class(p: &[char]) -> Option<(Ranges, bool, usize)> {
    let negated = matches!(p.get(1), Some('!' | '^'));
    let start = 1 + usize::from(negated);
    // A `]` right after the opening is a member, as in POSIX.
    let end = (start + 1..p.len()).find(|&k| p[k] == ']')?;
    let body = &p[start..end];
    let mut ranges = Vec::new();
    let mut k = 0;
    while k < body.len() {
        if body.get(k + 1) == Some(&'-') && k + 2 < body.len() {
            ranges.push((body[k], body[k + 2]));
            k += 3;
        } else {
            ranges.push((body[k], body[k]));
            k += 1;
        }
    }
    Some((ranges, negated, end + 1))
}

/// One character of the class, never `/`. A reversed range holds nothing.
fn class_regex(ranges: &Ranges, negated: bool) -> String {
    let hex = |c: char| format!("\\x{{{:X}}}", c as u32);
    let members: String = ranges
        .iter()
        .filter(|(lo, hi)| lo <= hi)
        .map(|&(lo, hi)| format!("{}-{}", hex(lo), hex(hi)))
        .collect();
    match (members.is_empty(), negated) {
        (true, true) => "[^/]".into(),
        (true, false) => r"[^\x{0}-\x{10FFFF}]".into(),
        (false, true) => format!("[[^{members}]&&[^/]]"),
        (false, false) => format!("[[{members}]&&[^/]]"),
    }
}

#[cfg(test)]
mod tests;
