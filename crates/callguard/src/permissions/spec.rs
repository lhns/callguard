//! `Bash(...)` specs matched on argv tokens, never on joined text, and the
//! raw-text fallback that backs deny and ask when nah's parse has a hole.

use std::collections::HashSet;

/// One token of a spec.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Tok {
    Lit(String),
    /// Contains `*` among other characters: globs within one argv token.
    Glob(String),
    /// Exactly `*`: one or more argv tokens.
    Any,
}

/// A parsed `Bash(spec)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Spec {
    pub toks: Vec<Tok>,
}

/// Splits `s` into words with shell-style quotes. `Err` on an unbalanced quote.
pub(super) fn shell_words(s: &str) -> Result<Vec<String>, String> {
    let mut words = Vec::new();
    let mut cur = String::new();
    let mut in_word = false;
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        match c {
            ' ' | '\t' | '\n' | '\r' => {
                if in_word {
                    words.push(std::mem::take(&mut cur));
                    in_word = false;
                }
            }
            '\'' => {
                in_word = true;
                loop {
                    match chars.next() {
                        Some('\'') => break,
                        Some(c) => cur.push(c),
                        None => return Err("unbalanced quote".into()),
                    }
                }
            }
            '"' => {
                in_word = true;
                loop {
                    match chars.next() {
                        Some('"') => break,
                        Some('\\') => match chars.clone().next() {
                            Some(e @ ('"' | '\\')) => {
                                chars.next();
                                cur.push(e);
                            }
                            _ => cur.push('\\'),
                        },
                        Some(c) => cur.push(c),
                        None => return Err("unbalanced quote".into()),
                    }
                }
            }
            // A backslash is a path separator unless it escapes a quote or a space.
            '\\' => {
                in_word = true;
                match chars.clone().next() {
                    Some(e @ ('\'' | '"' | ' ')) => {
                        chars.next();
                        cur.push(e);
                    }
                    _ => cur.push('\\'),
                }
            }
            c => {
                in_word = true;
                cur.push(c);
            }
        }
    }
    if in_word {
        words.push(cur);
    }
    Ok(words)
}

impl Spec {
    /// Parses the text between the parentheses of a `Bash` rule. A trailing
    /// `:*` means a trailing ` *`; anywhere else the colon is literal.
    pub fn parse(spec: &str) -> Result<Spec, String> {
        let spec = spec.trim();
        let owned;
        let spec = match spec.strip_suffix(":*") {
            Some(head) => {
                owned = format!("{head} *");
                owned.as_str()
            }
            None => spec,
        };
        let words = shell_words(spec)?;
        if words.is_empty() {
            return Err("empty command pattern".into());
        }
        // Claude ignores `Bash(command:...)`; a rule that never matches is
        // worse here.
        if words[0].starts_with("command:") {
            return Err("`command:` is not a pattern; write the command itself".into());
        }
        let toks = words
            .into_iter()
            .map(|w| {
                if w == "*" {
                    Tok::Any
                } else if w.contains('*') {
                    Tok::Glob(w)
                } else {
                    Tok::Lit(w)
                }
            })
            .collect();
        Ok(Spec { toks })
    }

    pub fn has_wildcard(&self) -> bool {
        self.toks.iter().any(|t| !matches!(t, Tok::Lit(_)))
    }

    /// `Bash(*)` and `Bash(:*)`: every command.
    pub fn is_blanket(&self) -> bool {
        self.toks == [Tok::Any]
    }

    /// The first token, as written.
    pub fn first(&self) -> &Tok {
        &self.toks[0]
    }

    /// The only wildcard is a final `*` token.
    fn trailing_only(&self) -> bool {
        matches!(self.toks.last(), Some(Tok::Any))
            && self.toks[..self.toks.len() - 1]
                .iter()
                .all(|t| matches!(t, Tok::Lit(_)))
    }

    /// Whether `argv` matches. With `norm`, the program names (rule and argv)
    /// are compared by base name, without `.exe`, folded when `caseless`.
    /// `prefix` accepts trailing argv tokens after the last spec token (the
    /// raw-text fallback). A runaway match (`work` steps) counts as `on_limit`.
    pub fn matches(
        &self,
        argv: &[String],
        norm: Option<bool>,
        prefix: bool,
        on_limit: bool,
        work: &mut usize,
    ) -> bool {
        if argv.is_empty() {
            return false;
        }
        let (mut a0, mut t0) = (None, None);
        if let Some(caseless) = norm {
            a0 = Some(prog_name(&argv[0], caseless));
            if let Tok::Lit(l) = &self.toks[0] {
                t0 = Some(Tok::Lit(prog_name(l, caseless)));
            }
        }
        let mut m = Matcher {
            toks: &self.toks,
            args: argv,
            a0,
            t0,
            prefix,
            strict: norm.is_none() && !prefix,
            only_trailing: self.trailing_only(),
            failed: HashSet::new(),
            work,
            exhausted: false,
        };
        let r = m.go(0, 0);
        if m.exhausted { on_limit } else { r }
    }
}

struct Matcher<'a> {
    toks: &'a [Tok],
    args: &'a [String],
    /// Replace the first argv word / first spec token (normalised names).
    a0: Option<String>,
    t0: Option<Tok>,
    prefix: bool,
    /// Allow: a final glob token must end the argv.
    strict: bool,
    only_trailing: bool,
    failed: HashSet<(usize, usize)>,
    work: &'a mut usize,
    exhausted: bool,
}

impl Matcher<'_> {
    fn arg(&self, j: usize) -> &str {
        match (&self.a0, j) {
            (Some(a), 0) => a,
            _ => &self.args[j],
        }
    }

    fn go(&mut self, i: usize, j: usize) -> bool {
        if *self.work == 0 {
            self.exhausted = true;
            return false;
        }
        *self.work -= 1;
        let (nt, na) = (self.toks.len(), self.args.len());
        if i == nt {
            return self.prefix || j == na;
        }
        if self.failed.contains(&(i, j)) {
            return false;
        }
        let last = i + 1 == nt;
        let tok = match (&self.t0, i) {
            (Some(t), 0) => t.clone(),
            _ => self.toks[i].clone(),
        };
        let ok = match &tok {
            Tok::Lit(s) => j < na && self.arg(j) == s && self.go(i + 1, j + 1),
            Tok::Glob(p) => {
                j < na
                    && glob(p, self.arg(j))
                    && if last && !self.strict {
                        true
                    } else {
                        self.go(i + 1, j + 1)
                    }
            }
            Tok::Any => {
                if last && self.only_trailing {
                    true // zero or more
                } else if last {
                    j < na
                } else {
                    (j + 1..=na).any(|k| !self.exhausted && self.go(i + 1, k))
                }
            }
        };
        if !ok {
            self.failed.insert((i, j));
        }
        ok
    }
}

/// `*` matches any run of characters (none included) in one token.
pub(super) fn glob(pat: &str, s: &str) -> bool {
    glob_match(pat, s, false, false)
}

/// The ranges of a `[...]` class; a single character is a range of one.
type Ranges = Vec<(char, char)>;

/// One element of a compiled glob.
enum Piece {
    Star,
    /// `?`: one character.
    One,
    /// `[a-c]`, `[!a]`, `[^a]`.
    Class(Ranges, bool),
    Lit(char),
}

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

/// Glob matching on one path segment or token: `*` matches any run of
/// characters (none included), with `question` a `?` matches one character,
/// with `classes` a `[...]` matches one character of its set (otherwise `[`
/// is a letter).
pub(super) fn glob_match(pat: &str, s: &str, question: bool, classes: bool) -> bool {
    let p: Vec<char> = pat.chars().collect();
    let mut pieces = Vec::new();
    let mut k = 0;
    while k < p.len() {
        let (piece, len) = match p[k] {
            '*' => (Piece::Star, 1),
            '?' if question => (Piece::One, 1),
            '[' if classes => match class(&p[k..]) {
                Some((ranges, negated, len)) => (Piece::Class(ranges, negated), len),
                None => (Piece::Lit('['), 1),
            },
            c => (Piece::Lit(c), 1),
        };
        pieces.push(piece);
        k += len;
    }
    let t: Vec<char> = s.chars().collect();
    let one = |piece: &Piece, c: char| match piece {
        Piece::One => true,
        Piece::Class(ranges, negated) => {
            ranges.iter().any(|&(lo, hi)| (lo..=hi).contains(&c)) != *negated
        }
        Piece::Lit(l) => *l == c,
        Piece::Star => false,
    };
    let (mut pi, mut ti) = (0, 0);
    let (mut star, mut mark) = (None, 0);
    while ti < t.len() {
        if matches!(pieces.get(pi), Some(Piece::Star)) {
            star = Some(pi);
            mark = ti;
            pi += 1;
        } else if pieces.get(pi).is_some_and(|piece| one(piece, t[ti])) {
            pi += 1;
            ti += 1;
        } else if let Some(sp) = star {
            pi = sp + 1;
            mark += 1;
            ti = mark;
        } else {
            return false;
        }
    }
    while matches!(pieces.get(pi), Some(Piece::Star)) {
        pi += 1;
    }
    pi == pieces.len()
}

/// The program name of a command word: base name without `.exe`, folded when
/// `caseless`.
pub(crate) fn prog_name(word: &str, caseless: bool) -> String {
    let base = word.rsplit(['/', '\\']).next().unwrap_or(word);
    let lower = base.to_ascii_lowercase();
    let base = [".exe", ".cmd", ".bat", ".com", ".ps1"]
        .iter()
        .find(|e| lower.ends_with(**e))
        .map_or(base, |e| &base[..base.len() - e.len()]);
    if caseless {
        base.to_lowercase()
    } else {
        base.to_owned()
    }
}

/// `argv` without git's global options (`git -C x push` becomes `git push`).
/// Returns None if `argv[0]` is not git or nothing was removed.
pub(super) fn strip_git_globals(argv: &[String], caseless: bool) -> Option<Vec<String>> {
    if argv.is_empty() || prog_name(&argv[0], caseless) != "git" {
        return None;
    }
    let mut i = 1;
    while let Some(a) = argv.get(i) {
        let a = a.as_str();
        match a {
            "-C" | "-c" | "--git-dir" | "--work-tree" | "--namespace" | "--config-env"
            | "--super-prefix" | "--attr-source" => i += 2,
            "--no-pager"
            | "-p"
            | "--paginate"
            | "--bare"
            | "--no-replace-objects"
            | "--literal-pathspecs"
            | "--exec-path" => i += 1,
            _ if ["--git-dir=", "--work-tree=", "--namespace=", "--exec-path="]
                .iter()
                .any(|p| a.starts_with(p)) =>
            {
                i += 1;
            }
            _ if a.starts_with('-') => i += 1, // an option nobody listed: skip it
            _ => break,
        }
    }
    let i = i.min(argv.len());
    (i > 1).then(|| {
        std::iter::once(argv[0].clone())
            .chain(argv[i..].iter().cloned())
            .collect()
    })
}

/// Steps one deny or ask match may take before it counts as a match.
pub(super) const WORK_LIMIT: usize = 200_000;

/// Deny and ask on one nah call with known argv: the rule matches the
/// normalised call, or the call with git's global options removed.
pub(super) fn matches_call(spec: &Spec, argv: &[String], caseless: bool) -> bool {
    let mut work = WORK_LIMIT;
    if spec.matches(argv, Some(caseless), false, true, &mut work) {
        return true;
    }
    match strip_git_globals(argv, caseless) {
        Some(stripped) => spec.matches(&stripped, Some(caseless), false, true, &mut work),
        None => false,
    }
}

/// The raw command split into segments of words: quotes and backslashes are
/// dropped (what they enclose splits like anything else), and whitespace and
/// shell operators end a word, operators also a segment. Over-splitting is the
/// point: a false deny is fine, a miss is not.
pub(super) fn raw_segments(command: &str, drop_backslash: bool) -> Vec<Vec<String>> {
    let mut segs: Vec<Vec<String>> = Vec::new();
    let mut cur: Vec<String> = Vec::new();
    let mut word = String::new();
    for c in command.chars() {
        match c {
            '\'' | '"' => {}
            '\\' if drop_backslash => {}
            ' ' | '\t' | '\r' | '\u{b}' | '\u{c}' => {
                if !word.is_empty() {
                    cur.push(std::mem::take(&mut word));
                }
            }
            ';' | '&' | '|' | '(' | ')' | '<' | '>' | '\n' | '`' | '{' | '}' => {
                if !word.is_empty() {
                    cur.push(std::mem::take(&mut word));
                }
                if !cur.is_empty() {
                    segs.push(std::mem::take(&mut cur));
                }
            }
            c => word.push(c),
        }
    }
    if !word.is_empty() {
        cur.push(word);
    }
    if !cur.is_empty() {
        segs.push(cur);
    }
    segs
}

/// The raw-text fallback: the rule's tokens appear consecutively at any
/// position of any segment, the first by base name. A rule with `Bash`'s
/// shape "every command" is the caller's business.
pub(super) fn matches_raw(spec: &Spec, command: &str, caseless: bool) -> bool {
    let mut work = WORK_LIMIT * 5;
    // A backslash escapes in a POSIX shell and separates in a Windows path:
    // try the command both ways.
    let segments = [true, false]
        .into_iter()
        .flat_map(|d| raw_segments(command, d));
    for seg in segments {
        // A leading `*` absorbs any prefix, so one start covers them all.
        let leading_any = matches!(spec.first(), Tok::Any);
        for s in 0..seg.len() {
            if leading_any && s > 0 {
                break;
            }
            let argv = &seg[s..];
            if spec.matches(argv, Some(caseless), true, true, &mut work) {
                return true;
            }
            if let Some(stripped) = strip_git_globals(argv, caseless)
                && spec.matches(&stripped, Some(caseless), true, true, &mut work)
            {
                return true;
            }
            if work == 0 {
                return true;
            }
        }
    }
    false
}
