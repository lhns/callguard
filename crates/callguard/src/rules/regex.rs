use super::*;

// --- RE2 semantics ---------------------------------------------------

/// `\s` in RE2: `[\t\n\f\r ]`.
const RE2_SPACE: &str = r"\t\n\f\r ";

/// Whether `chars[i..]` starts a repetition `{n}`, `{n,}` or `{n,m}`; returns
/// its length. RE2 reads any other `{` as a literal, the `regex` crate fails.
fn repeat_len(chars: &[char], i: usize) -> Option<usize> {
    let mut j = i + 1;
    let digits = |j: &mut usize| {
        let start = *j;
        while chars.get(*j).is_some_and(char::is_ascii_digit) {
            *j += 1;
        }
        *j > start
    };
    if !digits(&mut j) {
        return None;
    }
    if chars.get(j) == Some(&',') {
        j += 1;
        digits(&mut j);
    }
    (chars.get(j) == Some(&'}')).then(|| j + 1 - i)
}

/// Rewrites an RE2 pattern into the `regex` crate's syntax with the same
/// meaning: ASCII `\b \B \s \S \w \W \d \D`, `\Q..\E`, literal `\<` `\>`,
/// literal `{` and `&&` `~~` inside classes.
fn translate_regex(pat: &str) -> String {
    let chars: Vec<char> = pat.chars().collect();
    let mut out = String::with_capacity(pat.len() + 16);
    let mut in_class = false;
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        i += 1;
        if c == '\\' {
            let Some(&e) = chars.get(i) else {
                out.push('\\'); // the regex crate reports the trailing backslash
                break;
            };
            i += 1;
            match e {
                'b' if !in_class => out.push_str(r"(?-u:\b)"),
                'B' if !in_class => out.push_str(r"(?-u:\B)"),
                's' if in_class => out.push_str(RE2_SPACE),
                's' => out.push_str(&format!("[{RE2_SPACE}]")),
                'S' => out.push_str(&format!("[^{RE2_SPACE}]")),
                'd' if in_class => out.push_str("0-9"),
                'd' => out.push_str("[0-9]"),
                'D' => out.push_str("[^0-9]"),
                'w' if in_class => out.push_str("0-9A-Za-z_"),
                'w' => out.push_str("[0-9A-Za-z_]"),
                'W' => out.push_str("[^0-9A-Za-z_]"),
                '<' | '>' => out.push(e),
                // RE2: `\0` and `\1`..`\7` followed by an octal digit are octal
                // codes; a lone `\1`..`\9` is a backreference, which RE2 refuses.
                // `\9` is refused by the regex crate for the same reason.
                '1'..='9'
                    if !(e <= '7' && chars.get(i).is_some_and(|d| ('0'..='7').contains(d))) =>
                {
                    out.push_str(r"\9");
                }
                'Q' => {
                    while i < chars.len() {
                        if chars[i] == '\\' && chars.get(i + 1) == Some(&'E') {
                            i += 2;
                            break;
                        }
                        out.push_str(&::regex::escape(&chars[i].to_string()));
                        i += 1;
                    }
                }
                'p' | 'P' | 'x' if chars.get(i) == Some(&'{') => {
                    out.push('\\');
                    out.push(e);
                    while i < chars.len() {
                        out.push(chars[i]);
                        i += 1;
                        if chars[i - 1] == '}' {
                            break;
                        }
                    }
                }
                _ => {
                    out.push('\\');
                    out.push(e);
                }
            }
            continue;
        }
        if in_class {
            match c {
                ']' => {
                    in_class = false;
                    out.push(']');
                }
                '[' if chars.get(i) == Some(&':') => {
                    // A POSIX class [:alpha:] is copied whole.
                    let rest: String = chars[i..].iter().collect();
                    if let Some(end) = rest.find(":]") {
                        out.push('[');
                        out.push_str(&rest[..end + 2]);
                        i += rest[..end + 2].chars().count();
                    } else {
                        out.push_str(r"\[");
                    }
                }
                '[' => out.push_str(r"\["),
                '&' => out.push_str(r"\&"),
                '~' => out.push_str(r"\~"),
                _ => out.push(c),
            }
            continue;
        }
        match c {
            '[' => {
                in_class = true;
                out.push('[');
                if chars.get(i) == Some(&'^') {
                    out.push('^');
                    i += 1;
                }
                if chars.get(i) == Some(&']') {
                    out.push_str(r"\]"); // a leading ] is a literal
                    i += 1;
                }
            }
            '{' => match repeat_len(&chars, i - 1) {
                Some(n) => {
                    out.extend(&chars[i - 1..i - 1 + n]);
                    i = i - 1 + n;
                }
                None => out.push_str(r"\{"),
            },
            _ => out.push(c),
        }
    }
    out
}

/// Compiles an RE2 pattern with its RE2 meaning (see the module comment).
pub(crate) fn compile_regex(pat: &str) -> Result<Regex, RulesError> {
    // Octal escapes (`\101`) are RE2 syntax. The size limit stays at its
    // default: a repository's policy must not cost compile time.
    ::regex::RegexBuilder::new(&translate_regex(pat))
        .octal(true)
        .build()
        .map_err(|e| RulesError(e.to_string()))
}

/// For regexes that are part of the program.
pub(crate) fn builtin_regex(pat: &str) -> Regex {
    compile_regex(pat).unwrap_or_else(|e| panic!("built-in regex {pat:?}: {e}"))
}
