//! An independent, deliberately timid splitter of a POSIX shell command, used
//! to back an allow rule. It shares nothing with nah: an allow needs two
//! parsers that agree, and this one refuses (returns None) the moment the
//! command uses anything that could hide a second command or change what the
//! first does.

/// Redirects that cannot change what runs; removed before splitting.
const HARMLESS: [&str; 3] = ["2>/dev/null", ">/dev/null", "2>&1"];

struct State {
    segs: Vec<Vec<String>>,
    cur: Vec<String>,
    word: String,
    in_word: bool,
    /// An `&&`, `||` or `|` waits for its right-hand side.
    pending: bool,
}

impl State {
    /// Ends the current word. `None` if it is an assignment (`FOO=1 cmd`).
    fn end_word(&mut self) -> Option<()> {
        if self.in_word {
            let w = std::mem::take(&mut self.word);
            if self.cur.is_empty() && w.contains('=') {
                return None;
            }
            self.cur.push(w);
            self.in_word = false;
            self.pending = false;
        }
        Some(())
    }

    /// Ends the current segment at a separator. `None` if it is empty.
    fn end_seg(&mut self) -> Option<()> {
        self.end_word()?;
        if self.cur.is_empty() {
            return None;
        }
        self.segs.push(std::mem::take(&mut self.cur));
        Some(())
    }
}

/// The words of each command of `cmd`, or None to refuse the whole command.
pub(crate) fn split(cmd: &str) -> Option<Vec<Vec<String>>> {
    let cmd = cmd.trim_matches([' ', '\t', '\n']);
    let c: Vec<char> = cmd.chars().collect();
    let mut st = State {
        segs: Vec::new(),
        cur: Vec::new(),
        word: String::new(),
        in_word: false,
        pending: false,
    };
    let mut i = 0;
    'outer: while i < c.len() {
        if !st.in_word {
            for r in HARMLESS {
                let rc: Vec<char> = r.chars().collect();
                if c[i..].starts_with(&rc)
                    && c.get(i + rc.len())
                        .is_none_or(|n| matches!(n, ' ' | '\t' | '\n' | ';' | '&' | '|'))
                {
                    i += rc.len();
                    continue 'outer;
                }
            }
        }
        let ch = c[i];
        i += 1;
        match ch {
            ' ' | '\t' => st.end_word()?,
            '\n' => {
                st.end_word()?;
                if !st.cur.is_empty() {
                    st.end_seg()?;
                }
            }
            ';' => st.end_seg()?,
            '&' => {
                if c.get(i) != Some(&'&') {
                    return None; // background job
                }
                i += 1;
                st.end_seg()?;
                st.pending = true;
            }
            '|' => {
                match c.get(i) {
                    Some('&') => return None,
                    Some('|') => i += 1,
                    _ => {}
                }
                st.end_seg()?;
                st.pending = true;
            }
            '\'' => {
                st.in_word = true;
                loop {
                    let q = *c.get(i)?;
                    i += 1;
                    if q == '\'' {
                        break;
                    }
                    st.word.push(q);
                }
            }
            '"' => {
                st.in_word = true;
                loop {
                    let q = *c.get(i)?;
                    i += 1;
                    match q {
                        '"' => break,
                        '$' | '`' | '\\' => return None,
                        q => st.word.push(q),
                    }
                }
            }
            '$' | '`' | '<' | '>' | '(' | ')' | '{' | '}' | '#' | '*' | '?' | '[' | '~' | '!'
            | '\\' => return None,
            ch if ch.is_control() => return None,
            ch => {
                st.in_word = true;
                st.word.push(ch);
            }
        }
    }
    st.end_word()?;
    if !st.cur.is_empty() {
        st.segs.push(std::mem::take(&mut st.cur));
    }
    if st.pending || st.segs.is_empty() {
        return None;
    }
    Some(st.segs)
}
