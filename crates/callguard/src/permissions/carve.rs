//! `Read(!pattern)` in a deny or ask list: Claude's gitignore-style carve-out.
//!
//! The policy merge loses which layer wrote a rule, so the carve-outs are
//! attached to the rules before it while one layer is still alone
//! ([`attach`], called by the loader). A carved rule is then one string,
//! `Read(*.env) except Read(!sample.env)`: the merged policy shows it, its
//! `policy_rev` covers it, and the same rule without the carve-out in another
//! layer is a different string that stays. A `!` in the project file can only
//! ever narrow a rule of the project file.

use super::paths::{Anchor, PathSpec};
use super::{Rule, parse, quote_string};

const FAMILIES: [&str; 8] = [
    "Read",
    "Grep",
    "Glob",
    "LS",
    "Edit",
    "Write",
    "NotebookEdit",
    "MultiEdit",
];

const SEP: &str = " except ";

/// A carved rule's text as `(rule, carve-outs)`; None if it has no carve-out.
/// A separator counts only where a `Family(!` follows, so a path that contains
/// the word stays a path.
pub(super) fn split(text: &str) -> Option<(&str, Vec<&str>)> {
    let cuts: Vec<usize> = text
        .match_indices(&format!("){SEP}"))
        .map(|(i, _)| i)
        .filter(|i| {
            let rest = &text[i + 1 + SEP.len()..];
            FAMILIES
                .iter()
                .any(|f| rest.strip_prefix(f).is_some_and(|r| r.starts_with("(!")))
        })
        .collect();
    let first = *cuts.first()?;
    let mut parts = Vec::new();
    for (n, &c) in cuts.iter().enumerate() {
        let end = cuts.get(n + 1).map_or(text.len(), |next| next + 1);
        parts.push(&text[c + 1 + SEP.len()..end]);
    }
    Some((&text[..=first], parts))
}

/// A directory the rule blocks as a whole: its pattern ends in `/**` (a
/// trailing `/` is `/**`), or is `**`. A carve-out cannot reopen files in it.
pub(super) fn blocks_whole(s: &PathSpec) -> bool {
    s.rest == "**" || s.rest.ends_with("/**")
}

/// Attaches the `!` rules of one layer's one list to the rules before them in
/// that list, and drops them from it. Rules that cannot be read stay as they
/// are for the validation to report. The second value holds a warning for each
/// `!` that carves nothing.
pub(crate) fn attach(list: &[String], key: &str, src: &str) -> (Vec<String>, Vec<String>) {
    let mut out: Vec<String> = Vec::new();
    // Per entry of `out`: the family (write) of a rule a `!` can carve.
    let mut carvable: Vec<Option<bool>> = Vec::new();
    let mut warns = Vec::new();
    for text in list {
        match parse(text) {
            Ok(Rule::Negation { write, spec }) => {
                let nothing = |why: &str| {
                    format!(
                        "{src}: permissions.{key} {} carves nothing: {why}",
                        quote_string(text)
                    )
                };
                if spec.anchor != Anchor::Cwd {
                    warns.push(nothing(
                        "a `!` pattern is read relative to the working directory, so it cannot reach a rule anchored with /, ~/ or //",
                    ));
                    continue;
                }
                let mut hit = false;
                for (i, c) in carvable.iter().enumerate() {
                    if *c == Some(write) {
                        out[i] = format!("{}{SEP}{}", out[i].trim(), text.trim());
                        hit = true;
                    }
                }
                if !hit {
                    warns.push(nothing(
                        "no rule before it in this list is a bare or ./ path pattern that does not block a directory whole (ending in /**)",
                    ));
                }
            }
            Ok(Rule::Path {
                write,
                spec: Some(s),
                ..
            }) => {
                carvable.push((s.anchor == Anchor::Cwd && !blocks_whole(&s)).then_some(write));
                out.push(text.clone());
            }
            _ => {
                carvable.push(None);
                out.push(text.clone());
            }
        }
    }
    (out, warns)
}
