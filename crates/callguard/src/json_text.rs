//! JSON text with no whitespace outside strings and `<`, `>`, `&`, U+2028 and
//! U+2029 escaped inside them. The policy hash and the logs are pinned to this
//! form, and raw values are compacted to it too.
//!
//! The escaping is a safety property of the judge prompt: no value can contain
//! a literal `</transcript>` or start a line with markup. serde_json writes
//! those characters raw, so everything that must keep this form goes through here.

use serde::Serialize;

/// Drops whitespace outside strings. `s` must be valid JSON.
pub fn compact(s: &str) -> String {
    rewrite(s, true, false)
}

/// Compacts valid JSON text and escapes its strings (the form of [`to_string`],
/// raw values included).
pub fn escape(s: &str) -> String {
    rewrite(s, true, true)
}

/// `v` as compact, escaped JSON.
pub fn to_string<T: Serialize + ?Sized>(v: &T) -> Result<String, serde_json::Error> {
    serde_json::to_string(v).map(|s| escape(&s))
}

/// `v` as JSON indented by two spaces, escaped.
pub fn to_string_indent<T: Serialize + ?Sized>(v: &T) -> Result<String, serde_json::Error> {
    serde_json::to_string_pretty(v).map(|s| rewrite(&s, false, true))
}

fn rewrite(s: &str, compact: bool, html: bool) -> String {
    let mut out = String::with_capacity(s.len());
    let (mut in_str, mut esc) = (false, false);
    for c in s.chars() {
        if !in_str {
            if c == '"' {
                in_str = true;
                out.push(c);
            } else if !compact || !matches!(c, ' ' | '\t' | '\n' | '\r') {
                out.push(c);
            }
            continue;
        }
        if esc {
            esc = false;
            out.push(c);
            continue;
        }
        match c {
            '\\' => {
                esc = true;
                out.push(c);
            }
            '"' => {
                in_str = false;
                out.push(c);
            }
            '<' if html => out.push_str("\\u003c"),
            '>' if html => out.push_str("\\u003e"),
            '&' if html => out.push_str("\\u0026"),
            '\u{2028}' if html => out.push_str("\\u2028"),
            '\u{2029}' if html => out.push_str("\\u2029"),
            _ => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escapes_markup_and_line_separators() {
        let want = "\"a\\u003cb\\u003e\\u0026c\\u2028\\u2029\\\"\\\\\"";
        assert_eq!(to_string("a<b>&c\u{2028}\u{2029}\"\\").unwrap(), want);
    }

    #[test]
    fn compacts_raw_messages_but_not_strings() {
        let raw =
            serde_json::value::RawValue::from_string("{ \"a\" : [1, 2],\n \"b\":\"x  y\" }".into())
                .unwrap();
        assert_eq!(to_string(&raw).unwrap(), r#"{"a":[1,2],"b":"x  y"}"#);
        assert_eq!(compact("{ \"a\": \"<\" }"), r#"{"a":"<"}"#);
    }

    #[test]
    fn escaped_quote_does_not_end_the_string() {
        assert_eq!(escape(r#"{"a": "q\" <"}"#), "{\"a\":\"q\\\" \\u003c\"}");
    }
}
