use super::*;

#[test]
fn the_policy_dialect_keeps_its_regex_text() {
    // Expected strings come from the compiler before it moved here.
    for (pat, want) in [
        ("/p/*/x", "^/p/[^/]*/x$"),
        ("/p/**/x", "^/p/(?:.*/)?x$"),
        ("**/id_rsa*", "^(?:.*/)?id_rsa[^/]*$"),
        ("/p/a**b", "^/p/a.*b$"),
        ("/p/[ab]", "^/p/[ab]$"),
        ("/p/[!ab]", "^/p/[^ab]$"),
        ("/p/a/**", "^/p/a(?:/.*)?$"),
        ("**", "^.*$"),
        ("/p/?", "^/p/[^/]$"),
        ("/p/a+b(c)", r"^/p/a\+b\(c\)$"),
        ("/p/é.txt", r"^/p/é\.txt$"),
    ] {
        let re = compile(pat, Dialect::Policy { caseless: false }).unwrap();
        assert_eq!(re.as_str(), format!("(?s){want}"), "{pat}");
        let re = compile(pat, Dialect::Policy { caseless: true }).unwrap();
        assert_eq!(re.as_str(), format!("(?s)(?i){want}"), "{pat}");
    }
    let p = Dialect::Policy { caseless: false };
    // Quirks kept: `[!a]` can match `/`, an unclosed `[` is an error.
    assert!(compile("/p/[!a]", p).unwrap().is_match("/p//"));
    assert!(compile("/p/[ab", p).is_err());
}

fn rule(pat: &str, path: &str, classes: bool) -> bool {
    compile(pat, Dialect::PathRule { classes })
        .unwrap()
        .is_match(path)
}

#[test]
fn the_path_rule_dialect_tricky_cases() {
    // (pattern, path, classes, matches); the first run of the old matcher and
    // the new compiler agreed on 400000 generated pairs, these pin the corners.
    for (pat, path, classes, want) in [
        ("/a/**", "/a", true, true),
        ("/a/**", "/a/b/c", true, true),
        ("**/b", "b", true, true),
        ("**/b", "/x/b", true, true),
        ("**", "", true, true),
        ("/a/**/b", "/a/b", true, true),
        ("/a/**/b", "/a/x/y/b", true, true),
        ("/a/x**y", "/a/x/y", true, false),
        ("/a/x**y", "/a/xzy", true, true),
        ("/a/*", "/a/b/c", true, false),
        ("/a/?", "/a/", true, false),
        ("/a/[b]", "/a/b", true, true),
        ("/a/[b]", "/a/b", false, false),
        ("/a/[b]", "/a/[b]", false, true),
        ("/a/[b]", "/a/[b]", true, true),
        ("/a/[!b]", "/a/c", true, true),
        ("/a/[!b]", "/a/b", true, false),
        ("/a/[^b]", "/a/c", true, true),
        ("/a/[!b]", "/a//", true, false),
        ("/a/[z-a]", "/a/m", true, false),
        ("/a/[!z-a]", "/a/m", true, true),
        ("/a/[", "/a/[", true, true),
        ("/a/[]a]", "/a/]", true, true),
        ("/a/]", "/a/]", true, true),
        ("/a/é", "/a/é", true, true),
        ("/a/*", "/a/x\ny", true, true),
    ] {
        assert_eq!(rule(pat, path, classes), want, "{pat:?} {path:?} {classes}");
    }
}

#[test]
fn a_pattern_too_big_to_compile_is_an_error() {
    let big = format!("/{}", "?".repeat(500_000));
    assert!(compile(&big, Dialect::PathRule { classes: true }).is_err());
}
