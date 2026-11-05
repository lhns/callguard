use super::*;

/// A string in double quotes with C-style escapes, for messages: one stable
/// spelling that shows control characters.
pub(crate) fn quote_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\x07' => out.push_str("\\a"),
            '\x08' => out.push_str("\\b"),
            '\x0c' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\x0b' => out.push_str("\\v"),
            c if (c as u32) < 0x20 || c == '\x7f' => out.push_str(&format!("\\x{:02x}", c as u32)),
            c if c.is_control() => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// Structural problems of `p`. Regexes and globs are checked by
/// `rules::Set::compile`. With `merged`, cross-references (llm.backend) are
/// checked too.
pub fn validate(p: &Policy, merged: bool) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let one_of = |v: &str, ok: &[&str]| v.is_empty() || ok.contains(&v);
    if !one_of(&p.mode, &[MODE_ENFORCE, MODE_SHADOW]) {
        out.push(format!(
            "mode {} must be enforce or shadow",
            quote_string(&p.mode)
        ));
    }
    if !one_of(&p.unattended_ask, &["deny", "ask"]) {
        out.push(format!(
            "unattended_ask {} must be deny or ask",
            quote_string(&p.unattended_ask)
        ));
    }
    if p.deadline_ms < 0 {
        out.push("deadline_ms must not be negative".into());
    }
    for id in &p.disable_builtin {
        if !BUILTIN_IDS.contains(&id.as_str()) {
            out.push(format!(
                "disable_builtin: unknown built-in rule {}",
                quote_string(id)
            ));
        }
    }
    // A deny or ask rule that cannot be read would silently never fire.
    for (list, key) in [(&p.permissions.deny, "deny"), (&p.permissions.ask, "ask")] {
        for (i, r) in list.iter().enumerate() {
            if let Err(e) = permissions::parse(r) {
                out.push(format!("permissions.{key}[{i}] {}: {e}", quote_string(r)));
            }
        }
    }
    for (i, r) in p.rules.iter().enumerate() {
        let mut name = format!("rules[{i}]");
        if !r.id.is_empty() {
            name.push_str(&format!(" ({})", r.id));
        }
        if r.id.is_empty() {
            out.push(format!("{name}: missing id"));
        }
        if !["allow", "ask", "deny"].contains(&r.decision.as_str()) {
            out.push(format!(
                "{name}: decision {} must be allow, ask or deny",
                quote_string(&r.decision)
            ));
        }
        if r.r#match.is_empty() {
            out.push(format!("{name}: rule has no match conditions"));
        }
    }
    if let Some(n) = &p.nah {
        if !one_of(&n.mode, &[MODE_ENFORCE, MODE_SHADOW]) {
            out.push(format!(
                "nah.mode {} must be enforce or shadow",
                quote_string(&n.mode)
            ));
        }
        if n.timeout_ms < 0 {
            out.push("nah.timeout_ms must not be negative".into());
        }
        if n.budget_ms < 0 {
            out.push("nah.budget_ms must not be negative".into());
        }
        if n.budget_ms > 0 && n.timeout_ms > 0 && n.budget_ms > n.timeout_ms {
            out.push(format!(
                "nah.budget_ms {} must not exceed nah.timeout_ms {}",
                n.budget_ms, n.timeout_ms
            ));
        }
        for (field, set) in [
            ("path", !n.path.is_empty()),
            ("require", n.require),
            ("engine", !n.engine.is_empty()),
        ] {
            if set {
                out.push(format!(
                    "nah.{field} is no longer supported: nah is built into callguard; remove it"
                ));
            }
        }
    }
    if let Some(l) = &p.llm {
        if !one_of(&l.mode, &[MODE_ENFORCE, MODE_SHADOW]) {
            out.push(format!(
                "llm.mode {} must be enforce or shadow",
                quote_string(&l.mode)
            ));
        }
        if l.min_confidence.is_some_and(|c| !(0.0..=1.0).contains(&c)) {
            out.push("llm.min_confidence must be in [0,1]".into());
        }
        if l.timeout_ms < 0 {
            out.push("llm.timeout_ms must not be negative".into());
        }
        if merged
            && p.llm_enabled()
            && !l.backend.is_empty()
            && !p.backends.contains_key(&l.backend)
        {
            out.push(format!(
                "llm.backend {} is not defined in backends",
                quote_string(&l.backend)
            ));
        }
    }
    for (k, b) in &p.backends {
        match b.r#type.as_str() {
            "anthropic" | "openai" | "fake" => {}
            "exec" => {
                if b.command.is_empty() {
                    out.push(format!("backends.{k}: exec backend needs command"));
                }
            }
            t => out.push(format!(
                "backends.{k}: unknown type {} (anthropic, openai, exec, fake)",
                quote_string(t)
            )),
        }
        if b.model.ends_with("-latest") {
            out.push(format!(
                "backends.{k}: model {} is a moving alias; use an exact model id",
                quote_string(&b.model)
            ));
        }
    }
    if let Some(d) = &p.deny_streak
        && (d.consecutive < 0 || d.total < 0)
    {
        out.push("deny_streak values must not be negative".into());
    }
    out
}
