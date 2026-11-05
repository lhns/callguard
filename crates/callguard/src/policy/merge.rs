use super::*;

/// Replaces the rule with the same id in place, else appends.
fn upsert_rule(rules: &mut Vec<Rule>, r: &Rule) {
    match rules.iter_mut().find(|x| x.id == r.id) {
        Some(slot) => *slot = r.clone(),
        None => rules.push(r.clone()),
    }
}

/// Applies the system layer over `base` with full authority. A rule whose id is
/// already present replaces that rule; others are appended.
pub(crate) fn merge_system(base: &Policy, sys: &Policy) -> Policy {
    let mut out = base.clone();
    if sys.r#final {
        out.r#final = true;
    }
    if !sys.mode.is_empty() {
        out.mode = sys.mode.clone();
    }
    if let Some(d) = sys.defaults {
        out.defaults = Some(d);
        if !d {
            out.rules.clear(); // base holds only the default rules at this point
        }
    }
    out.disable_builtin = [base.disable_builtin.clone(), sys.disable_builtin.clone()].concat();
    if !sys.unattended_ask.is_empty() {
        out.unattended_ask = sys.unattended_ask.clone();
    }
    if sys.deadline_ms > 0 {
        out.deadline_ms = sys.deadline_ms;
    }
    for r in &sys.rules {
        upsert_rule(&mut out.rules, r);
    }
    append_permissions(&mut out.permissions, &sys.permissions);
    if let Some(sn) = &sys.nah {
        let mut n = base.nah.clone().unwrap_or_default();
        if sn.enabled.is_some() {
            n.enabled = sn.enabled;
        }
        n.guards.extend(sn.guards.clone());
        if sn.timeout_ms > 0 {
            n.timeout_ms = sn.timeout_ms;
        }
        if sn.budget_ms > 0 {
            n.budget_ms = sn.budget_ms;
        } else {
            // A short hard deadline alone must not leave the default budget
            // above it, which would make the policy invalid.
            n.budget_ms = n.budget_ms.min(n.timeout_ms);
        }
        if !sn.mode.is_empty() {
            n.mode = sn.mode.clone();
        }
        out.nah = Some(n);
    }
    if let Some(sl) = &sys.llm {
        out.llm = Some(merge_llm(base.llm.clone().unwrap_or_default(), sl));
    }
    if !sys.backends.is_empty() {
        out.backends = base.backends.clone();
        out.backends.extend(sys.backends.clone());
    }
    if let Some(d) = &sys.deny_streak {
        out.deny_streak = Some(d.clone());
    }
    if let Some(l) = &sys.log {
        out.log = Some(l.clone());
    }
    out
}

/// Adds the rules of `src` after those already in `dst`, skipping repeats.
/// Allow rules arrive vetted (see `permissions::vet_allow_list`).
fn append_permissions(dst: &mut Permissions, src: &Permissions) {
    for (to, from) in [
        (&mut dst.deny, &src.deny),
        (&mut dst.ask, &src.ask),
        (&mut dst.allow, &src.allow),
    ] {
        for r in from {
            if !to.contains(r) {
                to.push(r.clone());
            }
        }
    }
}

fn merge_llm(mut b: Llm, s: &Llm) -> Llm {
    if s.enabled.is_some() {
        b.enabled = s.enabled;
    }
    if !s.mode.is_empty() {
        b.mode = s.mode.clone();
    }
    if !s.backend.is_empty() {
        b.backend = s.backend.clone();
    }
    if s.timeout_ms > 0 {
        b.timeout_ms = s.timeout_ms;
    }
    if s.min_confidence.is_some() {
        b.min_confidence = s.min_confidence;
    }
    if let Some(st) = &s.transcript {
        let mut t = b.transcript.clone().unwrap_or_default();
        if st.max_messages > 0 {
            t.max_messages = st.max_messages;
        }
        if st.max_bytes > 0 {
            t.max_bytes = st.max_bytes;
        }
        b.transcript = Some(t);
    }
    // Absent, `null` and `[]` all mean "not set" (a written-out policy omits
    // empty lists), and an explicit empty list never loosened anything.
    if !s.environment.is_empty() {
        b.environment = s.environment.clone();
    }
    b.block.extend(s.block.iter().cloned());
    if !s.allow_exceptions.is_empty() {
        b.allow_exceptions = s.allow_exceptions.clone();
    }
    b
}

/// Applies a user or project layer: it may add deny/ask rules, append
/// `llm.block` and raise `llm.min_confidence`; everything else is dropped, each
/// drop reported as a warning naming `src` and the key.
pub(crate) fn merge_tighten(base: &Policy, layer: &Policy, src: &str) -> (Policy, Vec<String>) {
    const ONLY: &str =
        "this layer can only add deny/ask rules, append llm.block and raise llm.min_confidence";
    let mut warns: Vec<String> = Vec::new();
    let mut dropped = |key: &str, why: &str| warns.push(format!("{src}: {key} ignored: {why}"));
    let mut out = base.clone();
    if layer.r#final {
        dropped("final", ONLY);
    }
    if !layer.mode.is_empty() {
        dropped("mode", ONLY);
    }
    if layer.defaults.is_some() {
        dropped("defaults", ONLY);
    }
    if !layer.disable_builtin.is_empty() {
        dropped("disable_builtin", ONLY);
    }
    if !layer.unattended_ask.is_empty() {
        dropped("unattended_ask", ONLY);
    }
    if let Some(n) = &layer.nah {
        // Guards can only be switched on: that tightens nah.
        let mut cp = out.nah.take().unwrap_or_default();
        for (name, on) in &n.guards {
            if *on {
                cp.guards.insert(name.clone(), true);
            } else {
                dropped(
                    &format!("nah.guards.{name}"),
                    "a guard can only be switched on from this layer",
                );
            }
        }
        out.nah = Some(cp);
        if n.enabled.is_some() {
            dropped("nah.enabled", ONLY);
        }
        if n.timeout_ms != 0 {
            dropped("nah.timeout_ms", ONLY);
        }
        if n.budget_ms != 0 {
            dropped("nah.budget_ms", ONLY);
        }
        if !n.mode.is_empty() {
            dropped("nah.mode", ONLY);
        }
    }
    if !layer.backends.is_empty() {
        dropped("backends", ONLY);
    }
    if layer.deny_streak.is_some() {
        dropped("deny_streak", ONLY);
    }
    if layer.deadline_ms != 0 {
        dropped("deadline_ms", ONLY);
    }
    if layer.log.is_some() {
        dropped("log", ONLY);
    }
    for r in &layer.rules {
        if r.decision == "allow" {
            dropped(
                &format!("rules.{}", r.id),
                "allow rules are not accepted from this layer",
            );
            continue;
        }
        out.rules.push(r.clone()); // never replaces a lower layer's rule by id
    }
    append_permissions(&mut out.permissions, &layer.permissions);
    if let Some(l) = &layer.llm {
        let mut cp = base.llm.clone().unwrap_or_default();
        if l.enabled.is_some() {
            dropped("llm.enabled", ONLY);
        }
        if !l.mode.is_empty() {
            dropped("llm.mode", ONLY);
        }
        if !l.backend.is_empty() {
            dropped("llm.backend", ONLY);
        }
        if l.timeout_ms != 0 {
            dropped("llm.timeout_ms", ONLY);
        }
        if l.transcript.is_some() {
            dropped("llm.transcript", ONLY);
        }
        if !l.environment.is_empty() {
            dropped("llm.environment", ONLY);
        }
        if !l.allow_exceptions.is_empty() {
            dropped("llm.allow_exceptions", ONLY);
        }
        cp.block.extend(l.block.iter().cloned());
        if let Some(c) = l.min_confidence {
            if c > cp.min_confidence.unwrap_or(0.0) {
                cp.min_confidence = Some(c);
            } else {
                dropped("llm.min_confidence", "may only be raised");
            }
        }
        out.llm = Some(cp);
    }
    (out, warns)
}
