use super::*;
use crate::nah::NahResult;
use crate::permissions::{candidate_hosts, strict_host};

// --- Policy rules -----------------------------------------------------------

struct Compiled {
    rule: policy::Rule,
    /// `rule.decision`, parsed.
    decision: Decision,
    command: Option<Regex>,
    url: Option<Regex>,
    hosts: Vec<String>,
    fields: BTreeMap<String, Regex>,
    path: Vec<Regex>,
    not_path: Vec<Regex>,
}

impl Compiled {
    fn matches(&self, call: &Call, read_only: &dyn Fn() -> bool) -> bool {
        let m = &self.rule.r#match;
        if !m.tool.is_empty() && !m.tool.contains(&call.tool) {
            return false;
        }
        if !m.kind.is_empty() && !m.kind.contains(&call.kind) {
            return false;
        }
        if !m.harness.is_empty() && !m.harness.contains(&call.harness) {
            return false;
        }
        if m.unattended.is_some_and(|u| u != call.unattended) {
            return false;
        }
        if m.read_only.is_some_and(|r| r != read_only()) {
            return false;
        }
        for (k, allowed) in &m.context {
            if !call.context.get(k).is_some_and(|v| allowed.contains(v)) {
                return false;
            }
        }
        // A regex rule reads every spelling of the command (see
        // `Call::command_joined`): deny and ask fire on any, allow needs all.
        let allow = self.decision == Decision::Allow;
        if let Some(re) = &self.command {
            let hit = |c: &str| !c.is_empty() && re.is_match(c);
            if call.command.is_empty()
                || if allow {
                    !call.commands().all(hit)
                } else {
                    !call.commands().any(hit)
                }
            {
                return false;
            }
        }
        // Like the command: deny and ask fire on any URL, allow needs all.
        if let Some(re) = &self.url
            && (call.urls.is_empty()
                || if allow {
                    !call.urls.iter().all(|u| re.is_match(u))
                } else {
                    !call.urls.iter().any(|u| re.is_match(u))
                })
        {
            return false;
        }
        // Like the URL regex: allow needs every URL to be a plain one with a
        // listed host, deny and ask fire on any host a URL could mean.
        if !self.hosts.is_empty() {
            let listed = |h: &str| self.hosts.iter().any(|x| x == h);
            let hit = |u: &String| {
                if allow {
                    strict_host(u).is_some_and(|h| listed(&h))
                } else {
                    candidate_hosts(u).iter().any(|h| listed(h))
                }
            };
            if call.urls.is_empty()
                || if allow {
                    !call.urls.iter().all(hit)
                } else {
                    !call.urls.iter().any(hit)
                }
            {
                return false;
            }
        }
        for (k, re) in &self.fields {
            if k == "*" {
                if !re.is_match(&call.whole) {
                    return false;
                }
            } else if !call.fields.get(k).is_some_and(|v| re.is_match(v)) {
                return false;
            }
        }
        let Some(path) = &call.path else {
            return m.in_project.is_none() && self.path.is_empty();
        };
        if m.in_project.is_none() && self.path.is_empty() && self.not_path.is_empty() {
            return true;
        }
        if allow && call.pattern_escapes {
            return false;
        }
        // The path conditions hold for the path as written, and for where it
        // really is. Deny and ask need one of them (a link into a protected
        // place fires), allow needs both, and a path that does not resolve
        // cannot be allowed.
        let lexical = self.path_ok(path, call.in_project);
        let real = call
            .real_path
            .as_deref()
            .is_some_and(|p| self.path_ok(p, call.real_in_project));
        if allow {
            lexical && real
        } else {
            lexical
                || real
                || call
                    .pattern_paths
                    .iter()
                    .any(|(p, inside)| self.path_ok(p, *inside))
        }
    }

    /// The path conditions for one form of a non-empty path.
    fn path_ok(&self, path: &str, in_project: bool) -> bool {
        self.rule
            .r#match
            .in_project
            .is_none_or(|ip| ip == in_project)
            && (self.path.is_empty() || self.path.iter().any(|re| re.is_match(path)))
            && !self.not_path.iter().any(|re| re.is_match(path))
    }
}

/// A compiled, ordered list of policy rules.
pub struct Set {
    rules: Vec<Compiled>,
    env: Env,
}

impl std::fmt::Debug for Set {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Set")
            .field("rules", &self.rules.len())
            .finish()
    }
}

fn compile_rule(r: &policy::Rule, env: &Env) -> Result<Compiled, String> {
    if r.id.is_empty() {
        return Err("missing id".into());
    }
    let Some(decision) = Decision::parse(&r.decision) else {
        return Err(format!(
            "decision {} must be allow, ask or deny",
            quote_string(&r.decision)
        ));
    };
    let m = &r.r#match;
    if m.is_empty() {
        return Err("no match conditions".into());
    }
    let re = |pat: &str, what: String| compile_regex(pat).map_err(|e| format!("{what}: {e}"));
    let mut c = Compiled {
        rule: r.clone(),
        decision,
        command: None,
        url: None,
        hosts: m.host.clone(),
        fields: BTreeMap::new(),
        path: Vec::new(),
        not_path: Vec::new(),
    };
    if !m.command.is_empty() {
        c.command = Some(re(&m.command, "match.command".into())?);
    }
    if !m.url.is_empty() {
        c.url = Some(re(&m.url, "match.url".into())?);
    }
    for h in &m.host {
        let plain = !h.is_empty()
            && h.split('.').all(|l| {
                !l.is_empty()
                    && l.chars()
                        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
            });
        if !plain {
            return Err(format!(
                "match.host {}: a host is a lower-case name such as docs.rs",
                quote_string(h)
            ));
        }
    }
    for (k, v) in &m.field {
        c.fields.insert(
            k.clone(),
            re(v, format!("match.field[{}]", quote_string(k)))?,
        );
    }
    for g in &m.path {
        c.path.push(
            env.compile_glob(g)
                .map_err(|e| format!("match.path: {e}"))?,
        );
    }
    for g in &m.not_path {
        c.not_path.push(
            env.compile_glob(g)
                .map_err(|e| format!("match.not_path: {e}"))?,
        );
    }
    Ok(c)
}

/// The rule that decided a call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Matched {
    pub id: String,
    pub description: String,
    pub decision: Decision,
}

impl Set {
    /// Validates and compiles rules. The error names the offending rule.
    pub fn compile(rules: &[policy::Rule], env: &Env) -> Result<Set, RulesError> {
        let mut set = Vec::with_capacity(rules.len());
        for r in rules {
            set.push(
                compile_rule(r, env)
                    .map_err(|e| RulesError(format!("rule {}: {e}", quote_string(&r.id))))?,
            );
        }
        Ok(Set {
            rules: set,
            env: env.clone(),
        })
    }

    /// The matching rule that wins: deny over ask over allow, then list order.
    /// (Named `match_call` because `match` is a keyword.) Rules that ask for
    /// read-only commands never match here: they need nah's parse.
    #[cfg(test)]
    pub(crate) fn match_call(&self, call: &Call) -> Option<Matched> {
        self.match_with(call, None)
    }

    /// [`Set::match_call`] with nah's answer for the call, if there is one.
    pub(crate) fn match_with(&self, call: &Call, nah: Option<&NahResult>) -> Option<Matched> {
        let read_only = || self.read_only(call, nah);
        let mut best: Option<&Compiled> = None;
        for c in &self.rules {
            if !c.matches(call, &read_only) {
                continue;
            }
            if best.is_none_or(|b| c.decision > b.decision) {
                best = Some(c);
            }
        }
        best.map(|c| Matched {
            id: c.rule.id.clone(),
            description: c.rule.description.clone(),
            decision: c.decision,
        })
    }

    /// Whether the call is made only of read-only commands on files in the
    /// project. A path that a deny or ask rule would stop a `Read` of does not
    /// count (`secret-read` stops `cat .env` too).
    fn read_only(&self, call: &Call, nah: Option<&NahResult>) -> bool {
        if call.kind != KIND_SHELL {
            return false;
        }
        let flagged = |path: &str| {
            let input = serde_json::json!({ "file_path": path }).to_string();
            let read = Call::new(
                CallInput {
                    harness: call.harness.clone(),
                    tool: "Read".into(),
                    input: RawValue::from_string(input).ok(),
                    cwd: call.cwd.clone(),
                    project_dir: call.project_dir.clone(),
                    ..Default::default()
                },
                &self.env,
            );
            self.rules.iter().any(|c| {
                c.decision != Decision::Allow
                    && c.rule.r#match.read_only.is_none()
                    && c.matches(&read, &|| false)
            })
        };
        crate::permissions::read_only(&self.env, call, nah, &flagged)
    }
}
