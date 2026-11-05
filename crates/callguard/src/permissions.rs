//! Permission rules in Claude Code's syntax (`Bash(git push:*)`,
//! `Read(~/.ssh/**)`, `WebFetch(domain:example.com)`, `mcp__server__tool`),
//! matched on nah's parse where there is one.
//!
//! Deny and ask look for a match anywhere: in any call nah found, and in the
//! raw text whenever the parse has a hole. Allow is the opposite: it needs nah
//! and an independent lexer to agree that every command of the call is one the
//! rules name, with nothing around them (assignments, redirects, expansions)
//! that argv would hide. Anything else goes on to the judge.
//!
//! Where this differs from Claude's documentation:
//! - Specs match argv tokens, never joined text. Deny and ask also match a call
//!   whose program is given by path or whose git global options come first
//!   (`git -C . push`), which Claude's rule does not.
//! - Allow is stricter: wrappers (`timeout`, `env`, `cd x &&`), assignments,
//!   redirects and expansions send the call to the judge, programs compare
//!   literally, and a long list of open-ended programs and blanket patterns is
//!   dropped in every layer (the project layer has more limits).
//! - `Write`, `NotebookEdit` and `MultiEdit` rules mean `Edit`; `Grep`, `Glob`
//!   and `LS` mean `Read`. Claude accepts them and never matches.
//! - `/x` anchors at the project directory in every layer (Claude: at the
//!   settings source). `!` negation and `{a,b}` alternatives are not
//!   supported (such a rule cannot be read). `[a-c]` and `[!a]` are classes in
//!   deny and ask, which also match the literal text; allow matches the
//!   literal text only, so `src/[id].tsx` works and never widens.
//! - A deny or ask rule that cannot be read fails the policy (Claude skips it),
//!   including `Bash(command:...)` and `Tool(param:value)`.
//! - A backslash in a spec is a path separator unless it escapes a quote or a
//!   space; quoting a `*` does not make it literal.
//! - Hosts are read by this module, not by a URL parser: allow takes only the
//!   plain `http(s)://host[:port]/` shape, deny and ask test every host a
//!   tricky URL could mean.
//! - Limits shared with Claude: path rules cover tool calls, not what a shell
//!   command reads or writes. A call with no path (opencode `patch`) matches
//!   only a bare `Edit`; a relative path with no working directory matches
//!   no path rule.

mod lexer;
mod paths;
mod spec;
mod web;

use crate::nah::{NahResult, NahVerdict};
use crate::policy::{self, quote_string};
use crate::rules::{Call, Env, KIND_FETCH, KIND_READ, KIND_SHELL, KIND_WRITE, RulesError, kind_of};
use crate::schema::Decision;

use paths::{Ctx, PathSpec};
pub(crate) use spec::prog_name;
use spec::{Spec, Tok};
use web::{Domain, Mcp};

const WEBFETCH_TOOLS: [&str; 3] = ["WebFetch", "webfetch", "web_extract"];
const WEBSEARCH_TOOLS: [&str; 3] = ["WebSearch", "websearch", "web_search"];
/// The only shell tools an allow rule can match.
const ALLOW_SHELL_TOOLS: [&str; 3] = ["Bash", "bash", "terminal"];

/// A rule read from its text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Rule {
    /// `Bash`, `Bash(spec)`, `PowerShell`, `PowerShell(spec)`.
    Shell {
        powershell: bool,
        spec: Option<Spec>,
    },
    /// `Read(path)` and friends (`write` false), `Edit(path)` and friends.
    Path {
        write: bool,
        spec: Option<PathSpec>,
    },
    /// `WebFetch`, `WebFetch(domain:host)`.
    Fetch {
        domain: Option<Domain>,
    },
    /// Bare `WebSearch`.
    Search,
    Mcp(Mcp),
    /// Any other bare name: that tool, exactly.
    Tool(String),
}

/// Whether `c` can hide text from a person reading it: a control character
/// (an escape sequence that moves the cursor or erases a line), a Unicode line
/// separator or a bidirectional mark.
fn is_hiding(c: char) -> bool {
    c.is_control()
        || matches!(
            c,
            '\u{061c}' | '\u{200e}' | '\u{200f}' | '\u{2028}' | '\u{2029}' | '\u{202a}'
                ..='\u{202e}' | '\u{2066}'..='\u{2069}'
        )
}

/// `s` with every character that can hide text written as `\u{..}`, for
/// showing a rule to a person.
pub fn escape_unprintable(s: &str) -> String {
    s.chars()
        .map(|c| {
            if is_hiding(c) {
                format!("\\u{{{:04x}}}", c as u32)
            } else {
                c.to_string()
            }
        })
        .collect()
}

/// Reads one rule. The error says what is wrong with it. A rule with a
/// control or bidirectional character is refused in every layer: a deny or ask
/// rule fails validation, an allow rule is dropped.
pub(crate) fn parse(text: &str) -> Result<Rule, String> {
    if text.chars().any(is_hiding) {
        return Err("contains a control or bidirectional character".into());
    }
    let text = text.trim();
    let (name, spec) = match text.split_once('(') {
        Some((n, rest)) => match rest.strip_suffix(')') {
            Some(s) => (n.trim(), Some(s)),
            None => return Err("missing closing parenthesis".into()),
        },
        None => (text, None),
    };
    if name.is_empty() {
        return Err("no tool name".into());
    }
    if name.starts_with("mcp__") {
        if spec.is_some() {
            return Err("an mcp__ rule takes no parentheses".into());
        }
        return Ok(Rule::Mcp(Mcp::parse(name)?));
    }
    let write_family = ["Edit", "Write", "NotebookEdit", "MultiEdit"];
    let read_family = ["Read", "Grep", "Glob", "LS"];
    match (name, spec) {
        ("Bash" | "PowerShell", s) => Ok(Rule::Shell {
            powershell: name == "PowerShell",
            spec: s.map(Spec::parse).transpose()?,
        }),
        (n, s) if write_family.contains(&n) || read_family.contains(&n) => Ok(Rule::Path {
            write: write_family.contains(&n),
            spec: s.map(PathSpec::parse).transpose()?,
        }),
        ("WebFetch", s) => Ok(Rule::Fetch {
            domain: s.map(Domain::parse).transpose()?,
        }),
        ("WebSearch", None) => Ok(Rule::Search),
        (_, Some(_)) => Err(format!("{name}(...) rules are not supported")),
        (n, None) => {
            if n.contains(|c: char| c.is_whitespace() || c == '*' || c == ')') {
                return Err(format!("{n:?} is not a tool name"));
            }
            Ok(Rule::Tool(n.to_owned()))
        }
    }
}

mod vet;
pub use vet::*;

// --- The compiled set ----------------------------------------------------------------

struct Entry {
    text: String,
    rule: Rule,
}

/// Resolves symlinks: a normalized path in, its real location in POSIX form.
type Resolver = Box<dyn Fn(&Env, &str) -> Option<String> + Send + Sync>;

/// A permission rule that fired.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hit {
    pub decision: Decision,
    pub rule: String,
    pub reason: String,
}

/// The compiled `permissions` of a policy.
pub struct Permissions {
    deny: Vec<Entry>,
    ask: Vec<Entry>,
    allow: Vec<Entry>,
    env: Env,
    resolver: Resolver,
}

impl std::fmt::Debug for Permissions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Permissions")
            .field("deny", &self.deny.len())
            .field("ask", &self.ask.len())
            .field("allow", &self.allow.len())
            .finish()
    }
}

impl Permissions {
    /// Compiles the rules. A deny or ask rule that cannot be read is an error;
    /// an allow rule that cannot be read, or that loosens too far, is dropped
    /// and reported in the second value.
    pub fn compile(
        p: &policy::Permissions,
        env: &Env,
    ) -> Result<(Permissions, Vec<String>), RulesError> {
        let mut out = Permissions {
            deny: Vec::new(),
            ask: Vec::new(),
            allow: Vec::new(),
            env: env.clone(),
            resolver: Box::new(paths::resolve),
        };
        for (key, list, dst) in [
            ("deny", &p.deny, &mut out.deny),
            ("ask", &p.ask, &mut out.ask),
        ] {
            for (i, text) in list.iter().enumerate() {
                let rule = parse(text).map_err(|e| {
                    RulesError(format!(
                        "permissions.{key}[{i}] {}: {e}",
                        quote_string(text)
                    ))
                })?;
                dst.push(Entry {
                    text: text.trim().to_owned(),
                    rule,
                });
            }
        }
        let mut warns = Vec::new();
        for text in &p.allow {
            match vet_allow(text, None) {
                Ok(rule) => out.allow.push(Entry {
                    text: text.trim().to_owned(),
                    rule,
                }),
                Err(why) => warns.push(format!(
                    "permissions.allow {} dropped: {why}",
                    quote_string(text)
                )),
            }
        }
        Ok((out, warns))
    }

    /// Replaces the symlink resolver (tests).
    #[cfg(test)]
    fn with_resolver(mut self, r: Resolver) -> Permissions {
        self.resolver = r;
        self
    }

    /// The rule that decides `call`: the first deny, else the first ask, else
    /// an allow. `nah` is nah's result for this very call, if it gave one.
    pub fn check(&self, call: &Call, nah: Option<&NahResult>) -> Option<Hit> {
        let hit = |decision, e: &Entry| Hit {
            decision,
            rule: e.text.clone(),
            reason: format!("permission rule {}", e.text),
        };
        if let Some(e) = self.deny.iter().find(|e| self.matches(e, call, nah)) {
            return Some(hit(Decision::Deny, e));
        }
        if let Some(e) = self.ask.iter().find(|e| self.matches(e, call, nah)) {
            return Some(hit(Decision::Ask, e));
        }
        self.allowed(call, nah).map(|text| Hit {
            decision: Decision::Allow,
            reason: format!("permission rule {text}"),
            rule: text,
        })
    }

    // --- deny and ask ---

    fn matches(&self, e: &Entry, call: &Call, nah: Option<&NahResult>) -> bool {
        match &e.rule {
            Rule::Shell { powershell, spec } => {
                call.kind == KIND_SHELL
                    && (!powershell || call.tool == "PowerShell")
                    && spec
                        .as_ref()
                        .is_none_or(|s| s.is_blanket() || self.shell_match(s, call, nah))
            }
            Rule::Path { write, spec } => {
                call.kind == if *write { KIND_WRITE } else { KIND_READ }
                    && spec
                        .as_ref()
                        .is_none_or(|s| self.path_match(s, call, false))
            }
            Rule::Fetch { domain } => {
                WEBFETCH_TOOLS.contains(&call.tool.as_str())
                    && domain.as_ref().is_none_or(|d| {
                        let urls = &call.urls;
                        urls.is_empty()
                            || urls.iter().any(|u| {
                                let hosts = web::candidate_hosts(u);
                                hosts.is_empty() || hosts.iter().any(|h| d.matches(h))
                            })
                    })
            }
            Rule::Search => WEBSEARCH_TOOLS.contains(&call.tool.as_str()),
            Rule::Mcp(m) => m.matches(&call.tool, false),
            Rule::Tool(n) => call.tool == *n,
        }
    }

    /// A shell rule for deny or ask: any command nah found, else the raw text
    /// when the parse has a hole.
    fn shell_match(&self, spec: &Spec, call: &Call, nah: Option<&NahResult>) -> bool {
        let caseless = self.env.caseless();
        if let Some(n) = nah {
            for c in &n.calls {
                if let Some(argv) = c.argv.as_ref().filter(|a| !a.is_empty())
                    && spec::matches_call(spec, argv, caseless)
                {
                    return true;
                }
            }
        }
        parse_has_hole(call, nah)
            && call
                .commands()
                .any(|cmd| spec::matches_raw(spec, cmd, caseless))
    }

    fn ctx(&self, call: &Call) -> Ctx {
        let cwd = paths::dir_posix(&self.env, &call.cwd);
        let project = paths::dir_posix(&self.env, &call.project_dir).or_else(|| cwd.clone());
        Ctx {
            home: paths::dir_posix(&self.env, &self.env.home).unwrap_or_default(),
            cwd,
            project,
            caseless: self.env.caseless(),
        }
    }

    /// A path rule. Deny and ask match if any path value, requested or
    /// resolved, matches. Allow needs one value, and both forms must match.
    fn path_match(&self, spec: &PathSpec, call: &Call, allow: bool) -> bool {
        let raw = &call.raw_paths;
        if raw.is_empty() || (allow && raw.len() != 1) {
            return false;
        }
        if allow && call.pattern_escapes {
            return false;
        }
        let ctx = self.ctx(call);
        // `Edit(**/hooks/*)` names no protected name, but may reach one.
        let guarded = allow && !names_protected(spec);
        let root = ctx.project.as_deref().or(ctx.cwd.as_deref());
        for r in raw {
            if allow && (paths::is_network(&self.env, r) || self.env.drive_relative(r)) {
                return false;
            }
            let norm = self.env.clean_names(&self.env.normalize(r, &call.cwd));
            let posix = paths::to_posix(&self.env, &norm);
            let resolved =
                (self.resolver)(&self.env, &norm).filter(|_| !self.env.drive_relative(r));
            if guarded
                && [Some(&posix), resolved.as_ref()]
                    .into_iter()
                    .flatten()
                    .any(|p| in_protected(p, root))
            {
                return false;
            }
            let requested = spec.matches(&posix, &ctx, allow);
            let real = resolved
                .as_ref()
                .is_some_and(|p| spec.matches(p, &ctx, allow));
            let hit = if allow {
                requested && real
            } else {
                requested || real
            };
            if hit {
                return true;
            }
        }
        // The files a read tool's pattern starts in, as rules.rs resolved them.
        !allow
            && call
                .pattern_paths
                .iter()
                .any(|(p, _)| spec.matches(&paths::to_posix(&self.env, p), &ctx, false))
    }

    // --- allow ---

    /// The text of the allow rule that lets `call` pass, if one does.
    fn allowed(&self, call: &Call, nah: Option<&NahResult>) -> Option<String> {
        if self.allow.is_empty() {
            return None;
        }
        if call.kind == KIND_SHELL {
            return self.allowed_shell(call, nah);
        }
        self.allow
            .iter()
            .find(|e| match &e.rule {
                Rule::Path { write, spec } => {
                    call.kind == if *write { KIND_WRITE } else { KIND_READ }
                        && spec
                            .as_ref()
                            .is_some_and(|s| self.path_match(s, call, true))
                }
                Rule::Fetch { domain: Some(d) } => {
                    WEBFETCH_TOOLS.contains(&call.tool.as_str()) && {
                        let urls = &call.urls;
                        urls.len() == 1 && web::strict_host(&urls[0]).is_some_and(|h| d.matches(&h))
                    }
                }
                Rule::Search => WEBSEARCH_TOOLS.contains(&call.tool.as_str()),
                Rule::Mcp(m) => m.matches(&call.tool, true),
                Rule::Tool(n) => call.tool == *n,
                Rule::Shell { .. } | Rule::Fetch { domain: None } => false,
            })
            .map(|e| e.text.clone())
    }

    /// A shell command is allowed only if nah and the independent lexer both
    /// find nothing but commands the allow rules name, literally.
    fn allowed_shell(&self, call: &Call, nah: Option<&NahResult>) -> Option<String> {
        if !ALLOW_SHELL_TOOLS.contains(&call.tool.as_str()) {
            return None;
        }
        // A real, complete answer of nah for this call.
        let n = nah?;
        if n.verdict != NahVerdict::Delegate
            || n.coverage != "full"
            || n.facts.as_ref().is_none_or(|f| !f.gaps.is_empty())
            || n.calls.is_empty()
        {
            return None;
        }
        let specs: Vec<(&Entry, &Spec)> = self
            .allow
            .iter()
            .filter_map(|e| match &e.rule {
                Rule::Shell {
                    powershell: false,
                    spec: Some(s),
                } => Some((e, s)),
                _ => None,
            })
            .collect();
        let literal = |argv: &[String]| {
            specs.iter().find(|(_, s)| {
                let mut work = spec::WORK_LIMIT;
                s.matches(argv, spec::Mode::Allow, &mut work)
            })
        };
        if call.cwd.is_empty() {
            return None;
        }
        let want = self.env.fold(&self.env.normalize(&call.cwd, ""));
        let mut first = None;
        for c in &n.calls {
            let argv = c.argv.as_ref().filter(|a| !a.is_empty())?;
            let cwd = c.cwd.as_deref().filter(|c| !c.is_empty())?;
            if self.env.fold(&self.env.normalize(cwd, "")) != want {
                return None;
            }
            let (e, _) = literal(argv)?;
            first.get_or_insert(e);
        }
        // The second parser. One spelling of the command only: we cannot know
        // which one the harness runs.
        if call.raw_commands.len() != 1 {
            return None;
        }
        for seg in lexer::split(&call.raw_commands[0])? {
            literal(&seg)?;
        }
        first.map(|e| e.text.clone())
    }
}

/// Whether nah's parse of `call` leaves something unseen, so that deny and ask
/// must also look at the raw text.
pub(crate) fn parse_has_hole(call: &Call, nah: Option<&NahResult>) -> bool {
    let Some(n) = nah else {
        return true;
    };
    !ALLOW_SHELL_TOOLS.contains(&call.tool.as_str())
        || n.verdict != NahVerdict::Delegate
        || n.coverage != "full"
        || n.facts.as_ref().is_none_or(|f| !f.gaps.is_empty())
        || n.calls.is_empty()
        || n.calls
            .iter()
            .any(|c| c.argv.as_ref().is_none_or(Vec::is_empty))
}

#[cfg(test)]
mod tests;
