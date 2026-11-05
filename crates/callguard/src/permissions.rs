//! Permission rules in Claude Code's syntax (`Bash(git push:*)`,
//! `Read(~/.ssh/**)`, `WebFetch(domain:example.com)`, `mcp__server__tool`),
//! matched on nah's parse where there is one.
//!
//! Deny and ask look for a match anywhere: in any call nah found, and in the
//! raw text whenever the parse has a hole. Allow is the opposite: it needs nah
//! and an independent lexer to agree that every command of the call is one the
//! rules name, with nothing around them (assignments, redirects, expansions)
//! that argv would hide. Anything else goes on to the judge. The same gate lets
//! the built-in read-only commands through (`readonly`, rule
//! `read-only-command`).
//!
//! Where this differs from Claude's documentation:
//! - Specs match argv tokens, never joined text. Deny and ask also match a call
//!   whose program is given by path or whose git global options come first
//!   (`git -C . push`), which Claude's rule does not.
//! - Allow is stricter: wrappers (`timeout`, `env`, `cd x &&`), assignments,
//!   redirects and expansions send the call to the judge, programs compare
//!   literally, and a long list of open-ended programs and blanket patterns is
//!   dropped in every layer (the project layer has more limits). Like Claude,
//!   an exact rule runs a command nah cannot look into (`npm test`, `pytest`)
//!   with no look inside; any other gap in nah's answer does not pass.
//! - `Skill(name)` compares the literal `skill` input; Claude's deny rule
//!   matches a skill under any of its names (alias, display name), which
//!   callguard does not know. Deny and ask ignore the arguments of the call, so
//!   `Skill(name)` also stops `name` with arguments.
//! - PowerShell deny and ask rules canonicalize the common aliases (`ri`,
//!   `rm`, `gci`, ...) and ignore case, as Claude does; the call is matched on
//!   its raw text because nah does not analyse PowerShell. PowerShell allow
//!   rules are refused in every layer: with no parse of nah's to agree with
//!   the lexer, nothing could make them safe.
//! - `Write`, `NotebookEdit` and `MultiEdit` rules mean `Edit`; `Grep`, `Glob`
//!   and `LS` mean `Read`. Claude accepts them and never matches.
//! - `/x` anchors at the project directory in every layer (Claude: at the
//!   settings source). `{a,b}` alternatives are not supported (such a rule
//!   cannot be read). `[a-c]` and `[!a]` are classes in
//!   deny and ask, which also match the literal text; allow matches the
//!   literal text only, so `src/[id].tsx` works and never widens.
//! - A deny or ask rule that cannot be read fails the policy (Claude skips it),
//!   including `Bash(command:...)` and the other primary fields in
//!   `Tool(param:value)`.
//! - `Tool(param:value)` is deny and ask only. For shell, path and WebFetch
//!   tools only the parameters in `params::known` count (`Bash(git:status)`
//!   stays a command); `Bash(timeout:*)` stays the program `timeout`.
//! - `!` carve-outs follow Claude's limits (only `path` and `./path` rules of
//!   the same list and tool family listed before it; none reopens a directory
//!   a rule blocks whole, meaning a pattern ending in `/**`), but join their
//!   rules when each layer is read, so a project's `!` cannot touch a system or
//!   user rule (see `carve`). Allow lists drop a `!` rule. A carved path is
//!   still stopped when its resolved path (a link's target) is not carved.
//! - A backslash in a spec is a path separator unless it escapes a quote or a
//!   space; quoting a `*` does not make it literal.
//! - Hosts are read by this module, not by a URL parser: allow takes only the
//!   plain `http(s)://host[:port]/` shape, deny and ask test every host a
//!   tricky URL could mean.
//! - Limits shared with Claude: path rules cover tool calls, not what a shell
//!   command reads or writes. A call with no path (opencode `patch`) matches
//!   only a bare `Edit`; a relative path with no working directory matches
//!   no path rule.

mod carve;
mod lexer;
mod params;
mod paths;
mod readonly;
mod spec;
mod web;

use crate::nah::{NahResult, NahVerdict};
use crate::policy::{self, quote_string};
use crate::rules::{
    Call, Env, KIND_AGENT, KIND_FETCH, KIND_READ, KIND_SHELL, KIND_WRITE, RulesError, kind_of,
};
use crate::schema::Decision;

use paths::{Ctx, PathSpec};
pub(crate) use readonly::read_only;
pub(crate) use spec::prog_name;
use spec::{Spec, Tok};
use web::{Domain, Mcp};
pub(crate) use web::{candidate_hosts, strict_host};

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
        /// Paths carved out by `!` rules of the same layer (see [`carve`]).
        carve: Vec<PathSpec>,
    },
    /// `Read(!pattern)` as written, before [`carve::attach`] joins it to the
    /// rules it carves. Only a deny or ask list may hold it.
    Negation {
        write: bool,
        spec: PathSpec,
    },
    /// `WebFetch`, `WebFetch(domain:host)`.
    Fetch {
        domain: Option<Domain>,
    },
    /// Bare `WebSearch`.
    Search,
    Mcp(Mcp),
    /// `Agent(name)`, `Task(name)`: a call of kind agent whose `subagent_type`
    /// is `name`, exactly; `*` is any named agent.
    Agent(String),
    /// `Skill(name)`, `Skill(name *)`, `Skill(skill:name)`: the `skill` input
    /// of a `Skill` call, literally. `*` in `name` is a wildcard.
    Skill {
        name: String,
        /// `name *`: any arguments. Without it an allow rule needs none.
        any_args: bool,
        /// Written `skill:name`: never an allow rule.
        by_param: bool,
    },
    /// `Tool(param:value)`: a top-level scalar input of `tool`, literally; `*`
    /// in `value` is a wildcard. Deny and ask only.
    Param {
        tool: String,
        param: String,
        value: String,
    },
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
    if let Some((head, carves)) = carve::split(text) {
        let Rule::Path {
            write,
            spec: Some(spec),
            ..
        } = parse(head)?
        else {
            return Err("only a path rule can have a `!` carve-out".into());
        };
        // The limits `carve::attach` applies: nothing is carved out of a
        // rule that blocks a directory whole or is not a bare or ./ pattern,
        // and a `!` pattern anchored with /, ~/ or // carves nothing.
        let carvable = spec.anchor == paths::Anchor::Cwd && !carve::blocks_whole(&spec);
        let mut carve = Vec::new();
        for c in carves {
            match parse(c)? {
                Rule::Negation { write: w, spec: n } if w == write => {
                    if carvable && n.anchor == paths::Anchor::Cwd {
                        carve.push(n);
                    }
                }
                _ => return Err("a carve-out must be a `!` rule of the same tool family".into()),
            }
        }
        return Ok(Rule::Path {
            write,
            spec: Some(spec),
            carve,
        });
    }
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
    if let Some(s) = spec
        && name != "Skill"
        && let Some(rule) = params::parse(name, s)?
    {
        return Ok(rule);
    }
    let write_family = ["Edit", "Write", "NotebookEdit", "MultiEdit"];
    let read_family = ["Read", "Grep", "Glob", "LS"];
    match (name, spec) {
        ("Bash" | "PowerShell", s) => Ok(Rule::Shell {
            powershell: name == "PowerShell",
            spec: s.map(Spec::parse).transpose()?,
        }),
        (n, Some(s))
            if (write_family.contains(&n) || read_family.contains(&n))
                && s.trim_start().starts_with('!') =>
        {
            Ok(Rule::Negation {
                write: write_family.contains(&n),
                spec: PathSpec::parse(&s.trim_start()[1..])?,
            })
        }
        (n, s) if write_family.contains(&n) || read_family.contains(&n) => Ok(Rule::Path {
            write: write_family.contains(&n),
            spec: s.map(PathSpec::parse).transpose()?,
            carve: Vec::new(),
        }),
        ("WebFetch", s) => Ok(Rule::Fetch {
            domain: s.map(Domain::parse).transpose()?,
        }),
        ("WebSearch", None) => Ok(Rule::Search),
        ("Skill", Some(s)) => parse_skill(s),
        ("Agent" | "Task" | "task", Some(s)) => {
            let name = s.trim();
            if name.is_empty() {
                return Err("no agent name".into());
            }
            Ok(Rule::Agent(name.to_owned()))
        }
        (_, Some(_)) => Err(format!(
            "{name}(...) cannot be read: a rule on an input parameter is written {name}(param:value)"
        )),
        (n, None) => {
            if n.contains(|c: char| c.is_whitespace() || c == '*' || c == ')') {
                return Err(format!("{n:?} is not a tool name"));
            }
            Ok(Rule::Tool(n.to_owned()))
        }
    }
}

/// Whether `s` can name a tool input field.
fn is_param_name(s: &str) -> bool {
    s.chars()
        .next()
        .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
        && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// Whether a `Tool(param:value)` rule applies to the tool of `call`.
fn param_tool_matches(tool: &str, call: &Call) -> bool {
    match tool {
        "Bash" => call.kind == KIND_SHELL,
        "Agent" | "Task" | "task" => call.kind == KIND_AGENT,
        t => call.tool == t,
    }
}

/// The inside of `Skill(...)`.
fn parse_skill(spec: &str) -> Result<Rule, String> {
    let spec = spec.trim();
    let (by_param, rest) = match spec.strip_prefix("skill") {
        Some(r) if r.trim_start().starts_with(':') => (true, r.trim_start()[1..].trim()),
        _ => (false, spec),
    };
    let (name, any_args) = match rest.strip_suffix(" *").or_else(|| rest.strip_suffix(":*")) {
        Some(n) if !by_param => (n.trim(), true),
        _ => (rest, false),
    };
    if name.is_empty() {
        return Err("no skill name".into());
    }
    if name.contains(char::is_whitespace) {
        return Err("a skill name has no spaces; `Skill(name *)` means any arguments".into());
    }
    Ok(Rule::Skill {
        name: name.to_owned(),
        any_args: any_args || name == "*",
        by_param,
    })
}

mod vet;
pub use vet::*;

pub(crate) use carve::attach as attach_carveouts;

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
                if matches!(rule, Rule::Negation { .. }) {
                    return Err(RulesError(format!(
                        "permissions.{key}[{i}] {}: a `!` rule is joined to the rules before it when the policy is loaded",
                        quote_string(text)
                    )));
                }
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

    /// Whether a deny or ask rule matches `call`, a `Read` the read-only
    /// commands stand in for.
    pub(crate) fn stops(&self, call: &Call) -> bool {
        self.deny
            .iter()
            .chain(&self.ask)
            .any(|e| self.matches(e, call, None))
    }

    // --- deny and ask ---

    fn matches(&self, e: &Entry, call: &Call, nah: Option<&NahResult>) -> bool {
        match &e.rule {
            Rule::Shell { powershell, spec } => {
                call.kind == KIND_SHELL
                    && (!powershell || call.tool == "PowerShell")
                    && spec.as_ref().is_none_or(|s| {
                        s.is_blanket() || self.shell_match(s, *powershell, call, nah)
                    })
            }
            Rule::Path { write, spec, carve } => {
                call.kind == if *write { KIND_WRITE } else { KIND_READ }
                    && spec
                        .as_ref()
                        .is_none_or(|s| self.path_match(s, carve, call, false))
            }
            // Joined to its rules at load; one that was not has no meaning.
            Rule::Negation { .. } => false,
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
            Rule::Agent(name) => {
                call.kind == KIND_AGENT
                    && call
                        .fields
                        .get("subagent_type")
                        .is_some_and(|t| (name == "*" && !t.is_empty()) || t == name)
            }
            Rule::Param { tool, param, value } => {
                param_tool_matches(tool, call)
                    && call
                        .scalars
                        .get(param)
                        .is_some_and(|v| spec::glob(value, v))
            }
            Rule::Skill { name, .. } => {
                call.tool == "Skill"
                    && call
                        .fields
                        .get("skill")
                        .is_some_and(|k| spec::glob(name, k))
            }
            Rule::Tool(n) => call.tool == *n,
        }
    }

    /// A shell rule for deny or ask: any command nah found, else the raw text
    /// when the parse has a hole.
    fn shell_match(
        &self,
        spec: &Spec,
        powershell: bool,
        call: &Call,
        nah: Option<&NahResult>,
    ) -> bool {
        let caseless = self.env.caseless();
        if let Some(n) = nah {
            for c in &n.calls {
                if let Some(argv) = c.argv.as_ref().filter(|a| !a.is_empty())
                    && spec::matches_call(spec, argv, caseless, powershell)
                {
                    return true;
                }
            }
        }
        parse_has_hole(call, nah)
            && call
                .commands()
                .any(|cmd| spec::matches_raw(spec, cmd, caseless, powershell))
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
    fn path_match(&self, spec: &PathSpec, carve: &[PathSpec], call: &Call, allow: bool) -> bool {
        let raw = &call.raw_paths;
        if raw.is_empty() || (allow && raw.len() != 1) {
            return false;
        }
        if allow && call.pattern_escapes {
            return false;
        }
        let ctx = self.ctx(call);
        let covers = |p: &str| {
            spec.matches(p, &ctx, allow) && !carve.iter().any(|c| c.matches(p, &ctx, false))
        };
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
            // Each form on its own: a link whose name is carved out but whose
            // target is not still matches.
            let requested = covers(&posix);
            let real = resolved.as_ref().is_some_and(|p| covers(p));
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
                .any(|(p, _)| covers(&paths::to_posix(&self.env, p)))
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
                Rule::Path { write, spec, .. } => {
                    call.kind == if *write { KIND_WRITE } else { KIND_READ }
                        && spec
                            .as_ref()
                            .is_some_and(|s| self.path_match(s, &[], call, true))
                }
                Rule::Fetch { domain: Some(d) } => {
                    WEBFETCH_TOOLS.contains(&call.tool.as_str()) && {
                        let urls = &call.urls;
                        urls.len() == 1 && web::strict_host(&urls[0]).is_some_and(|h| d.matches(&h))
                    }
                }
                Rule::Search => WEBSEARCH_TOOLS.contains(&call.tool.as_str()),
                Rule::Mcp(m) => m.matches(&call.tool, true),
                Rule::Skill {
                    name,
                    any_args,
                    by_param: false,
                } => {
                    call.tool == "Skill"
                        && call
                            .fields
                            .get("skill")
                            .is_some_and(|k| spec::glob(name, k))
                        && (*any_args || call.fields.get("args").is_none_or(String::is_empty))
                }
                Rule::Tool(n) => call.tool == *n,
                Rule::Shell { .. }
                | Rule::Fetch { domain: None }
                | Rule::Agent(_)
                | Rule::Param { .. }
                | Rule::Negation { .. }
                | Rule::Skill { .. } => false,
            })
            .map(|e| e.text.clone())
    }

    /// A shell command is allowed only if nah and the independent lexer both
    /// find nothing but commands the allow rules name, literally.
    fn allowed_shell(&self, call: &Call, nah: Option<&NahResult>) -> Option<String> {
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
            specs
                .iter()
                .find(|(_, s)| {
                    let mut work = spec::WORK_LIMIT;
                    s.matches(argv, spec::Mode::Allow, &mut work)
                })
                .map(|(e, _)| *e)
        };
        // A rule needs a command to name.
        let e = shell_gate(&self.env, call, nah, true, literal)??;
        Some(e.text.clone())
    }
}

/// Programs that run the repository's own scripts or build files. For an allow
/// rule naming one (`Bash(npm test)`), nah's children from inside the script
/// (`jest`, a recipe's commands, a child it could not spell) are not checked
/// against the rules: the rule runs the command, as in Claude Code. They are
/// still nah's to block, and a gap that is not opaque still refuses.
const SCRIPT_RUNNERS: [&str; 8] = ["npm", "yarn", "pnpm", "bun", "make", "just", "cargo", "go"];

/// The gate of every shell allow, by rule (`rules`) or built in: nah's answer
/// and the independent lexer must agree that the call is nothing but commands
/// `pick` accepts, with nothing around them (assignments, redirects,
/// expansions) that argv would hide. `pick` returns what the command stands
/// for (the rule that names it); the value of the first command comes back.
///
/// Every command the lexer reads must pass `pick`. A nah call that equals one
/// of them is checked as well (its working directory too). A nah call that
/// equals none (a script's child) only passes for `rules`, and only when one
/// of the lexer's commands is a script runner.
pub(crate) fn shell_gate<T>(
    env: &Env,
    call: &Call,
    nah: Option<&NahResult>,
    rules: bool,
    pick: impl Fn(&[String]) -> Option<T>,
) -> Option<Option<T>> {
    if !ALLOW_SHELL_TOOLS.contains(&call.tool.as_str()) {
        return None;
    }
    // A real answer of nah for this call, complete but for code it cannot read.
    let n = nah?;
    if n.verdict != NahVerdict::Delegate || !opaque_only(n) || call.cwd.is_empty() {
        return None;
    }
    // The second parser. One spelling of the command only: we cannot know
    // which one the harness runs.
    if call.raw_commands.len() != 1 {
        return None;
    }
    let segs = lexer::split(&call.raw_commands[0])?;
    let mut first = None;
    for seg in &segs {
        let t = pick(seg)?;
        first.get_or_insert(t);
    }
    let runs_scripts = rules && segs.iter().any(|s| SCRIPT_RUNNERS.contains(&s[0].as_str()));
    let want = env.fold(&env.normalize(&call.cwd, ""));
    let mut seen = false;
    for c in &n.calls {
        match c.argv.as_ref().filter(|a| segs.contains(a)) {
            Some(argv) => {
                seen = true;
                let cwd = c.cwd.as_deref().filter(|c| !c.is_empty())?;
                if env.fold(&env.normalize(cwd, "")) != want {
                    return None;
                }
                pick(argv)?;
            }
            None if runs_scripts => {}
            None => return None,
        }
    }
    // A rule needs a command of nah's to name.
    if rules && !seen {
        return None;
    }
    Some(first)
}

/// Gaps nah reports for a command that runs code of the repository, which it
/// cannot read: `npm test`, `pytest`, `cargo test`, `make`, `go test`. An allow
/// rule for the exact command may pass over them, as Claude Code does; a
/// budget that ran out or a construct nah could not parse reports something
/// else (`Limit execution-limit`, `Unmodeled parse-error`) or no answer at all.
const OPAQUE_GAPS: [&str; 6] = [
    "Unmodeled unresolved-package-script",
    "Unmodeled unrecoverable-source",
    "Unmodeled unresolved-build-target",
    "Unmodeled resource-components-unavailable",
    "Unmodeled Process semantic-fields-unavailable",
    "Unmodeled Filesystem access-semantics-partial",
];

/// Whether nah's answer is complete but for the opaque gaps.
fn opaque_only(n: &NahResult) -> bool {
    let Some(f) = n.facts.as_ref() else {
        return false;
    };
    f.gaps.iter().all(|g| OPAQUE_GAPS.contains(&g.as_str()))
        && match n.coverage.as_str() {
            "full" => true,
            "partial" => !f.gaps.is_empty(),
            _ => false,
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
