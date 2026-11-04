//! The engine: policy loading, the pipeline (builtin, nah, rules, llm) and the
//! common finishing steps.
//!
//! Go's `Decide(ctx, req)` becomes `decide(&self, req)`: the deadline is the
//! policy's `deadline_ms`, counted from the call. Nah is a [`NahEngine`] held
//! in `Options`; the default is a supervised child process running nah.

use std::any::Any;
use std::collections::HashSet;
use std::panic::{self, AssertUnwindSafe};
use std::path::PathBuf;
use std::sync::{Arc, mpsc};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde_json::value::RawValue;
use sha2::{Digest, Sha256};

use crate::backend::{self, Backend};
use crate::declog::{self, ShadowVerdict};
use crate::fallback::{fallback_verdict, new_id};
use crate::hostmeta::{self, Meta};
use crate::judge::{self, JudgeError, JudgeResult};
use crate::nah::{NahEngine, NahRequest, NahResult, NahVerdict};
use crate::permissions::Permissions;
use crate::policy::{self, Policy, go_quote};
use crate::rules::{self, Builtin, Call, CallInput, Env, Set, input_string_field};
use crate::schema::{
    Decision, Facts, LAYER_BUILTIN, LAYER_LLM, LAYER_NAH, LAYER_NONE, LAYER_RULES, REQUEST_SCHEMA,
    Request, VERDICT_SCHEMA, Verdict,
};
use crate::transcript::{self, Message as TMessage};

/// Tunes an [`Engine`]. Unset values mean the policy's settings.
#[derive(Default)]
pub struct Options {
    /// Replaces the policy's configured LLM backend (eval and tests).
    pub backend: Option<Arc<dyn Backend>>,
    /// Overrides the policy's decision log path; "-" disables logging.
    pub log_path: String,
    /// The nah engine; `None` means a supervised child process.
    pub nah_engine: Option<Arc<dyn NahEngine>>,
    /// The clock; `None` means the system clock.
    pub now: Option<Arc<dyn Fn() -> SystemTime + Send + Sync>>,
    /// Extra files the self-protection rules guard, such as an explicit
    /// `--policy` file.
    pub protect_paths: Vec<String>,
    /// Warnings from policy loading, copied into every verdict.
    pub warnings: Vec<String>,
    /// Keeps nah facts (request.facts and the nah summary) away from the judge;
    /// `eval --facts off` uses it.
    pub omit_facts: bool,
    /// Turns off the git and gh probing for the judge (eval and tests).
    pub no_host_meta: bool,
    /// When > 0, replaces the policy's `llm.timeout_ms` (and raises the
    /// deadline to fit); eval uses it.
    pub llm_timeout_ms: i64,
}

/// Selects the policy layers for [`Engine::load`].
#[derive(Default)]
pub struct LoadOptions {
    /// System layer file; "" means the platform default. A missing default file
    /// is not an error; a missing explicit file is.
    pub system_policy: String,
    /// Selects `<project_dir>/.callguard/policy.json`; "" skips it.
    pub project_dir: String,
    /// Overrides the user config dir (tests); "-" skips the user layer.
    pub user_config_dir: String,
    pub options: Options,
}

/// The judge call; tests replace it (Go: `judgeFunc`).
type JudgeFn = Box<
    dyn Fn(&dyn Backend, &judge::Config, judge::Input, Instant) -> Result<JudgeResult, JudgeError>
        + Send
        + Sync,
>;

/// The host probe with its runner bound; tests replace it (Go: `probeFunc`).
type ProbeFn = Box<dyn Fn(&str, &str, Option<&Meta>, Instant) -> Option<Meta> + Send + Sync>;

struct Inner {
    pol: Policy,
    rev: String,
    opts: Options,
    env: Env,
    builtin: Builtin,
    rules: Set,
    perms: Permissions,
    /// None when logging is off.
    logger: Option<declog::Logger>,
    nah: Arc<dyn NahEngine>,
    judge: JudgeFn,
    /// Host observations for the judge; None when probing is off.
    probe: Option<ProbeFn>,
}

/// Decides tool calls against one merged policy. Safe for concurrent use.
pub struct Engine {
    inner: Arc<Inner>,
}

/// Why an engine could not be built (invalid policy, bad rule, load error).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct EngineError(pub String);

/// What the pipeline hands back before the common finishing steps.
struct Outcome {
    v: Verdict,
    /// The deciding layer's own mode is enforce.
    layer_enforced: bool,
    in_tok: i64,
    out_tok: i64,
    /// An llm deny turned into ask by the deny streak.
    escalated: bool,
    /// Shadow-mode layers that did not end the pipeline.
    shadow: Vec<ShadowVerdict>,
    warnings: Vec<String>,
}

impl Outcome {
    fn new(v: Verdict, layer_enforced: bool) -> Outcome {
        Outcome {
            v,
            layer_enforced,
            in_tok: 0,
            out_tok: 0,
            escalated: false,
            shadow: Vec::new(),
            warnings: Vec::new(),
        }
    }

    fn fallback(req: &Request, cause: &str) -> Outcome {
        Outcome::new(fallback_verdict(Some(req), cause), true)
    }
}

fn decided(decision: &str, layer: &str, rule: &str, reason: &str) -> Outcome {
    let mut v = blank_verdict(Decision::parse(decision).unwrap_or(Decision::Ask), layer);
    v.rule = rule.into();
    v.reason = reason.into();
    v.confidence = 1.0;
    Outcome::new(v, true)
}

/// A verdict with only decision and layer set; `finish` fills in the identity.
fn blank_verdict(decision: Decision, layer: &str) -> Verdict {
    Verdict {
        schema: String::new(),
        v: 0,
        id: String::new(),
        decision,
        enforced: false,
        reason: String::new(),
        layer: layer.into(),
        rule: String::new(),
        confidence: 0.0,
        policy_rev: String::new(),
        backend: String::new(),
        latency_ms: 0,
        warnings: Vec::new(),
    }
}

fn panic_message(p: &(dyn Any + Send)) -> String {
    if let Some(s) = p.downcast_ref::<&str>() {
        (*s).to_owned()
    } else if let Some(s) = p.downcast_ref::<String>() {
        s.clone()
    } else {
        "unknown panic".into()
    }
}

/// Go's `time.Duration.String` for whole milliseconds.
fn go_duration(ms: u64) -> String {
    if ms < 1000 {
        return format!("{ms}ms");
    }
    let (secs, rem) = (ms / 1000, ms % 1000);
    let (h, m, s) = (secs / 3600, secs % 3600 / 60, secs % 60);
    let frac = if rem == 0 {
        String::new()
    } else {
        format!(".{rem:03}").trim_end_matches('0').to_owned()
    };
    if h > 0 {
        format!("{h}h{m}m{s}{frac}s")
    } else if m > 0 {
        format!("{m}m{s}{frac}s")
    } else {
        format!("{s}{frac}s")
    }
}

/// Go's `time.RFC3339Nano` in UTC.
fn rfc3339_nano(t: SystemTime) -> String {
    let nanos = t
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos() as i128);
    let Ok(dt) = time::OffsetDateTime::from_unix_timestamp_nanos(nanos) else {
        return String::new();
    };
    let mut s = format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}",
        dt.year(),
        dt.month() as u8,
        dt.day(),
        dt.hour(),
        dt.minute(),
        dt.second()
    );
    let frac = format!("{:09}", dt.nanosecond());
    let frac = frac.trim_end_matches('0');
    if !frac.is_empty() {
        s.push('.');
        s.push_str(frac);
    }
    s.push('Z');
    s
}

impl Engine {
    /// Builds an engine from an already merged policy. Unset settings take their
    /// defaults; rules are used as given (use `policy::default()` for the
    /// default rules).
    pub fn new(pol: Policy, mut opts: Options) -> Result<Engine, EngineError> {
        let mut pol = policy::with_defaults(pol);
        if opts.llm_timeout_ms > 0 {
            if let Some(llm) = pol.llm.as_mut() {
                llm.timeout_ms = opts.llm_timeout_ms;
            }
            pol.deadline_ms = pol.deadline_ms.max(opts.llm_timeout_ms + 2000);
        }
        let problems = policy::validate(&pol, false);
        if !problems.is_empty() {
            return Err(EngineError(format!(
                "invalid policy: {}",
                problems.join("; ")
            )));
        }
        let env = Env::host();
        let set = Set::compile(&pol.rules, &env)
            .map_err(|e| EngineError(format!("invalid policy: {e}")))?;
        let (perms, perm_warnings) = Permissions::compile(&pol.permissions, &env)
            .map_err(|e| EngineError(format!("invalid policy: {e}")))?;
        opts.warnings.extend(perm_warnings);
        let builtin = Builtin::new(env.clone(), &pol.disable_builtin, &opts.protect_paths)
            .map_err(|e| EngineError(e.to_string()))?;
        let probe: Option<ProbeFn> = if opts.no_host_meta {
            None
        } else {
            Some(Box::new(|cwd, command, have, deadline| {
                hostmeta::probe(&hostmeta::exec_runner, cwd, command, have, deadline)
            }))
        };
        let logger = Some(log_path(&pol, &opts))
            .filter(|p| !p.is_empty())
            .map(|p| declog::Logger::new(&p));
        let nah = opts.nah_engine.clone().unwrap_or_else(default_nah_engine);
        let rev = policy::rev(&pol);
        Ok(Engine {
            inner: Arc::new(Inner {
                pol,
                rev,
                opts,
                env,
                builtin,
                rules: set,
                perms,
                logger,
                nah,
                judge: Box::new(|b, cfg, input, deadline| judge::judge(b, cfg, input, deadline)),
                probe,
            }),
        })
    }

    /// Reads and merges the policy layers and builds an engine.
    pub fn load(opts: LoadOptions) -> Result<Engine, EngineError> {
        let l = policy::load(&policy::LoadOptions {
            system_policy: opts.system_policy.clone(),
            project_dir: opts.project_dir.clone(),
            user_config_dir: opts.user_config_dir.clone(),
        })
        .map_err(|e| EngineError(e.0))?;
        let problems = l.problems();
        if !problems.is_empty() {
            return Err(EngineError(format!(
                "invalid policy: {}",
                problems.join("; ")
            )));
        }
        let mut o = opts.options;
        o.warnings.extend(l.warnings.iter().cloned());
        // The system default directory is protected by a built-in glob; an
        // explicit --policy file and the user layer file are protected here.
        for p in [opts.system_policy, policy::user_path(&opts.user_config_dir)] {
            if p.is_empty() {
                continue;
            }
            if let Ok(abs) = std::path::absolute(&p) {
                o.protect_paths.push(abs.to_string_lossy().into_owned());
            }
        }
        Engine::new(l.policy, o)
    }

    /// The merged policy the engine uses.
    pub fn policy(&self) -> &Policy {
        &self.inner.pol
    }

    /// "sha256:<hex>" of the merged policy.
    pub fn policy_rev(&self) -> &str {
        &self.inner.rev
    }

    /// The verdict for `req`. Never fails: every failure becomes a fallback
    /// verdict (ask, or deny when unattended), and it returns before the policy
    /// deadline. A panic in a layer becomes a fallback too.
    pub fn decide(&self, req: &Request) -> Verdict {
        let inner = &self.inner;
        let start = inner.now();
        let deadline = Duration::from_millis(inner.pol.deadline_ms.max(0) as u64);
        let t0 = Instant::now();

        // The pipeline runs on its own thread so that a layer which ignores its
        // deadline (a stuck judge) cannot hold the call past the policy
        // deadline; the thread is left to finish on its own.
        let (tx, rx) = mpsc::channel();
        let (worker, worker_req) = (Arc::clone(inner), req.clone());
        let spawned = std::thread::Builder::new()
            .name("callguard-pipeline".into())
            .spawn(move || {
                let out = panic::catch_unwind(AssertUnwindSafe(|| {
                    worker.pipeline(&worker_req, t0 + deadline)
                }))
                .unwrap_or_else(|p| {
                    Outcome::fallback(
                        &worker_req,
                        &format!("internal error: {}", panic_message(&*p)),
                    )
                });
                let _ = tx.send(out);
            });
        let out = match spawned {
            Err(e) => Outcome::fallback(req, &format!("internal error: {e}")),
            Ok(_) => match rx.recv_timeout(deadline) {
                Ok(out) => out,
                Err(mpsc::RecvTimeoutError::Timeout) => Outcome::fallback(
                    req,
                    &format!(
                        "deadline of {} exceeded",
                        go_duration(deadline.as_millis() as u64)
                    ),
                ),
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    Outcome::fallback(req, "internal error: the pipeline ended without an answer")
                }
            },
        };
        panic::catch_unwind(AssertUnwindSafe(|| inner.finish(req, out, start))).unwrap_or_else(
            |p| {
                // Last resort: finish itself panicked.
                fallback_verdict(
                    Some(req),
                    &format!("internal error: {}", panic_message(&*p)),
                )
            },
        )
    }
}

/// nah in a child process of this executable. This crate's own tests must not
/// start one, so they get the stand-in that delegates.
#[cfg(not(test))]
fn default_nah_engine() -> Arc<dyn NahEngine> {
    Arc::new(crate::supervisor::SupervisedEngine::current())
}

#[cfg(test)]
fn default_nah_engine() -> Arc<dyn NahEngine> {
    Arc::new(crate::nah::DelegatingEngine)
}

/// Time left for the rest of the pipeline when nah's hard deadline is cut to fit
/// the call's.
const NAH_MARGIN_MS: u64 = 200;

/// What nah gave when it gave no answer: a delegate that records the gap, with
/// partial coverage.
fn no_parse(cause: &str) -> NahResult {
    NahResult {
        verdict: NahVerdict::Delegate,
        rule: String::new(),
        reason: cause.to_owned(),
        coverage: "partial".into(),
        facts: Some(Facts {
            source: "nah".into(),
            coverage: "partial".into(),
            gaps: vec![format!("nah gave no analysis: {cause}")],
            ..Default::default()
        }),
        warnings: Vec::new(),
        calls: Vec::new(),
    }
}

const NO_HUMAN: &str =
    "No human is available to approve this call; ask the user to approve it or add a policy rule.";

impl Inner {
    fn now(&self) -> SystemTime {
        self.opts.now.as_ref().map_or_else(SystemTime::now, |f| f())
    }

    /// Applies shadow mode, the unattended rule, identity and logging.
    fn finish(&self, req: &Request, out: Outcome, start: SystemTime) -> Verdict {
        let mut v = out.v.clone();
        v.schema = VERDICT_SCHEMA.into();
        v.v = 1;
        v.id = new_id();
        v.policy_rev = self.rev.clone();
        v.enforced =
            out.layer_enforced && self.pol.mode != policy::MODE_SHADOW && v.layer != LAYER_NONE;
        v.warnings = self
            .opts
            .warnings
            .iter()
            .chain(&out.warnings)
            .cloned()
            .collect();
        if v.enforced
            && v.decision == Decision::Ask
            && req.unattended
            && self.pol.unattended_ask == "deny"
        {
            v.decision = Decision::Deny;
            v.reason.push(' ');
            v.reason.push_str(NO_HUMAN);
        }
        v.latency_ms = self
            .now()
            .duration_since(start)
            .map_or(0, |d| d.as_millis() as i64);
        if let Err(e) = self.log(req, &v, &out) {
            v.warnings.push(format!("decision log: {e}"));
        }
        v
    }

    fn log(&self, req: &Request, v: &Verdict, out: &Outcome) -> std::io::Result<()> {
        let Some(logger) = &self.logger else {
            return Ok(());
        };
        let include_input = self.pol.log.as_ref().is_some_and(|l| l.include_input);
        let mut ent = declog::Entry {
            ts: rfc3339_nano(self.now()),
            id: v.id.clone(),
            session_id: req.session_id.clone(),
            tool_use_id: req.tool_use_id.clone(),
            harness: req.harness.clone(),
            tool: req.tool.name.clone(),
            kind: rules::kind_of(&req.tool.name).into(),
            input_sha256: input_sha256(req),
            decision: v.decision.as_str().into(),
            enforced: v.enforced,
            layer: v.layer.clone(),
            rule: v.rule.clone(),
            confidence: v.confidence,
            backend: v.backend.clone(),
            policy_rev: v.policy_rev.clone(),
            latency_ms: v.latency_ms,
            unattended: req.unattended,
            input_tokens: out.in_tok,
            output_tokens: out.out_tok,
            escalated: out.escalated,
            shadow: out.shadow.clone(),
            ..Default::default()
        };
        if v.layer != LAYER_LLM || include_input {
            ent.reason = v.reason.clone();
        }
        if include_input {
            ent.input = req.tool.input.clone();
        }
        logger.append(&ent)
    }

    /// Runs builtin, nah, rules and llm in order; the first layer that decides
    /// wins (design section 4).
    fn pipeline(&self, req: &Request, deadline: Instant) -> Outcome {
        if (!req.schema.is_empty() && req.schema != REQUEST_SCHEMA) || (req.v != 0 && req.v != 1) {
            return Outcome::fallback(req, "unsupported request schema");
        }
        if req.tool.name.is_empty() {
            return Outcome::fallback(req, "request has no tool name");
        }
        let project_dir = resolve_project_dir(req);
        let call = Call::new(
            CallInput {
                harness: req.harness.clone(),
                tool: req.tool.name.clone(),
                input: req.tool.input.clone(),
                cwd: req.cwd.clone(),
                project_dir: project_dir.clone(),
                context: req.context.clone(),
                unattended: req.unattended,
            },
            &self.env,
        );

        // A project that is the home directory or a root says nothing about
        // what is "inside the project"; the in-project rules stay quiet.
        let mut warns: Vec<String> = Vec::new();
        if call.project_ignored && !call.path.is_empty() {
            warns.push(format!(
                "project directory {project_dir} is the home directory or a file system root: no path counts as inside the project"
            ));
        }

        // 0 builtin
        if let Some(hit) = self.builtin.check(&call) {
            let mut out = decided(&hit.decision, LAYER_BUILTIN, &hit.id, &hit.reason);
            out.warnings = warns;
            return out;
        }

        // 1 nah. A layer in shadow mode records what it would have decided and
        // the pipeline goes on, so a shadowed nah never hides the layers behind it.
        let mut shadow: Vec<ShadowVerdict> = Vec::new();
        let mut nah_res: Option<NahResult> = None;
        // Why nah gave no answer, when the layer is enforced: nah is required,
        // so the call may be refused or asked about but never allowed.
        let mut nah_failure: Option<String> = None;
        let nah = self.pol.nah.clone().unwrap_or_default();
        if nah.is_enabled() {
            let shadowed = nah.mode == policy::MODE_SHADOW;
            let input = req
                .tool
                .input
                .clone()
                .unwrap_or_else(|| RawValue::from_string("null".into()).expect("null is JSON"));
            // The hard deadline of the nah process never runs past the call's
            // own; the rest of the call needs a little time to answer.
            let left = deadline.saturating_duration_since(Instant::now());
            let timeout_ms = (nah.timeout_ms.max(0) as u64)
                .min((left.as_millis() as u64).saturating_sub(NAH_MARGIN_MS))
                .max(1);
            let res = self.nah.decide(&NahRequest {
                tool: req.tool.name.clone(),
                input,
                cwd: req.cwd.clone(),
                project_dir: project_dir.clone(),
                guards: nah.guards.clone(),
                budget_ms: nah.budget_ms.max(0) as u64,
                timeout_ms,
            });
            match res {
                Err(e) => {
                    // No parse: the facts say so, so nothing later treats the
                    // call as understood.
                    warns.push(format!("nah skipped: {e}"));
                    nah_res = Some(no_parse(&e.to_string()));
                    if !shadowed {
                        nah_failure = Some(e.to_string());
                    }
                }
                Ok(res) if res.verdict == NahVerdict::Block => {
                    let rule = if res.rule.is_empty() {
                        "nah".to_owned()
                    } else {
                        format!("nah:{}", res.rule)
                    };
                    if !shadowed {
                        let mut out = decided("deny", LAYER_NAH, &rule, &res.reason);
                        out.warnings = warns;
                        out.warnings.extend(res.warnings);
                        return out;
                    }
                    warns.push(format!("shadow nah: would deny ({rule}): {}", res.reason));
                    shadow.push(ShadowVerdict {
                        layer: LAYER_NAH.into(),
                        decision: "deny".into(),
                        rule,
                    });
                }
                Ok(mut res) => {
                    warns.append(&mut res.warnings);
                    nah_res = Some(res);
                }
            }
        }

        // 2 rules: the regex rules and the permission rules, the stricter
        // decision wins and a regex rule wins a tie.
        let regex_hit = self.rules.match_call(&call);
        let perm_hit = self.perms.check(&call, nah_res.as_ref());
        let rank = |d: &str| match d {
            "deny" => 3,
            "ask" => 2,
            "allow" => 1,
            _ => 0,
        };
        let perm_wins = match (&regex_hit, &perm_hit) {
            (Some(r), Some(p)) => rank(p.decision) > rank(&r.decision),
            (None, Some(_)) => true,
            _ => false,
        };
        let verdict = match (regex_hit, perm_hit) {
            (_, Some(p)) if perm_wins => Some((p.decision.to_owned(), p.rule, p.reason)),
            (Some(r), _) => {
                let reason = if r.description.is_empty() {
                    format!("policy rule {}", r.id)
                } else {
                    r.description.clone()
                };
                Some((r.decision, r.id, reason))
            }
            _ => None,
        };
        // Without nah's parse an allow cannot stand; a deny or ask can.
        let verdict = verdict.filter(|(d, _, _)| nah_failure.is_none() || d != "allow");
        if let Some((decision, rule, reason)) = verdict {
            let mut out = decided(&decision, LAYER_RULES, &rule, &reason);
            out.warnings = warns;
            out.shadow = shadow;
            return out;
        }
        if let Some(cause) = nah_failure {
            // The judge is skipped: it would read the call without the parse
            // that makes its answer safe to trust.
            let mut out = Outcome::fallback(
                req,
                &format!("nah, the command parser, failed ({cause}) and no rule decided the call"),
            );
            out.v.rule = "nah".into();
            out.warnings = warns;
            out.shadow = shadow;
            return out;
        }

        // 3 llm
        if !self.pol.llm_enabled() {
            let mut v = blank_verdict(Decision::Ask, LAYER_NONE);
            v.reason = "no callguard layer decided this call".into();
            let mut out = Outcome::new(v, false);
            out.warnings = warns;
            out.shadow = shadow;
            return out;
        }
        let facts = self.judge_facts(req, nah_res.as_ref());
        let mut out = self.run_llm(req, &call, &project_dir, facts, nah_res.as_ref(), deadline);
        warns.append(&mut out.warnings);
        out.warnings = warns;
        out.shadow = shadow;
        out
    }

    /// What the judge learns about the parse of the call: the host's facts,
    /// else what nah reported when it delegated.
    fn judge_facts(&self, req: &Request, nah_res: Option<&NahResult>) -> Option<Facts> {
        if self.opts.omit_facts {
            return None;
        }
        if let Some(f) = &req.facts {
            return Some(f.clone());
        }
        nah_res.map(|r| {
            r.facts.clone().unwrap_or_else(|| Facts {
                source: "nah".into(),
                coverage: r.coverage.clone(),
                ..Default::default()
            })
        })
    }

    fn run_llm(
        &self,
        req: &Request,
        call: &Call,
        project_dir: &str,
        facts: Option<Facts>,
        nah_res: Option<&NahResult>,
        deadline: Instant,
    ) -> Outcome {
        let llm = self.pol.llm.clone().unwrap_or_default();
        let enforced = llm.mode != policy::MODE_SHADOW;
        let fail = |rule: &str, backend_name: &str, cause: &str, warns: Vec<String>| {
            let mut v = fallback_verdict(Some(req), cause);
            v.rule = rule.into();
            v.backend = backend_name.into();
            let mut out = Outcome::new(v, enforced);
            out.warnings = warns;
            out
        };

        let b: Arc<dyn Backend> = match &self.opts.backend {
            Some(b) => Arc::clone(b),
            None => {
                let Some(cfg) = self.pol.backends.get(&llm.backend) else {
                    return fail(
                        "backend",
                        "",
                        &format!("llm backend {} is not configured", go_quote(&llm.backend)),
                        Vec::new(),
                    );
                };
                match backend::from_config(cfg) {
                    Ok(b) => Arc::from(b),
                    Err(e) => {
                        return fail(
                            "backend",
                            "",
                            &format!("llm backend {} unavailable: {e}", go_quote(&llm.backend)),
                            Vec::new(),
                        );
                    }
                }
            }
        };
        if let Some(dc) = req.context.get("data_class").filter(|d| !d.is_empty())
            && !b.data_classes().contains(dc)
        {
            let name = b.name();
            return fail(
                "data-class",
                &name,
                &format!(
                    "data class {} may not be sent to backend {name}",
                    go_quote(dc)
                ),
                Vec::new(),
            );
        }

        let mut warns: Vec<String> = Vec::new();
        let (msgs, terr) = self.transcript(req);
        if let Some(e) = terr {
            warns.push(format!("transcript unreadable: {e}"));
        }
        let mut input = judge::Input {
            harness: req.harness.clone(),
            tool: req.tool.name.clone(),
            kind: call.kind.clone(),
            tool_input: req.tool.input.clone(),
            cwd: req.cwd.clone(),
            project_dir: project_dir.to_owned(),
            context: req.context.clone(),
            unattended: req.unattended,
            transcript: msgs,
            ..Default::default()
        };
        let mut meta = req.meta.clone();
        if let Some(probe) = &self.probe
            && !req.cwd.is_empty()
            && call.kind == rules::KIND_SHELL
        {
            let command = input_string_field(req.tool.input_str(), "command");
            meta = probe(&req.cwd, &command, req.meta.as_ref(), deadline);
        }
        if let Some(m) = meta {
            input.git_status = m.git_status;
            input.repo_visibility = m.repo_visibility;
        }
        if let Some(f) = &facts {
            input.facts = serde_json::to_string(f)
                .ok()
                .and_then(|s| RawValue::from_string(s).ok());
        }

        let jdeadline =
            deadline.min(Instant::now() + Duration::from_millis(llm.timeout_ms.max(0) as u64));
        let cfg = judge::Config {
            environment: llm.environment.clone(),
            block: llm.block.clone(),
            allow_exceptions: llm.allow_exceptions.clone(),
            min_confidence: llm.min_confidence.unwrap_or(0.7),
        };
        let res = match (self.judge)(b.as_ref(), &cfg, input, jdeadline) {
            Ok(r) => r,
            Err(e) => {
                let name = b.name();
                let rule = if name.is_empty() {
                    "judge".to_owned()
                } else {
                    name.clone()
                };
                return fail(&rule, &name, &format!("the llm judge failed: {e}"), warns);
            }
        };
        // The judge saw a cut input and nah did not see all of the call: the part
        // nobody read may hold the payload (padding pushes it past the cut).
        // Only an allow is doubted: a deny stands.
        if res.decision == "allow"
            && res.input_cut
            && crate::permissions::parse_has_hole(call, nah_res)
        {
            warns.push(
                "llm allow ignored: the tool input was cut for the judge and the command parse is incomplete"
                    .into(),
            );
            return fail(
                "input-cut",
                &b.name(),
                "the tool input was too long for the llm judge to read in full and the command parse is incomplete",
                warns,
            );
        }
        let Some(d) = Decision::parse(&res.decision) else {
            return fail(
                "judge",
                &b.name(),
                &format!(
                    "the llm judge returned decision {}",
                    go_quote(&res.decision)
                ),
                warns,
            );
        };
        let mut v = blank_verdict(d, LAYER_LLM);
        v.rule = res.rule;
        v.reason = res.reason;
        v.confidence = res.confidence;
        v.backend = b.name();
        let mut out = Outcome::new(v, enforced);
        out.in_tok = res.input_tokens;
        out.out_tok = res.output_tokens;
        out.warnings = warns;
        if d == Decision::Deny
            && enforced
            && self.pol.mode != policy::MODE_SHADOW
            && !req.unattended
            && self.streak_reached(req)
        {
            out.v.decision = Decision::Ask;
            out.escalated = true;
            out.warnings.push("deny streak: escalated to human".into());
        }
        out
    }

    /// Reads this session's recent llm denies from the decision log.
    fn streak_reached(&self, req: &Request) -> bool {
        let Some(ds) = &self.pol.deny_streak else {
            return false;
        };
        let Some(logger) = &self.logger else {
            return false;
        };
        if req.session_id.is_empty() {
            return false;
        }
        let Ok(entries) = declog::read_tail(logger.path(), &req.session_id) else {
            return false;
        };
        let (consecutive, total) = declog::llm_denies(&entries);
        (ds.consecutive > 0 && consecutive as i64 >= ds.consecutive)
            || (ds.total > 0 && total as i64 >= ds.total)
    }

    /// The judge's view of the conversation, newest within the policy limits.
    /// Assistant text survives only as the referent of a user reply
    /// (`transcript::referents`), and calls the guard blocked earlier are
    /// marked. The second value is a read error, which is only a warning.
    fn transcript(&self, req: &Request) -> (Vec<TMessage>, Option<String>) {
        let Some(t) = &req.transcript else {
            return (Vec::new(), None);
        };
        let lim = self
            .pol
            .llm
            .as_ref()
            .and_then(|l| l.transcript.clone())
            .unwrap_or_default();
        let (max_messages, max_bytes) = (
            lim.max_messages.max(0) as usize,
            lim.max_bytes.max(0) as usize,
        );
        let mut msgs: Vec<TMessage> = Vec::new();
        let mut err = None;
        if !t.messages.is_empty() {
            for m in &t.messages {
                match m.role.as_str() {
                    transcript::ROLE_USER
                    | transcript::ROLE_ASSISTANT
                    | transcript::ROLE_TOOL_CALL
                    | transcript::ROLE_THIRD_PARTY => msgs.push(TMessage {
                        role: m.role.clone(),
                        text: m.text.clone(),
                        tool: m.tool.clone(),
                        input: m.input.clone(),
                        id: m.id.clone(),
                        outcome: String::new(),
                    }),
                    transcript::ROLE_OUTCOME if transcript::valid_outcome(&m.outcome) => {
                        msgs.push(TMessage {
                            role: m.role.clone(),
                            id: m.id.clone(),
                            outcome: m.outcome.clone(),
                            ..Default::default()
                        });
                    }
                    _ => {}
                }
            }
            msgs = transcript::limit(transcript::referents(msgs), max_messages, max_bytes);
        } else if !t.path.is_empty()
            && (t.format == "claude-jsonl" || (t.format.is_empty() && req.harness == "claude"))
        {
            match transcript::read_claude_jsonl(&t.path, max_messages, max_bytes) {
                Ok(m) => msgs = m,
                Err(e) => err = Some(e.to_string()),
            }
        }
        if !msgs.is_empty() {
            msgs = transcript::mark_blocked(msgs, &self.blocked_calls(req));
        }
        (msgs, err)
    }

    /// The tool_use ids of this session that callguard itself denied (enforced),
    /// from the decision log.
    fn blocked_calls(&self, req: &Request) -> HashSet<String> {
        let Some(logger) = &self.logger else {
            return HashSet::new();
        };
        if req.session_id.is_empty() {
            return HashSet::new();
        }
        let Ok(entries) = declog::read_tail(logger.path(), &req.session_id) else {
            return HashSet::new();
        };
        entries
            .into_iter()
            .filter(|e| !e.tool_use_id.is_empty() && e.enforced && e.decision == "deny")
            .map(|e| e.tool_use_id)
            .collect()
    }
}

/// SHA-256 of the input exactly as the harness sent it: the bytes are kept
/// untouched from parse to hash, so the log ties to what the host ran.
fn input_sha256(req: &Request) -> String {
    hex::encode(Sha256::digest(req.tool.input_str().as_bytes()))
}

/// `req.project_dir` if set, else the nearest directory at or above `req.cwd`
/// that contains `.git`, else `req.cwd`.
pub fn resolve_project_dir(req: &Request) -> String {
    if !req.project_dir.is_empty() {
        return req.project_dir.clone();
    }
    if req.cwd.is_empty() {
        return String::new();
    }
    let mut dir = PathBuf::from(&req.cwd);
    loop {
        if std::fs::metadata(dir.join(".git")).is_ok() {
            return dir.to_string_lossy().into_owned();
        }
        // Go's filepath.Dir: the parent, "." for a bare name, itself at the root.
        let parent: PathBuf = match dir.parent() {
            Some(p) if p.as_os_str().is_empty() => PathBuf::from("."),
            Some(p) => p.to_path_buf(),
            None => dir.clone(),
        };
        if parent == dir {
            return req.cwd.clone();
        }
        dir = parent;
    }
}

/// Where the decision log goes for `pol` and `opts` ("" = no log).
pub(crate) fn log_path(pol: &Policy, opts: &Options) -> String {
    if opts.log_path == "-" || pol.log.as_ref().is_some_and(|l| l.disabled) {
        return String::new();
    }
    if !opts.log_path.is_empty() {
        return opts.log_path.clone();
    }
    if let Some(l) = &pol.log
        && !l.path.is_empty()
    {
        return l.path.clone();
    }
    declog::default_path()
}

#[cfg(test)]
mod tests;
