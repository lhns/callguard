//! The engine: policy loading, the pipeline (builtin, nah, rules, llm) and the
//! common finishing steps (engine.go + pipeline.go). Stub (worker D).
//!
//! Go's `Decide(ctx, req)` becomes `decide(&self, req)`: the deadline is the
//! policy's `deadline_ms`, counted from the call. Nah is a [`NahEngine`] held
//! in `Options`; the default is [`DelegatingEngine`] until Phase 2. Go's
//! `Options.NahPath` is gone (the plan removes `nah.path`).
#![allow(unused_variables, dead_code)]

use std::sync::Arc;
use std::time::SystemTime;

use crate::backend::Backend;
use crate::nah::NahEngine;
use crate::policy::Policy;
use crate::schema::{Request, Verdict};

/// Tunes an [`Engine`]. Unset values mean the policy's settings.
#[derive(Default)]
pub struct Options {
    /// Replaces the policy's configured LLM backend (eval and tests).
    pub backend: Option<Arc<dyn Backend>>,
    /// Overrides the policy's decision log path; "-" disables logging.
    pub log_path: String,
    /// The nah engine; `None` means [`crate::nah::DelegatingEngine`].
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

/// Decides tool calls against one merged policy. Safe for concurrent use.
pub struct Engine {
    pol: Policy,
    rev: String,
    opts: Options,
}

/// Why an engine could not be built (invalid policy, bad rule, load error).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct EngineError(pub String);

impl Engine {
    /// Builds an engine from an already merged policy. Unset settings take their
    /// defaults; rules are used as given (use `policy::default()` for the
    /// default rules).
    pub fn new(pol: Policy, opts: Options) -> Result<Engine, EngineError> {
        todo!("port engine.New")
    }

    /// Reads and merges the policy layers and builds an engine.
    pub fn load(opts: LoadOptions) -> Result<Engine, EngineError> {
        todo!("port engine.Load")
    }

    /// The merged policy the engine uses.
    pub fn policy(&self) -> &Policy {
        &self.pol
    }

    /// "sha256:<hex>" of the merged policy.
    pub fn policy_rev(&self) -> &str {
        &self.rev
    }

    /// The verdict for `req`. Never fails: every failure becomes a fallback
    /// verdict (ask, or deny when unattended), and it returns before the policy
    /// deadline. A panic in a layer becomes a fallback too.
    pub fn decide(&self, req: &Request) -> Verdict {
        todo!("port Engine.Decide + pipeline")
    }
}

/// `req.project_dir` if set, else the nearest directory at or above `req.cwd`
/// that contains `.git`, else `req.cwd`.
pub fn resolve_project_dir(req: &Request) -> String {
    todo!("port callguard.ResolveProjectDir")
}

/// Where the decision log goes for `pol` and `opts` ("" = no log).
pub(crate) fn log_path(pol: &Policy, opts: &Options) -> String {
    todo!("port engine.logPath")
}
