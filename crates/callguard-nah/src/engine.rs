//! `nah_cli::decide_with` over nah-observe, behind callguard's `NahEngine`.
//! It runs in the supervised child (`callguard::supervisor`), never in the
//! process that answers the harness.

use std::cell::RefCell;
use std::path::Path;
use std::time::{Duration, Instant};

use callguard::nah::{NahEngine, NahError, NahRequest, NahResult, NahVerdict};
use nah_cli::{DecisionResult, shipped_guard_states};
use nah_proto::ctx::{AbsolutePath, Ctx, ShippedGuardState, TrustProjection};
use nah_proto::decision::DecisionOutput;
use nah_proto::observation::{Observation, ObservationRequest};
use nah_proto::tool::ToolCallInput;
use serde_json::{Value, json};

use crate::observe::{host_platform, observe};
use crate::{facts, graph};

/// nah recurses deeply on nested input; its worst inputs overflow any stack
/// (Phase 0), so this only makes an overflow rare. The process boundary is the
/// guard.
const STACK_BYTES: usize = 64 << 20;

/// The engine the child process runs.
#[derive(Debug, Clone, Copy, Default)]
pub struct RealEngine;

impl NahEngine for RealEngine {
    fn decide(&self, req: &NahRequest) -> Result<NahResult, NahError> {
        let req = req.clone();
        let handle = std::thread::Builder::new()
            .name("nah".into())
            .stack_size(STACK_BYTES)
            .spawn(move || decide_here(&req))
            .map_err(|e| NahError::Failed(format!("cannot start the nah thread: {e}")))?;
        handle
            .join()
            .map_err(|_| NahError::Crashed("nah panicked".into()))?
    }
}

/// A working directory nah accepts: absolute. A relative one is resolved from
/// the process's own; if that fails there is no parse.
fn absolute_cwd(cwd: &str) -> Result<String, NahError> {
    if cwd.is_empty() {
        return Err(NahError::Failed("the call has no working directory".into()));
    }
    let p = Path::new(cwd);
    if p.is_absolute() {
        return Ok(cwd.to_owned());
    }
    std::path::absolute(p)
        .ok()
        .and_then(|a| a.to_str().map(str::to_owned))
        .ok_or_else(|| NahError::Failed(format!("working directory {cwd:?} is not absolute")))
}

fn home() -> Result<String, NahError> {
    let key = if cfg!(windows) { "USERPROFILE" } else { "HOME" };
    std::env::var(key)
        .ok()
        .filter(|h| !h.is_empty())
        .ok_or_else(|| NahError::Failed(format!("{key} is not set")))
}

/// nah's context. Every shipped guard is stated explicitly: a default-off guard
/// is passed as explicitly disabled, so a repo's `.nah/project.toml` cannot
/// enable it, and `overrides` (from callguard's policy) then set a guard on or
/// off. Names nah does not know are returned, not fatal: failing the whole
/// call over a bad name in a policy would let a policy file switch nah off.
fn ctx(
    home: &str,
    overrides: &std::collections::BTreeMap<String, bool>,
) -> Result<(Ctx, Vec<String>), NahError> {
    let failed = |e: &dyn std::fmt::Display| NahError::Failed(format!("nah context: {e}"));
    let platform = host_platform();
    let home = AbsolutePath::new(platform, home.to_owned()).map_err(|e| failed(&e))?;
    let mut states = Vec::new();
    for state in shipped_guard_states() {
        let name = state.name().to_owned();
        let want = overrides.get(&name).copied().unwrap_or(state.enabled());
        let explicit_off = !want && !state.enabled();
        // A default-on guard turned off by policy is explicit too.
        let explicit_off = explicit_off || (!want && overrides.contains_key(&name));
        states.push(
            ShippedGuardState::with_explicit_disable(name, want, explicit_off)
                .map_err(|e| failed(&e))?,
        );
    }
    let known: Vec<String> = states.iter().map(|s| s.name().to_owned()).collect();
    let unknown = overrides
        .keys()
        .filter(|k| !known.contains(k))
        .map(|k| format!("nah: unknown guard {k:?} in nah.guards, ignored"))
        .collect();
    let ctx = Ctx::new(
        platform,
        home,
        states,
        vec![],
        TrustProjection::new(vec![]).map_err(|e| failed(&e))?,
    )
    .map_err(|e| failed(&e))?;
    Ok((ctx, unknown))
}

/// nah's analysis under the policy's budget (the fork's `decide_with_budget`;
/// nah's own `decide_with` is fixed at 100 ms). The 2 s default is provisional
/// until the load run reports.
fn run<F>(input: &ToolCallInput, ctx: &Ctx, budget_ms: u64, observe: F) -> DecisionResult
where
    F: FnMut(&ObservationRequest) -> Result<Observation, String>,
{
    let budget = Duration::from_millis(if budget_ms == 0 { DEFAULT_BUDGET_MS } else { budget_ms });
    nah_cli::decide_with_budget(input, ctx, budget, observe)
}

const DEFAULT_BUDGET_MS: u64 = 2000;

fn decide_here(req: &NahRequest) -> Result<NahResult, NahError> {
    let failed = |what: &str, e: &dyn std::fmt::Display| NahError::Failed(format!("{what}: {e}"));
    let cwd = absolute_cwd(&req.cwd)?;
    let input: Value = serde_json::from_str(req.input.get())
        .map_err(|e| failed("the tool input is not readable by nah", &e))?;
    let call: ToolCallInput = serde_json::from_value(
        json!({"v": 1, "tool": req.tool, "input": input, "cwd": cwd}),
    )
    .map_err(|e| failed("nah does not accept the call", &e))?;
    let (ctx, mut warnings) = ctx(&home()?, &req.guards)?;

    let observations = RefCell::new(Vec::<Observation>::new());
    let observe_warnings = RefCell::new(Vec::<String>::new());
    let started = Instant::now();
    let result = run(&call, &ctx, req.budget_ms, |request| {
        let observation = observe(request, &observe_warnings);
        if let Ok(o) = &observation {
            observations.borrow_mut().push(o.clone());
        }
        observation
    });
    let micros = u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX);
    let output =
        DecisionOutput::new(result.core(), "callguard", micros).map_err(|e| failed("nah output", &e))?;
    let out = serde_json::to_value(&output).map_err(|e| failed("nah output", &e))?;

    let text = |key: &str| out.get(key).and_then(Value::as_str).unwrap_or("").to_owned();
    let names: Vec<String> = out
        .get("policy_attributions")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|a| a.get("name").and_then(Value::as_str).map(str::to_owned))
        .collect();
    let verdict = match text("verdict").as_str() {
        "block" => NahVerdict::Block,
        "delegate" => NahVerdict::Delegate,
        other => return Err(NahError::Failed(format!("unknown nah verdict {other:?}"))),
    };
    let coverage = text("coverage");
    let graph = graph::graph_facts(&result, &observations.borrow());
    let mapped = facts::map(&graph, names.clone(), &coverage);

    warnings.append(&mut observe_warnings.borrow_mut());
    if coverage != "full" {
        warnings.extend(result.warnings().iter().map(|w| format!("nah: {w}")));
    }
    Ok(NahResult {
        verdict,
        rule: names.first().cloned().unwrap_or_default(),
        reason: text("reason"),
        coverage,
        facts: Some(mapped),
        warnings,
    })
}
