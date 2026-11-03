//! `nah_cli::decide_with` over native `nah_observe`: what `callguard-nah` will wrap.

use crate::facts;
use nah_cli::{DecisionResult, shipped_guard_states};
use nah_proto::ctx::{AbsolutePath, Ctx, Platform, ShippedGuardState, TrustProjection};
use nah_proto::decision::DecisionOutput;
use nah_proto::observation::{Observation, ObservationRequest};
use nah_proto::tool::ToolCallInput;
use serde_json::{Value, json};
use std::time::Instant;

pub fn host_platform() -> Platform {
    if cfg!(windows) {
        Platform::Windows
    } else if cfg!(target_os = "macos") {
        Platform::Macos
    } else {
        Platform::Linux
    }
}

#[derive(Clone)]
pub struct Config {
    pub home: String,
    /// `factory` or `all`, then overrides.
    pub base_all: bool,
    pub overrides: Vec<(String, bool)>,
    /// None: unpatched `decide_with`, nah's 100 ms.
    pub budget_ms: Option<u64>,
}

pub fn ctx(config: &Config) -> Result<Ctx, String> {
    let platform = host_platform();
    let home = AbsolutePath::new(platform, config.home.clone()).map_err(|e| e.to_string())?;
    let mut states = if config.base_all {
        nah_cli::all_shipped_guard_states_enabled()
    } else {
        shipped_guard_states()
    };
    for (name, enabled) in &config.overrides {
        let state = states
            .iter_mut()
            .find(|s| s.name() == name)
            .ok_or_else(|| format!("unknown guard {name}"))?;
        *state = ShippedGuardState::with_explicit_disable(name.as_str(), *enabled, !*enabled)
            .map_err(|e| e.to_string())?;
    }
    Ctx::new(
        platform,
        home,
        states,
        vec![],
        TrustProjection::new(vec![]).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())
}

fn run<F>(input: &ToolCallInput, ctx: &Ctx, budget_ms: Option<u64>, observe: F) -> DecisionResult
where
    F: FnMut(&ObservationRequest) -> Result<Observation, String>,
{
    #[cfg(feature = "budget")]
    if let Some(ms) = budget_ms {
        return nah_cli::decide_with_budget(
            input,
            ctx,
            std::time::Duration::from_millis(ms),
            observe,
        );
    }
    #[cfg(not(feature = "budget"))]
    assert!(budget_ms.is_none(), "built without the budget feature");
    nah_cli::decide_with(input, ctx, observe)
}

/// One decision: `nah decide`'s output plus failures, warnings, refusals, facts.
pub fn decide(request: &[u8], config: &Config) -> Result<Value, String> {
    let input: ToolCallInput =
        serde_json::from_slice(request).map_err(|e| format!("invalid request: {e}"))?;
    let ctx = ctx(config)?;
    let started = Instant::now();
    let mut observations = Vec::new();
    let result = run(&input, &ctx, config.budget_ms, |request| {
        let observation =
            nah_observe::fulfill_observation_request(request).map_err(|e| e.to_string());
        if let Ok(observation) = &observation {
            observations.push(observation.clone());
        }
        observation
    });
    let us = u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX);
    let output = DecisionOutput::new(result.core(), "nah-native", us).map_err(|e| e.to_string())?;
    let mut value = serde_json::to_value(&output).map_err(|e| e.to_string())?;
    let object = value.as_object_mut().ok_or("output is not an object")?;
    object.insert(
        "failures".into(),
        result
            .failures()
            .iter()
            .map(|f| format!("{}/{}/{}", f.source(), f.component(), f.code()))
            .collect(),
    );
    object.insert("warnings".into(), result.warnings().iter().cloned().collect());
    object.insert(
        "refusals".into(),
        result.refusals().iter().map(|r| r.code().to_owned()).collect(),
    );
    object.insert("evidence".into(), json!(result.guard_evidence().is_some()));
    object.insert("facts".into(), facts::facts(&result, &observations));
    Ok(value)
}
