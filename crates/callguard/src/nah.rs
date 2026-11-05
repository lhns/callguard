//! The nah engine seam. `crates/callguard-nah` is the only crate that links nah
//! and implements `NahEngine` there; this crate's pipeline talks to nah through
//! `supervisor::SupervisedEngine`, a child process running that engine. Nothing
//! here depends on nah.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;

use crate::schema::Facts;

/// One call for nah to analyse. `guards` passes every guard explicitly (on or
/// off), so a project-level nah config cannot change them. `budget_ms` is the
/// analysis budget.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NahRequest {
    pub tool: String,
    pub input: Box<RawValue>,
    pub cwd: String,
    pub project_dir: String,
    pub guards: BTreeMap<String, bool>,
    /// nah's analysis budget.
    pub budget_ms: u64,
    /// The hard deadline of the whole call: the parent kills the child then.
    #[serde(default)]
    pub timeout_ms: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum NahVerdict {
    Block,
    Delegate,
}

/// One command nah found in the call, the root tool call excepted. Permission
/// rules read these and not `Facts.commands`, which leaves out calls whose
/// argv nah could not spell. They are not part of the judge's input.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct NahCall {
    /// None when nah could not spell the argv (or an element is no string).
    #[serde(default)]
    pub argv: Option<Vec<String>>,
    #[serde(default)]
    pub program: String,
    /// The working directory nah assigned to the call, if known.
    #[serde(default)]
    pub cwd: Option<String>,
    /// The program of the call this one was unwrapped from ("" at top level).
    #[serde(default)]
    pub via: String,
}

/// nah's answer. `rule` is the first policy attribution name, "" if none;
/// `coverage` is "full", "partial" or "none" (no analysis took place).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NahResult {
    pub verdict: NahVerdict,
    pub rule: String,
    pub reason: String,
    pub coverage: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub facts: Option<Facts>,
    /// Things worth telling the user, such as a refused observation.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
    /// Every call nah found but the root, unknown ones included. A reply
    /// without the field has none, and then no allow rule can match.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub calls: Vec<NahCall>,
}

/// Why nah gave no answer. The pipeline turns every variant into a warning
/// and carries on (or into the fallback when nah is required).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum NahError {
    /// The analysis did not finish in time.
    #[error("nah did not answer within {0} ms")]
    Timeout(u64),
    /// The engine panicked or failed abnormally.
    #[error("nah crashed: {0}")]
    Crashed(String),
    /// The engine reported its own failure.
    #[error("nah failed: {0}")]
    Failed(String),
}

pub trait NahEngine: Send + Sync {
    fn decide(&self, req: &NahRequest) -> Result<NahResult, NahError>;
}

/// Always delegates, with coverage "none" and no facts: a stand-in for tests
/// of this crate, which must not start a nah process.
#[cfg(test)]
#[derive(Debug, Clone, Copy, Default)]
pub struct DelegatingEngine;

#[cfg(test)]
impl NahEngine for DelegatingEngine {
    fn decide(&self, _req: &NahRequest) -> Result<NahResult, NahError> {
        Ok(NahResult {
            verdict: NahVerdict::Delegate,
            rule: String::new(),
            reason: String::new(),
            coverage: "none".into(),
            facts: None,
            warnings: Vec::new(),
            calls: Vec::new(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn delegating_engine_delegates_with_no_coverage() {
        let req = NahRequest {
            tool: "Bash".into(),
            input: RawValue::from_string(r#"{"command":"rm -rf /"}"#.into()).unwrap(),
            cwd: "/work".into(),
            project_dir: "/work".into(),
            guards: BTreeMap::new(),
            budget_ms: 2000,
            timeout_ms: 10000,
        };
        let res = DelegatingEngine.decide(&req).unwrap();
        assert_eq!(res.verdict, NahVerdict::Delegate);
        assert_eq!(res.coverage, "none");
        assert!(res.facts.is_none());
    }

    #[test]
    fn wire_format_round_trips() {
        let text = r#"{"tool":"Bash","input":{"command":"ls"},"cwd":"/","project_dir":"/","guards":{"a":false},"budget_ms":5,"timeout_ms":9}"#;
        let req: NahRequest = serde_json::from_str(text).unwrap();
        assert_eq!(serde_json::to_string(&req).unwrap(), text);
        let res: NahResult = serde_json::from_str(
            r#"{"verdict":"block","rule":"r","reason":"x","coverage":"full"}"#,
        )
        .unwrap();
        assert_eq!(res.verdict, NahVerdict::Block);
    }
}
