//! The nah engine seam. Phase 1 runs `DelegatingEngine`, which stands in for
//! nah; Phase 2 adds `crates/callguard-nah`, the only crate that links nah, and
//! implements `NahEngine` there. Nothing in this crate depends on nah.
//! nah runs in the callguard process; `crashguard` makes a crash safe.

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
    pub budget_ms: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum NahVerdict {
    Block,
    Delegate,
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

/// Always delegates, with coverage "none" and no facts. Phase 1 uses it in
/// place of nah, so the judge and the rules see "no parse" and no allow rule
/// can match on a parse that never happened.
#[derive(Debug, Clone, Copy, Default)]
pub struct DelegatingEngine;

impl NahEngine for DelegatingEngine {
    fn decide(&self, _req: &NahRequest) -> Result<NahResult, NahError> {
        Ok(NahResult {
            verdict: NahVerdict::Delegate,
            rule: String::new(),
            reason: String::new(),
            coverage: "none".into(),
            facts: None,
        })
    }
}

/// Engines that fail on purpose, for the crash tests. Only with the
/// `test-engines` feature. The choice is made by an explicit argument of the
/// test or CLI, never by an environment variable an agent could set.
#[cfg(feature = "test-engines")]
pub mod test_engines {
    use super::*;

    /// Panics.
    #[derive(Debug, Clone, Copy, Default)]
    pub struct PanicEngine;
    impl NahEngine for PanicEngine {
        fn decide(&self, _req: &NahRequest) -> Result<NahResult, NahError> {
            panic!("test engine: panic")
        }
    }

    /// Aborts the process, as a stack overflow does.
    #[derive(Debug, Clone, Copy, Default)]
    pub struct AbortEngine;
    impl NahEngine for AbortEngine {
        fn decide(&self, _req: &NahRequest) -> Result<NahResult, NahError> {
            std::process::abort()
        }
    }

    /// Never answers.
    #[derive(Debug, Clone, Copy, Default)]
    pub struct HangEngine;
    impl NahEngine for HangEngine {
        fn decide(&self, _req: &NahRequest) -> Result<NahResult, NahError> {
            loop {
                std::thread::sleep(std::time::Duration::from_secs(3600));
            }
        }
    }

    /// The engine named "panic", "abort" or "hang".
    pub fn by_name(name: &str) -> Option<Box<dyn NahEngine>> {
        match name {
            "panic" => Some(Box::new(PanicEngine)),
            "abort" => Some(Box::new(AbortEngine)),
            "hang" => Some(Box::new(HangEngine)),
            _ => None,
        }
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
        };
        let res = DelegatingEngine.decide(&req).unwrap();
        assert_eq!(res.verdict, NahVerdict::Delegate);
        assert_eq!(res.coverage, "none");
        assert!(res.facts.is_none());
    }

    #[test]
    fn wire_format_round_trips() {
        let text = r#"{"tool":"Bash","input":{"command":"ls"},"cwd":"/","project_dir":"/","guards":{"a":false},"budget_ms":5}"#;
        let req: NahRequest = serde_json::from_str(text).unwrap();
        assert_eq!(serde_json::to_string(&req).unwrap(), text);
        let res: NahResult = serde_json::from_str(
            r#"{"verdict":"block","rule":"r","reason":"x","coverage":"full"}"#,
        )
        .unwrap();
        assert_eq!(res.verdict, NahVerdict::Block);
    }
}
