//! callguard decides whether a pending coding-agent tool call may run without
//! a human prompt. See docs/design.md for the contract.
//!

pub mod backend;
pub mod declog;
pub mod engine;
pub mod evalrun;
pub mod evals;
pub mod fallback;
pub mod gitfilter;
pub mod gojson;
pub mod hook;
pub mod hostmeta;
pub mod judge;
pub mod nah;
pub mod permissions;
pub mod policy;
pub mod rules;
pub mod schema;
pub mod serde_util;
pub mod supervisor;
pub mod transcript;
pub mod trust;
pub mod which;
