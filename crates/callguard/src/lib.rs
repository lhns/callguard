//! callguard decides whether a pending coding-agent tool call may run without
//! a human prompt. See docs/design.md for the contract.
//!

pub mod backend;
mod child;
pub(crate) mod declog;
pub mod engine;
pub mod evalrun;
pub mod evals;
pub mod fallback;
pub mod gitfilter;
pub mod hook;
pub mod hostmeta;
pub mod io_util;
pub mod json_text;
pub(crate) mod judge;
pub mod nah;
pub mod permissions;
pub mod policy;
pub mod rules;
pub mod schema;
pub(crate) mod serde_util;
pub mod supervisor;
pub(crate) mod transcript;
pub mod trust;
pub(crate) mod which;
