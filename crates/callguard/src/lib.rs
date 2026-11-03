//! callguard decides whether a pending coding-agent tool call may run without
//! a human prompt. See docs/design.md for the contract.
//!
//! Every module is declared here, so porting workers never edit this file.
//! Modules marked "stub" hold the Go package's exported types and function
//! signatures with `todo!()` bodies; remove the module's `#![allow]` line when
//! you port it.

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
pub mod policy;
pub mod rules;
pub mod schema;
pub mod serde_util;
pub mod supervisor;
pub mod transcript;
