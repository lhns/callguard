//! Turns harness hook payloads into callguard requests and callguard verdicts
//! into each harness's native answer. The adapters never fail open: every
//! internal failure becomes an ask/deny answer the harness honours
//! (docs/design.md sections 9 and 10). Stub (worker C).
//!
//! A [`Decider`] borrows the request; the adapters catch panics from it
//! (`catch_unwind`) and answer with the fallback.
#![allow(unused_variables, dead_code)]

use std::collections::BTreeMap;
use std::io::{Read, Write};

use crate::schema::{Request, Verdict};

/// Caps the hook payload read from stdin.
pub const MAX_INPUT: usize = 4 << 20;

/// Decides one request.
pub type Decider<'a> = &'a (dyn Fn(&Request) -> Verdict + Sync);

/// The adapter flags shared by all harnesses.
#[derive(Debug, Clone, Default)]
pub struct Options {
    /// Marks every request as unattended (`--unattended`).
    pub unattended: bool,
    /// `--context key=value` entries, merged into `req.context`.
    pub context: BTreeMap<String, String>,
    /// A JSON object of strings merged into `req.context` (`--context-file`).
    /// Read on every call; an unreadable or invalid file yields a fallback
    /// verdict. It must be root-owned: the agent must not be able to write it.
    pub context_file: String,
    /// Lets the Claude adapter emit allow in permission_mode auto.
    pub allow_in_auto: bool,
}

/// The Claude Code hook. Returns the process exit code (0, or 2 to block).
pub fn claude(
    input: &mut dyn Read,
    out: &mut dyn Write,
    err_out: &mut dyn Write,
    opt: &Options,
    d: Decider,
) -> i32 {
    todo!("port hook.Claude")
}

/// The Hermes hook. Returns the process exit code.
pub fn hermes(
    input: &mut dyn Read,
    out: &mut dyn Write,
    err_out: &mut dyn Write,
    opt: &Options,
    d: Decider,
) -> i32 {
    todo!("port hook.Hermes")
}

/// The adapter for the opencode and pi plugins: request fields on stdin, a
/// callguard verdict on stdout, exit 0 always. The plugins fail closed on
/// anything else.
pub fn generic(
    input: &mut dyn Read,
    out: &mut dyn Write,
    err_out: &mut dyn Write,
    opt: &Options,
    d: Decider,
) -> i32 {
    todo!("port hook.Generic")
}
