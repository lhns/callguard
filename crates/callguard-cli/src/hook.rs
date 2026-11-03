//! `callguard hook claude|hermes|generic`. A misconfigured hook must still
//! block, so every usage error exits 2 (Claude and Hermes treat other non-zero
//! exits as "run the tool"). Stub (worker C).
#![allow(unused_variables)]

use std::io::{Read, Write};

pub fn run(
    args: &[String],
    stdin: &mut dyn Read,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> i32 {
    todo!("port cmd/callguard/hook.go")
}
