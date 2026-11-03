//! `callguard plugin opencode|pi`: prints the plugin source embedded from
//! `adapters/` (use `include_str!("../../../adapters/...")`). Stub (worker C).
#![allow(unused_variables)]

use std::io::Write;

pub fn run(args: &[String], stdout: &mut dyn Write, stderr: &mut dyn Write) -> i32 {
    todo!("port cmd/callguard/plugin.go")
}
