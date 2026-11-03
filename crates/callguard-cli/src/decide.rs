//! `callguard decide`: request JSON on stdin, verdict JSON on stdout. Exit
//! codes: 0 allow, 1 deny, 2 ask, 3 bad request or policy error (a fallback
//! verdict is still printed), 64 bad flags. Stub (worker C).
#![allow(unused_variables)]

use std::io::{Read, Write};

pub fn run(
    args: &[String],
    stdin: &mut dyn Read,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> i32 {
    todo!("port cmd/callguard/decide.go")
}
