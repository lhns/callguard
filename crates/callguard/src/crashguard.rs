//! Makes a crash in nah safe, with nah running in this process (owner's
//! decision; a separate worker is proving the design). Stub: both bodies are
//! `todo!()`.
//!
//! The goal: a panic, a stack overflow or a hang inside the engine still ends
//! with the fallback verdict on stdout and the harness's blocking exit code,
//! never with exit 0 and never with another exit code.
#![allow(unused_variables)]

use std::time::Duration;

/// What the process writes when it must give up: the exact stdout bytes of the
/// fallback answer for the harness in use, and the exit code that blocks it
/// (2 for the Claude and Hermes hooks). Built before nah runs.
#[derive(Debug, Clone)]
pub struct FallbackBytes {
    pub stdout: Vec<u8>,
    pub exit_code: i32,
}

/// Install the crash handlers before nah runs: a panic hook, a handler for
/// stack overflow, and a watchdog that fires at `hard_deadline`. Each writes
/// `fallback` and exits with its code. Call once per process.
pub fn arm(fallback: FallbackBytes, hard_deadline: Duration) {
    todo!("panic hook, overflow handler, watchdog")
}

/// Runs `f` on a thread with a 64 MB stack and returns its result. A panic in
/// `f` is returned as `Err` with the panic message.
pub fn run_on_nah_thread<T, F>(f: F) -> Result<T, String>
where
    F: FnOnce() -> T + Send + 'static,
    T: Send + 'static,
{
    todo!("spawn a 64 MB thread, join, map a panic to Err")
}
