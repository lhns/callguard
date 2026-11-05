//! nah linked into callguard. This is the only crate that depends on nah; the
//! rest of callguard talks to it through `callguard::nah::NahEngine`, in a
//! child process (`callguard::supervisor`).

mod engine;
mod facts;
mod harden;
mod observe;

pub use engine::RealEngine;
pub use harden::{harden_process, isolate_std_handles, limit_memory, memory_limit_warning};
