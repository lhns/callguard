//! The hidden `__engine` verb: the child process that runs nah (see
//! `callguard::supervisor`), and the crash-test engine choice.

use std::io::{Read, Write};

use callguard::engine::Options;

/// Runs nah for the parent that started this process.
pub fn run(args: &[String], stdin: &mut dyn Read, stdout: &mut dyn Write) -> i32 {
    callguard_nah::harden_process();
    #[cfg(feature = "test-engines")]
    if let Some(i) = args.iter().position(|a| a == "--test-engine") {
        let name = args.get(i + 1).map_or("", String::as_str);
        return callguard::supervisor::serve_test_engine(name, stdout);
    }
    let _ = args;
    callguard::supervisor::serve(&callguard_nah::RealEngine, stdin, stdout)
}

/// Engine options for `decide` and `hook`. With the `test-engines` feature the
/// `--test-engine <name>` flag makes the nah child misbehave; the flag is the
/// only way to choose one, never an environment variable.
pub fn options(log_path: &str, test_engine: &str) -> Options {
    let mut o = Options {
        log_path: log_path.to_owned(),
        ..Default::default()
    };
    #[cfg(feature = "test-engines")]
    if !test_engine.is_empty() {
        o.nah_engine = Some(std::sync::Arc::new(
            callguard::supervisor::SupervisedEngine::current().with_test_engine(test_engine),
        ));
    }
    let _ = test_engine;
    o
}
