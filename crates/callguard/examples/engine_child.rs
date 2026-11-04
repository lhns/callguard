//! The supervised child, for the supervisor's tests: `engine_child __engine
//! <mode>` plays a nah engine that behaves as the mode says. Built by `cargo
//! test`, never installed.

use std::io::{Read, Write};
use std::process::{Command, Stdio, exit};
use std::time::Duration;

use callguard::nah::{NahEngine, NahError, NahRequest, NahResult, NahVerdict};
use callguard::supervisor;

struct Fake;

impl NahEngine for Fake {
    fn decide(&self, req: &NahRequest) -> Result<NahResult, NahError> {
        Ok(NahResult {
            verdict: NahVerdict::Delegate,
            rule: String::new(),
            reason: format!("saw {}", req.tool),
            coverage: "full".into(),
            facts: None,
            warnings: Vec::new(),
            calls: Vec::new(),
        })
    }
}

fn main() {
    let mode = std::env::args().nth(2).unwrap_or_default();
    let (mut stdin, mut stdout) = (std::io::stdin().lock(), std::io::stdout().lock());
    match mode.as_str() {
        "ok" => exit(supervisor::serve(&Fake, &mut stdin, &mut stdout)),
        "panic" => panic!("child panic"),
        "abort" => std::process::abort(),
        "hang" => loop {
            std::thread::sleep(Duration::from_secs(3600));
        },
        "garbage" => {
            let _ = stdout.write_all(b"not json\n");
            exit(0);
        }
        "exit3" => {
            let _ = supervisor::serve(&Fake, &mut stdin, &mut stdout);
            exit(3);
        }
        "big" => {
            let chunk = vec![b'x'; 1 << 20];
            for _ in 0..10 {
                if stdout.write_all(&chunk).is_err() {
                    break;
                }
            }
            exit(0);
        }
        // A grandchild keeps the stdout pipe open for a long time, as a hung
        // git would; the answer must still arrive without waiting for it.
        "grandchild-ok" | "grandchild-hang" => {
            let mut sleeper = Command::new(std::env::current_exe().unwrap());
            sleeper.args(["__engine", "sleep"]).stdout(Stdio::inherit());
            let _ = sleeper.spawn();
            if mode == "grandchild-hang" {
                std::thread::sleep(Duration::from_secs(3600));
            }
            exit(supervisor::serve(&Fake, &mut stdin, &mut stdout));
        }
        // The real child loop with an engine that never answers: its own
        // watchdog must end it after the request's deadline.
        "serve-hang" => {
            struct Hang;
            impl NahEngine for Hang {
                fn decide(&self, _: &NahRequest) -> Result<NahResult, NahError> {
                    loop {
                        std::thread::sleep(Duration::from_secs(3600));
                    }
                }
            }
            exit(supervisor::serve(&Hang, &mut stdin, &mut stdout));
        }
        "sleep" => std::thread::sleep(Duration::from_secs(30)),
        _ => {
            let mut sink = Vec::new();
            let _ = stdin.read_to_end(&mut sink);
            exit(64);
        }
    }
}
