//! Runs nah in a child process of callguard, so nothing nah does can take the
//! hook down: a stack overflow aborts the whole
//! process and `catch_unwind` cannot see it, so the parent never touches nah.
//!
//! The parent starts `current_exe() __engine`, writes the [`NahRequest`] as
//! JSON on its stdin and reads one line of JSON, a [`Reply`], from its stdout.
//! A crash, a timeout, a nonzero exit, oversized or unreadable output is a
//! [`NahError`].

use std::io::{self, Read, Write};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::nah::{NahEngine, NahError, NahRequest, NahResult};

/// The most bytes the parent reads from the child. Facts of a big command run
/// to a few hundred KB; more is a runaway.
pub const MAX_REPLY_BYTES: usize = 8 << 20;

/// The most request bytes the child reads: a tool input is at most a few MB.
pub const MAX_REQUEST_BYTES: u64 = 64 << 20;

/// The hidden verb the child is started with.
pub const ENGINE_VERB: &str = "__engine";

/// What the child writes: one JSON line.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[allow(clippy::large_enum_variant)]
pub enum Reply {
    Result(NahResult),
    /// The engine ran and reported its own failure.
    Error(String),
}

/// The [`NahEngine`] the pipeline uses: nah in a child process.
#[derive(Debug, Clone)]
pub struct SupervisedEngine {
    exe: PathBuf,
    /// Extra arguments after the verb (crash-test engines).
    args: Vec<String>,
}

impl SupervisedEngine {
    /// Runs this executable's `__engine` verb.
    pub fn current() -> SupervisedEngine {
        SupervisedEngine::with_exe(std::env::current_exe().unwrap_or_default())
    }

    pub fn with_exe(exe: PathBuf) -> SupervisedEngine {
        SupervisedEngine {
            exe,
            args: Vec::new(),
        }
    }

    /// Extra arguments after the verb.
    pub fn with_args(mut self, args: Vec<String>) -> SupervisedEngine {
        self.args = args;
        self
    }

    /// The child runs the crash-test engine `name` (see [`serve_test_engine`]).
    #[cfg(feature = "test-engines")]
    pub fn with_test_engine(self, name: &str) -> SupervisedEngine {
        self.with_args(vec!["--test-engine".into(), name.into()])
    }

    fn spawn(&self) -> io::Result<Child> {
        // All three handles explicit: nothing of the harness's pipes may reach
        // the child or the `git` it starts, or a hanging git would hold the
        // harness's stdout open past our exit.
        Command::new(&self.exe)
            .arg(ENGINE_VERB)
            .args(&self.args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
    }
}

/// What the stdout reader found.
enum Read1 {
    Line(Vec<u8>),
    /// EOF before a newline: the child ended without a reply.
    Eof(usize),
    TooLarge,
}

/// Reads up to the first newline. It stops there instead of waiting for EOF,
/// because a grandchild can hold the pipe open after the child is gone.
fn read_line(mut r: impl Read) -> Read1 {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 8192];
    loop {
        match r.read(&mut chunk) {
            Ok(0) | Err(_) => return Read1::Eof(buf.len()),
            Ok(n) => {
                if let Some(i) = chunk[..n].iter().position(|b| *b == b'\n') {
                    buf.extend_from_slice(&chunk[..i]);
                    return if buf.len() > MAX_REPLY_BYTES {
                        Read1::TooLarge
                    } else {
                        Read1::Line(buf)
                    };
                }
                buf.extend_from_slice(&chunk[..n]);
                if buf.len() > MAX_REPLY_BYTES {
                    return Read1::TooLarge;
                }
            }
        }
    }
}

fn kill(child: &mut Child) {
    let _ = child.kill();
    let _ = child.wait();
}

impl NahEngine for SupervisedEngine {
    fn decide(&self, req: &NahRequest) -> Result<NahResult, NahError> {
        let timeout = Duration::from_millis(req.timeout_ms.max(1));
        let deadline = Instant::now() + timeout;
        let body = serde_json::to_vec(req).map_err(|e| NahError::Failed(e.to_string()))?;
        let mut child = self
            .spawn()
            .map_err(|e| NahError::Failed(format!("cannot start the nah process: {e}")))?;

        // The request goes in from a thread, so a child that never reads cannot
        // block us before the deadline starts to count.
        let mut stdin = child.stdin.take().expect("stdin is piped");
        std::thread::spawn(move || {
            let _ = stdin.write_all(&body);
        });
        let stdout = child.stdout.take().expect("stdout is piped");
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            let _ = tx.send(read_line(stdout));
        });

        let line = match rx.recv_timeout(timeout) {
            Ok(Read1::Line(line)) => line,
            Ok(Read1::TooLarge) => {
                kill(&mut child);
                return Err(NahError::Failed("the nah process wrote too much".into()));
            }
            Ok(Read1::Eof(n)) => {
                // Ended without a reply: the exit status says how.
                return Err(match wait_until(&mut child, deadline) {
                    Some(st) => NahError::Crashed(format!(
                        "the nah process ended with {st} and no answer ({n} bytes of output)"
                    )),
                    None => {
                        kill(&mut child);
                        NahError::Timeout(req.timeout_ms)
                    }
                });
            }
            Err(_) => {
                // The pipe may stay open in a grandchild: do not wait for it.
                kill(&mut child);
                return Err(NahError::Timeout(req.timeout_ms));
            }
        };
        // A reply, then the child must also exit cleanly.
        match wait_until(&mut child, deadline) {
            Some(st) if st.success() => {}
            Some(st) => {
                return Err(NahError::Crashed(format!(
                    "the nah process ended with {st}"
                )));
            }
            None => {
                kill(&mut child);
                return Err(NahError::Timeout(req.timeout_ms));
            }
        }
        match serde_json::from_slice::<Reply>(&line) {
            Ok(Reply::Result(r)) => Ok(r),
            Ok(Reply::Error(e)) => Err(NahError::Failed(e)),
            Err(e) => Err(NahError::Failed(format!(
                "the nah process wrote an unreadable answer: {e}"
            ))),
        }
    }
}

/// Waits for `child` to exit until `deadline`.
fn wait_until(child: &mut Child, deadline: Instant) -> Option<std::process::ExitStatus> {
    loop {
        match child.try_wait() {
            Ok(Some(st)) => return Some(st),
            Ok(None) => {}
            Err(_) => return None,
        }
        if Instant::now() >= deadline {
            return None;
        }
        std::thread::sleep(Duration::from_millis(1));
    }
}

/// Ends this process a little after the parent's deadline, so a child whose
/// parent died (the harness killed callguard) does not spin on forever.
fn watchdog(timeout_ms: u64) {
    let limit = Duration::from_millis(timeout_ms.max(1)) + Duration::from_secs(2);
    std::thread::spawn(move || {
        std::thread::sleep(limit);
        std::process::exit(3);
    });
}

/// The child's side: reads the request from `stdin`, asks `engine`, writes one
/// reply line to `stdout`. Returns the process exit code.
pub fn serve(engine: &dyn NahEngine, stdin: &mut dyn Read, stdout: &mut dyn Write) -> i32 {
    let Ok(Some(body)) = crate::io_util::read_capped(stdin, MAX_REQUEST_BYTES as usize) else {
        return 1;
    };
    let reply = match serde_json::from_slice::<NahRequest>(&body) {
        Err(e) => Reply::Error(format!("unreadable request: {e}")),
        Ok(req) => {
            watchdog(req.timeout_ms);
            match engine.decide(&req) {
                Ok(r) => Reply::Result(r),
                Err(e) => Reply::Error(e.to_string()),
            }
        }
    };
    let Ok(mut line) = serde_json::to_vec(&reply) else {
        return 1;
    };
    line.push(b'\n');
    if stdout
        .write_all(&line)
        .and_then(|()| stdout.flush())
        .is_err()
    {
        return 1;
    }
    0
}

/// Crash-test engines for the child, `__engine --test-engine <name>`: panic,
/// abort, hang, overflow, garbage and oom. Compiled out of release builds;
/// only an explicit argument of the test selects one, never an environment
/// variable.
#[cfg(feature = "test-engines")]
pub fn serve_test_engine(name: &str, stdout: &mut dyn Write) -> i32 {
    #[allow(unconditional_recursion)]
    fn recurse(n: u64) -> u64 {
        let pad = [n as u8; 256];
        std::hint::black_box(&pad);
        recurse(n + 1) + u64::from(pad[0])
    }
    match name {
        "panic" => panic!("test engine: panic"),
        "abort" => std::process::abort(),
        "hang" => loop {
            std::thread::sleep(Duration::from_secs(3600));
        },
        "overflow" => i32::try_from(recurse(0) % 7).unwrap_or(1),
        "garbage" => {
            let _ = stdout.write_all(b"this is not json\n");
            let _ = stdout.flush();
            0
        }
        // An allocation that cannot succeed ends in the allocator's abort.
        "oom" => {
            let v = vec![1u8; usize::MAX / 2];
            std::hint::black_box(&v);
            0
        }
        _ => 64,
    }
}

#[cfg(test)]
mod tests;
