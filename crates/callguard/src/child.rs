//! Small helpers for a child process that must answer by a deadline. Each
//! caller keeps its own policy (limits, environment, what a timeout means).

use std::io::{self, Read};
use std::process::{Child, ExitStatus};
use std::sync::mpsc::{self, Receiver};
use std::time::{Duration, Instant};

/// Waits for `child` to exit until `deadline`: `Some` if it exited, `None` if
/// the deadline came first.
pub(crate) fn wait_until(child: &mut Child, deadline: Instant) -> io::Result<Option<ExitStatus>> {
    loop {
        if let Some(status) = child.try_wait()? {
            return Ok(Some(status));
        }
        if Instant::now() >= deadline {
            return Ok(None);
        }
        std::thread::sleep(Duration::from_millis(2));
    }
}

/// Kills `child` and reaps it. Its pipes may stay open in a grandchild, so
/// callers do not wait for them.
pub(crate) fn kill(child: &mut Child) {
    let _ = child.kill();
    let _ = child.wait();
}

/// Runs `f` on `r` in a thread and reports its result by channel, so a reader
/// whose pipe a grandchild holds open is left to finish alone and never holds
/// the caller past its deadline.
pub(crate) fn read_in_background<R, T>(
    r: R,
    f: impl FnOnce(R) -> T + Send + 'static,
) -> Receiver<T>
where
    R: Read + Send + 'static,
    T: Send + 'static,
{
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(f(r));
    });
    rx
}
