//! A `git` that hangs, with a grandchild that keeps every inherited handle
//! open. Copied to a directory named `git` on PATH by the tests; built by
//! `cargo test`, never installed.

use std::process::Command;
use std::time::Duration;

fn main() {
    if std::env::args().nth(1).as_deref() != Some("--grandchild") {
        // The grandchild inherits whatever handles this process has.
        let _ = Command::new(std::env::current_exe().unwrap())
            .arg("--grandchild")
            .spawn();
    }
    std::thread::sleep(Duration::from_secs(45));
}
