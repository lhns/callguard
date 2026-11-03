//! The `callguard` command. See README.md.

mod decide;
mod eval;
mod hook;
mod plugin;
mod policy;

use std::io::{self, Write};

const USAGE: &str = "callguard - allow, ask or deny a coding-agent tool call

Usage:
  callguard decide [flags]          request JSON on stdin, verdict JSON on stdout
  callguard hook <harness> [flags]  harness hook: claude, hermes, generic (opencode, pi plugins)
  callguard plugin <harness>        print the opencode or pi plugin source
  callguard policy check [flags]    load, merge and lint the policy layers
  callguard eval [flags]            run the labelled eval set
  callguard version

Run \"callguard <command> -h\" for flags.
";

/// Set at build time with `CALLGUARD_VERSION=... cargo build`.
const VERSION: &str = match option_env!("CALLGUARD_VERSION") {
    Some(v) => v,
    None => "dev",
};

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let code = run(
        &args,
        &mut io::stdin().lock(),
        &mut io::stdout().lock(),
        &mut io::stderr().lock(),
    );
    std::process::exit(code);
}

fn run(
    args: &[String],
    stdin: &mut dyn io::Read,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> i32 {
    let Some(verb) = args.first() else {
        let _ = stderr.write_all(USAGE.as_bytes());
        return 64;
    };
    let rest = &args[1..];
    match verb.as_str() {
        "decide" => decide::run(rest, stdin, stdout, stderr),
        "hook" => hook::run(rest, stdin, stdout, stderr),
        "plugin" => plugin::run(rest, stdout, stderr),
        "policy" => policy::run(rest, stdout, stderr),
        "eval" => eval::run(rest, stdout, stderr),
        "version" | "--version" => {
            let _ = writeln!(stdout, "callguard {VERSION}");
            0
        }
        "help" | "-h" | "--help" => {
            let _ = stdout.write_all(USAGE.as_bytes());
            0
        }
        other => {
            let _ = write!(stderr, "callguard: unknown command {other:?}\n\n{USAGE}");
            64
        }
    }
}
