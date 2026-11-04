//! The `callguard` command. See README.md.

mod decide;
mod engine_child;
mod eval;
mod flags;
mod hook;
mod plugin;
mod policy;
mod trust;

use std::io::{self, Write};
use std::panic::{AssertUnwindSafe, catch_unwind};

use callguard::hook::{LAST_RESORT_JSON, last_resort, panic_message};
use callguard::json_text;
use callguard::schema::Request;

const USAGE: &str = "callguard - allow, ask or deny a coding-agent tool call

Usage:
  callguard decide [flags]          request JSON on stdin, verdict JSON on stdout
  callguard hook <harness> [flags]  harness hook: claude, hermes, generic (opencode, pi plugins)
  callguard plugin <harness>        print the opencode or pi plugin source
  callguard policy check [flags]    load, merge and lint the policy layers
  callguard trust [flags]           review and trust a project's allow rules
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
    // Before anything starts a process: the harness's pipes stay ours.
    callguard_nah::isolate_std_handles();
    // A panic anywhere is caught in `guarded`; this only words the message.
    std::panic::set_hook(Box::new(|info| {
        let _ = writeln!(io::stderr(), "callguard: internal error: {info}");
    }));
    let args: Vec<String> = std::env::args_os()
        .skip(1)
        .map(|a| a.to_string_lossy().into_owned())
        .collect();
    let code = guarded(
        &args,
        &|| {
            run(
                &args,
                &mut io::stdin().lock(),
                &mut io::stdout().lock(),
                &mut io::stderr().lock(),
            )
        },
        &mut io::stdout(),
        &mut io::stderr(),
    );
    let _ = io::stdout().flush();
    std::process::exit(code);
}

/// Runs `dispatch`; a panic in it never fails open. Each verb answers with
/// the fallback the harness honours: Claude and Hermes hooks block with exit
/// 2 (Claude treats any other non-zero exit as "run the tool"), the generic
/// hook prints a deny verdict and exits 0 like every other generic answer, and
/// `decide` prints a fallback verdict with its documented exit 3 for failures.
fn guarded(
    args: &[String],
    dispatch: &dyn Fn() -> i32,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> i32 {
    let panic = match catch_unwind(AssertUnwindSafe(dispatch)) {
        Ok(code) => return code,
        Err(p) => panic_message(p.as_ref()),
    };
    let unattended = args
        .iter()
        .any(|a| a == "--unattended" || a == "-unattended");
    let req = Request {
        unattended,
        ..Default::default()
    };
    let verb = args.first().map(String::as_str).unwrap_or("");
    let sub = args.get(1).map(String::as_str).unwrap_or("");
    match (verb, sub) {
        ("hook", "generic") => {
            let _ = writeln!(stderr, "callguard: internal error: {panic}");
            let _ = stdout.write_all(LAST_RESORT_JSON.as_bytes());
            0
        }
        ("hook", _) => {
            let _ = writeln!(
                stderr,
                "callguard: internal error: {panic}; blocking the call"
            );
            2
        }
        ("decide", _) => {
            let v = last_resort(Some(&req), &format!("internal error: {panic}"));
            match json_text::to_string(&v) {
                Ok(b) => {
                    let _ = writeln!(stdout, "{b}");
                }
                Err(_) => {
                    let _ = stdout.write_all(LAST_RESORT_JSON.as_bytes());
                }
            }
            3
        }
        _ => {
            let _ = writeln!(stderr, "callguard: internal error: {panic}");
            1
        }
    }
}

fn run(
    args: &[String],
    stdin: &mut dyn io::Read,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> i32 {
    // Crash test hook: an explicit argument of the test, never an environment
    // variable an agent could set, and compiled out of release builds.
    #[cfg(feature = "test-engines")]
    if args.iter().any(|a| a == "--test-panic") {
        panic!("test panic");
    }
    let Some(verb) = args.first() else {
        let _ = stderr.write_all(USAGE.as_bytes());
        return 64;
    };
    let rest = &args[1..];
    match verb.as_str() {
        "decide" => decide::run(rest, stdin, stdout, stderr),
        "hook" => hook::run(rest, stdin, stdout, stderr),
        "plugin" => plugin::run(rest, stdout, stderr),
        // Hidden: the nah child process of callguard::supervisor.
        callguard::supervisor::ENGINE_VERB => engine_child::run(rest, stdin, stdout),
        "policy" => policy::run(rest, stdout, stderr),
        "trust" => trust::run(rest, stdin, stdout, stderr),
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

#[cfg(test)]
mod tests {
    use callguard::schema::{Decision, Verdict};

    use super::*;

    fn args(a: &[&str]) -> Vec<String> {
        a.iter().map(|s| (*s).to_owned()).collect()
    }

    /// A panic inside any verb must still block or ask, whatever the harness.
    fn panicking(a: &[&str]) -> (i32, String, String) {
        let args = args(a);
        let (mut out, mut err) = (Vec::new(), Vec::new());
        let code = guarded(&args, &|| panic!("boom"), &mut out, &mut err);
        (
            code,
            String::from_utf8(out).unwrap(),
            String::from_utf8(err).unwrap(),
        )
    }

    #[test]
    fn a_panic_in_a_claude_or_hermes_hook_exits_2() {
        for harness in ["claude", "hermes", "bogus"] {
            let (code, out, err) = panicking(&["hook", harness, "--log", "-"]);
            assert_eq!(code, 2, "{harness}");
            assert!(out.is_empty(), "{harness}: stdout {out:?}");
            assert!(
                err.contains("boom") && err.contains("blocking"),
                "{harness}: stderr {err:?}"
            );
        }
    }

    #[test]
    fn a_panic_in_the_generic_hook_prints_a_deny() {
        let (code, out, _) = panicking(&["hook", "generic"]);
        assert_eq!(code, 0);
        let v: Verdict = serde_json::from_str(&out).unwrap();
        assert!(v.decision == Decision::Deny && v.enforced, "{v:?}");
    }

    #[test]
    fn a_panic_in_decide_prints_a_fallback_verdict_and_exits_3() {
        let (code, out, _) = panicking(&["decide"]);
        assert_eq!(code, 3);
        let v: Verdict = serde_json::from_str(&out).unwrap();
        assert!(
            v.decision == Decision::Ask && v.enforced && v.layer == "fallback",
            "{v:?}"
        );
        // Unattended means nobody can answer an ask.
        let (code, out, _) = panicking(&["decide", "--unattended"]);
        let v: Verdict = serde_json::from_str(&out).unwrap();
        assert!(code == 3 && v.decision == Decision::Deny, "{out}");
    }

    #[test]
    fn a_panic_in_another_verb_is_not_exit_0() {
        let (code, _, err) = panicking(&["policy", "check"]);
        assert_eq!(code, 1);
        assert!(err.contains("boom"));
    }

    #[test]
    fn no_panic_passes_the_exit_code_through() {
        let a = args(&["version"]);
        let (mut out, mut err) = (Vec::new(), Vec::new());
        assert_eq!(guarded(&a, &|| 7, &mut out, &mut err), 7);
        assert!(out.is_empty() && err.is_empty());
    }

    #[test]
    fn dispatch() {
        let run_args = |a: &[&str]| {
            let (mut out, mut err) = (Vec::new(), Vec::new());
            let code = run(&args(a), &mut io::empty(), &mut out, &mut err);
            (
                code,
                String::from_utf8(out).unwrap(),
                String::from_utf8(err).unwrap(),
            )
        };
        assert_eq!(run_args(&[]).0, 64);
        assert_eq!(run_args(&["frobnicate"]).0, 64);
        let (code, out, _) = run_args(&["version"]);
        assert!(code == 0 && out.starts_with("callguard "), "{out}");
        let (code, out, _) = run_args(&["--help"]);
        assert!(code == 0 && out.contains("Usage:"));
    }
}
