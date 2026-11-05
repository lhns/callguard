//! `callguard hook claude|hermes|generic`. A misconfigured hook must still
//! block, so every usage error exits 2 (Claude and Hermes treat other non-zero
//! exits as "run the tool").

use std::io::{Read, Write};

use callguard::engine::Engine;
use callguard::fallback::fallback_verdict;
use callguard::hook::{self, Options};
use callguard::schema::{Request, Verdict};

use crate::engine_child;
use crate::flags::{self, FlagError, Kind, spec};

const USAGE: &str = "usage: callguard hook claude|hermes|generic [flags]

Flags:
  --policy PATH         system policy file (default: the platform default)
  --no-user-policy      do not read the user policy layer
  --log PATH            decision log path (\"-\" disables logging)
  --unattended          nobody can answer a prompt: ask becomes deny
  --context KEY=VALUE   request context entry (repeatable)
  --context-file PATH   JSON object of strings merged into the context;
                        must be root-owned, the agent must not be able to write it
  --allow-in-auto       claude only: also emit allow in permission_mode auto
  --add-dir PATH        a directory besides the project that counts as inside
                        it (repeatable; not the home directory or a root)

claude also answers InstructionsLoaded events (register the hook for them
too; it prints nothing): the loaded file paths are recorded per session in
<state dir>/callguard/instructions/ and their text goes to the llm judge as
unverified context.
";

/// Runs a hook adapter. Usage errors exit 2: Claude and Hermes treat exit 2 as
/// a block and any other non-zero exit as "run the tool"; the plugins block on
/// any non-zero exit.
pub fn run(
    args: &[String],
    stdin: &mut dyn Read,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> i32 {
    let Some(name) = args.first() else {
        let _ = stderr.write_all(USAGE.as_bytes());
        return 2;
    };
    if !matches!(name.as_str(), "claude" | "hermes" | "generic") {
        let _ = write!(
            stderr,
            "callguard hook: unknown harness {name:?}; blocking the call\n\n{USAGE}"
        );
        return 2;
    }

    let f = match flags::parse(
        &[
            spec("policy", Kind::Str),
            spec("no-user-policy", Kind::Bool),
            spec("log", Kind::Str),
            spec("unattended", Kind::Bool),
            #[cfg(feature = "test-engines")]
            spec("test-engine", Kind::Str),
            spec("context", Kind::Pair),
            spec("context-file", Kind::Str),
            spec("allow-in-auto", Kind::Bool),
            spec("add-dir", Kind::List),
        ],
        &args[1..],
    ) {
        Ok(f) => f,
        Err(FlagError::Help) => {
            let _ = stderr.write_all(USAGE.as_bytes());
            return 0;
        }
        Err(FlagError::Bad(m)) => {
            let _ = writeln!(stderr, "{m}");
            let _ = writeln!(stderr, "callguard hook: bad flags; blocking the call");
            return 2;
        }
    };
    if let Some(extra) = f.rest.first() {
        let _ = writeln!(
            stderr,
            "callguard hook: unexpected argument {extra:?}; blocking the call"
        );
        return 2;
    }
    if f.bool("allow-in-auto") && name != "claude" {
        let _ = writeln!(
            stderr,
            "callguard hook: --allow-in-auto applies to claude only; blocking the call"
        );
        return 2;
    }

    let opt = Options {
        unattended: f.bool("unattended"),
        context: f.pairs("context").into_iter().collect(),
        context_file: f.str("context-file"),
        allow_in_auto: f.bool("allow-in-auto"),
        additional_dirs: engine_child::add_dirs(f.list("add-dir")),
        // Beside the default decision log, whatever --log says.
        instructions_dir: (name == "claude")
            .then(callguard::instructions::default_dir)
            .flatten(),
    };
    let policy_path = f.opt_str("policy");
    let test_engine = f.str("test-engine");
    let no_user = f.bool("no-user-policy");
    let log_path = f.str("log");
    // The engine is built per request, because the project policy layer
    // depends on the request's project directory.
    let d = move |req: &Request| -> Verdict {
        let lo =
            engine_child::load_options(req, policy_path.clone(), no_user, &log_path, &test_engine);
        match Engine::load(lo) {
            Ok(eng) => eng.decide(req),
            Err(e) => fallback_verdict(Some(req), &format!("policy: {e}")),
        }
    };
    match name.as_str() {
        "claude" => hook::claude(stdin, stdout, stderr, &opt, &d),
        "hermes" => hook::hermes(stdin, stdout, stderr, &opt, &d),
        _ => hook::generic(stdin, stdout, stderr, &opt, &d),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run_hook(args: &[&str]) -> i32 {
        let args: Vec<String> = args.iter().map(|s| (*s).to_owned()).collect();
        run(
            &args,
            &mut std::io::empty(),
            &mut Vec::new(),
            &mut Vec::new(),
        )
    }

    /// Every usage error must block (exit 2), never exit 1 or 64, which Claude
    /// and Hermes treat as "run the tool".
    #[test]
    fn usage_errors_exit_2() {
        assert_eq!(run_hook(&[]), 2, "no harness");
        assert_eq!(run_hook(&["claud"]), 2, "unknown harness");
        for h in ["claude", "hermes", "generic"] {
            assert_eq!(run_hook(&[h, "--bogus"]), 2, "{h} bad flag");
            assert_eq!(run_hook(&[h, "--context", "novalue"]), 2, "{h} bad context");
            assert_eq!(run_hook(&[h, "extra"]), 2, "{h} extra argument");
        }
        assert_eq!(
            run_hook(&["hermes", "--allow-in-auto"]),
            2,
            "hermes --allow-in-auto"
        );
        assert_eq!(run_hook(&["generic", "--allow-in-auto"]), 2);
    }

    #[test]
    fn help_is_not_a_block() {
        assert_eq!(run_hook(&["claude", "-h"]), 0);
    }

    /// With the engine failing to build, the hook answers with the fallback:
    /// the Claude adapter asks, never allows.
    #[test]
    fn an_unusable_policy_asks() {
        let args: Vec<String> = [
            "claude",
            "--policy",
            "/definitely/not/here.json",
            "--no-user-policy",
            "--log",
            "-",
        ]
        .iter()
        .map(|s| (*s).to_owned())
        .collect();
        let payload = r#"{"hook_event_name":"PreToolUse","tool_name":"Read","tool_input":{"file_path":"/x"}}"#;
        let (mut out, mut err) = (Vec::new(), Vec::new());
        let code = run(&args, &mut payload.as_bytes(), &mut out, &mut err);
        let out = String::from_utf8(out).unwrap();
        assert!(
            code == 0 && out.contains(r#""permissionDecision":"ask""#),
            "code={code} out={out:?}"
        );
    }
}
