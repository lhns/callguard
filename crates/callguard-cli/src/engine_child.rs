//! The hidden `__engine` verb: the child process that runs nah (see
//! `callguard::supervisor`), and the crash-test engine choice.

use std::io::{Read, Write};

use callguard::engine::{self, LoadOptions, LogTarget, Options};
use callguard::policy::UserConfig;
use callguard::schema::Request;

/// The most memory the nah child may use (a constant, not a policy setting).
/// Normal use peaks near 25 MB plus the 64 MB analysis thread; `${x:-...}`
/// nested 100k deep grows 60-80 MB/s until killed. Git children share the cap.
const MEMORY_LIMIT_BYTES: usize = 512 << 20;

/// Runs nah for the parent that started this process.
pub fn run(args: &[String], stdin: &mut dyn Read, stdout: &mut dyn Write) -> i32 {
    callguard_nah::harden_process();
    callguard_nah::limit_memory(MEMORY_LIMIT_BYTES);
    #[cfg(feature = "test-engines")]
    if let Some(i) = args.iter().position(|a| a == "--test-engine") {
        let name = args.get(i + 1).map_or("", String::as_str);
        return callguard::supervisor::serve_test_engine(name, stdout);
    }
    let _ = args;
    callguard::supervisor::serve(&callguard_nah::RealEngine, stdin, stdout)
}

/// How `decide` and `hook` load the engine for `req`: the system policy file
/// (None = the platform default), the user layer unless `no_user_policy`, the
/// project layer of the request's project directory.
pub fn load_options(
    req: &Request,
    system_policy: Option<String>,
    no_user_policy: bool,
    log_path: &str,
    test_engine: &str,
) -> LoadOptions {
    LoadOptions {
        system_policy,
        project_dir: engine::resolve_project_dir(req),
        user_config_dir: if no_user_policy {
            UserConfig::None
        } else {
            UserConfig::Default
        },
        options: options(log_path, test_engine),
    }
}

/// The values of `--add-dir`, relative ones made absolute from this process's
/// directory (the request's own `cwd` moves with the agent); a leading `~/`
/// is the home directory. An empty one stays
/// empty, and the engine refuses it with a warning.
pub fn add_dirs(given: Vec<String>) -> Vec<String> {
    given
        .into_iter()
        .map(|d| {
            if d.trim().is_empty() {
                return d;
            }
            // `--add-dir=~/x` reaches us unexpanded (no shell, or `=` form).
            let env = callguard::rules::Env::host();
            let d = if (d == "~" || d.starts_with("~/")) && !env.home.is_empty() {
                format!("{}{}", env.home.trim_end_matches(['/', '\\']), &d[1..])
            } else {
                d
            };
            std::path::absolute(&d).map_or(d, |p| p.to_string_lossy().into_owned())
        })
        .collect()
}

/// Engine options for `decide` and `hook`. `log_path` is the `--log` flag:
/// "" is the default place, "-" no log. With the `test-engines` feature the
/// `--test-engine <name>` flag makes the nah child misbehave; the flag is the
/// only way to choose one, never an environment variable.
pub fn options(log_path: &str, test_engine: &str) -> Options {
    #[allow(unused_mut)] // only the test-engines build assigns
    let mut o = Options {
        log: match log_path {
            "" => LogTarget::Default,
            "-" => LogTarget::Off,
            file => LogTarget::File(file.to_owned()),
        },
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn add_dirs_become_absolute_and_an_empty_one_stays_for_the_engine_to_refuse() {
        let got = add_dirs(vec!["rel/x".into(), String::new(), "  ".into()]);
        assert!(std::path::Path::new(&got[0]).is_absolute(), "{got:?}");
        assert!(got[0].ends_with("x"));
        assert_eq!((got[1].as_str(), got[2].as_str()), ("", "  "));
        let abs = std::env::temp_dir().to_string_lossy().into_owned();
        assert_eq!(add_dirs(vec![abs.clone()]), [abs]);
        // A leading `~/` is the home directory, not a directory named `~`.
        let home = callguard::rules::Env::host().home;
        if !home.is_empty() {
            let got = add_dirs(vec!["~/x".into()]);
            assert!(
                got[0].replace('\\', "/").ends_with("/x") && !got[0].contains('~'),
                "{got:?}"
            );
        }
    }
}
