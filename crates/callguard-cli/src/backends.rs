//! `callguard backends init`: writes a template backends file for the user.
//! An explicit command only; the hook never creates files.

use std::io::Write;

use callguard::policy::{self, UserConfig};

const USAGE: &str = "usage: callguard backends init     write a template backends.json to the user's config directory\n";

pub fn run(args: &[String], stdout: &mut dyn Write, stderr: &mut dyn Write) -> i32 {
    if args != ["init"] {
        let _ = stderr.write_all(USAGE.as_bytes());
        return 64;
    }
    init(&UserConfig::Default, stdout, stderr)
}

fn init(config: &UserConfig, stdout: &mut dyn Write, stderr: &mut dyn Write) -> i32 {
    match policy::init_backends_file(config) {
        Ok(path) => {
            let _ = writeln!(
                stdout,
                "wrote {path}\n\n\
                 Replace each \"{}\" with your key, and change the models and base_url as\n\
                 needed. \"default\" names the backend the judge uses (unless the system\n\
                 policy sets llm.backend). An entry here replaces the policy's backend of\n\
                 the same name, so list data_classes for each. Instead of \"api_key\" an\n\
                 entry can name an environment variable with \"api_key_env\".\n\n\
                 Keep this file private: it is readable by your user only on Linux and\n\
                 macOS (mode 0600); on Windows it inherits the per-user permissions of\n\
                 %APPDATA%. callguard asks before an agent reads it and denies its edits,\n\
                 but a process running as you can still read it.",
                policy::PLACEHOLDER_KEY
            );
            0
        }
        Err(e) => {
            let _ = writeln!(stderr, "callguard: {e}");
            1
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run_init(dir: &std::path::Path) -> (i32, String, String) {
        let (mut out, mut err) = (Vec::new(), Vec::new());
        let code = init(
            &UserConfig::Dir(dir.to_string_lossy().into_owned()),
            &mut out,
            &mut err,
        );
        (
            code,
            String::from_utf8(out).unwrap(),
            String::from_utf8(err).unwrap(),
        )
    }

    #[test]
    fn init_writes_a_template_that_loads_quietly() {
        let d = tempfile::tempdir().unwrap();
        let (code, out, err) = run_init(d.path());
        let file = d.path().join("callguard").join("backends.json");
        assert!(code == 0 && err.is_empty(), "{code} {err}");
        assert!(out.contains(&file.to_string_lossy().into_owned()), "{out}");
        let text = std::fs::read_to_string(&file).unwrap();
        assert!(text.contains(policy::PLACEHOLDER_KEY) && text.contains("openai"));
        let sys = d.path().join("sys.json");
        std::fs::write(&sys, r#"{"policy_version":1}"#).unwrap();
        let l = policy::load(&policy::LoadOptions {
            system_policy: Some(sys.to_string_lossy().into_owned()),
            user_config_dir: UserConfig::Dir(d.path().to_string_lossy().into_owned()),
            ..Default::default()
        })
        .unwrap();
        assert!(l.warnings.is_empty() && l.problems().is_empty(), "{l:?}");
        assert_eq!(l.policy.llm.as_ref().unwrap().backend, "anthropic");
        assert!(l.policy.backends.contains_key("local"));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = |p: &std::path::Path| std::fs::metadata(p).unwrap().permissions().mode();
            assert_eq!(mode(&file) & 0o777, 0o600);
            assert_eq!(mode(file.parent().unwrap()) & 0o777, 0o700);
        }
    }

    #[test]
    fn init_refuses_to_overwrite_and_leaves_the_file_alone() {
        let d = tempfile::tempdir().unwrap();
        let file = d.path().join("callguard").join("backends.json");
        std::fs::create_dir_all(file.parent().unwrap()).unwrap();
        std::fs::write(&file, "mine").unwrap();
        let (code, out, err) = run_init(d.path());
        assert!(code == 1 && out.is_empty(), "{code} {out}");
        assert!(
            err.contains("already exists") && err.contains("backends.json"),
            "{err}"
        );
        assert_eq!(std::fs::read_to_string(&file).unwrap(), "mine");
    }

    #[test]
    fn init_takes_no_other_arguments() {
        let (mut out, mut err) = (Vec::new(), Vec::new());
        assert_eq!(run(&["init".into(), "x".into()], &mut out, &mut err), 64);
        assert_eq!(run(&[], &mut out, &mut err), 64);
        assert!(out.is_empty());
    }
}
