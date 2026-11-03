//! `callguard plugin opencode|pi`: prints the plugin source embedded from
//! `adapters/`, byte for byte.

use std::io::Write;

const USAGE: &str = "usage: callguard plugin opencode|pi

Prints the plugin source. Install with:
  callguard plugin opencode > ~/.config/opencode/plugins/callguard.js
  callguard plugin pi > ~/.pi/agent/extensions/callguard/index.js
";

const OPENCODE: &str = include_str!("../../../adapters/opencode/callguard.js");
const PI: &str = include_str!("../../../adapters/pi/callguard.js");

pub fn run(args: &[String], stdout: &mut dyn Write, stderr: &mut dyn Write) -> i32 {
    let [harness] = args else {
        let _ = stderr.write_all(USAGE.as_bytes());
        return 64;
    };
    match harness.as_str() {
        "opencode" => {
            let _ = stdout.write_all(OPENCODE.as_bytes());
        }
        "pi" => {
            let _ = stdout.write_all(PI.as_bytes());
        }
        other => {
            let _ = write!(
                stderr,
                "callguard plugin: unknown harness {other:?}\n\n{USAGE}"
            );
            return 64;
        }
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run_plugin(args: &[&str]) -> (i32, Vec<u8>) {
        let args: Vec<String> = args.iter().map(|s| (*s).to_owned()).collect();
        let mut out = Vec::new();
        let code = run(&args, &mut out, &mut Vec::new());
        (code, out)
    }

    #[test]
    fn prints_embedded_source() {
        for (h, src) in [("opencode", OPENCODE), ("pi", PI)] {
            let (code, out) = run_plugin(&[h]);
            let text = String::from_utf8(out).unwrap();
            assert!(code == 0 && text.contains("hook"), "{h}: code={code}");
            assert_eq!(text, src, "{h}: not byte-identical");
        }
        let (code, out) = run_plugin(&["vim"]);
        assert!(code == 64 && out.is_empty());
        assert_eq!(run_plugin(&[]).0, 64);
        assert_eq!(run_plugin(&["pi", "extra"]).0, 64);
    }

    #[test]
    fn plugins_match_the_files_on_disk() {
        let root = format!("{}/../..", env!("CARGO_MANIFEST_DIR"));
        for (h, src) in [("opencode", OPENCODE), ("pi", PI)] {
            let disk = std::fs::read(format!("{root}/adapters/{h}/callguard.js")).unwrap();
            assert_eq!(disk, src.as_bytes(), "{h}");
        }
    }
}
