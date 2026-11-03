//! Pathological inputs, each run in a child of this binary so an abort is an
//! observation rather than the end of the run.

use crate::engine::{self, Config};
use crate::{cwd_flag, flag, request};
use serde_json::{Value, json};
use std::io::Write;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

fn shell_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

/// Cases scale with n. `None` means the size is out of range for this case.
pub fn command(case: &str, n: usize) -> Option<String> {
    let nest =
        |open: &str, mid: &str, close: &str| format!("{}{}{}", open.repeat(n), mid, close.repeat(n));
    Some(match case {
        "cmdsub" => format!("echo {}", nest("$(", "echo x", ")")),
        "cmdsub-spaced" => format!("echo {}", nest("$( ", "echo x", " )")),
        "dq-cmdsub" => format!("echo {}", nest("\"$(", "echo x", ")\"")),
        "backtick" => {
            // Escaping doubles per level.
            if n > 20 {
                return None;
            }
            let mut s = "echo x".to_owned();
            for _ in 0..n {
                s = format!("echo `{}`", s.replace('\\', "\\\\").replace('`', "\\`"));
            }
            s
        }
        "subshell" => nest("(", "true", ")"),
        "brace" => nest("{ ", "true;", " };"),
        "if" => nest("if true; then ", "true", "; fi"),
        "while" => nest("while true; do ", "true", "; done"),
        "case" => nest("case x in x) ", "true", ";; esac"),
        "funcdef" => nest("f() { ", "true", "; }"),
        "arith" => format!("echo $(({}))", nest("(", "1", ")")),
        "param" => format!("echo {}", nest("${x:-", "y", "}")),
        "pipeline" => format!("true{}", " | true".repeat(n.saturating_sub(1))),
        "and-list" => format!("true{}", " && true".repeat(n.saturating_sub(1))),
        "semis" => "true;".repeat(n),
        "env-chain" => format!("{}rm -rf /", "env ".repeat(n)),
        "eval-chain" => format!("{}rm -rf /", "eval ".repeat(n)),
        "xargs-chain" => format!("echo | {}rm -rf /", "xargs ".repeat(n)),
        "sudo-chain" => format!("{}rm -rf /", "sudo ".repeat(n)),
        "bash-c-quoted" => {
            // Quoting grows exponentially; n is levels. Stop at about 32 MB.
            let mut s = "rm -rf /".to_owned();
            for _ in 0..n {
                s = format!("bash -c {}", shell_quote(&s));
                if s.len() > 32 << 20 {
                    return None;
                }
            }
            s
        }
        "func-recursion" => "f() { g; }; g() { f; }; f".to_owned(),
        // n bytes of each shape.
        "bytes-one-word" => format!("echo {}", "a".repeat(n)),
        "bytes-words" => format!("echo {}", "a ".repeat(n / 2)),
        "bytes-newlines" => "true\n".repeat(n / 5),
        "bytes-unterminated" => format!("echo \"{}", "$(".repeat(n / 2)),
        "bytes-heredoc" => format!("cat <<EOF\n{}EOF\n", "line of text\n".repeat(n / 13)),
        "heredocs" => "cat <<A\nx\nA\n".repeat(n),
        "heredoc-in-cmdsub" => nest("$(cat <<E\n", "x", "\nE\n)"),
        // Embedded languages: third-party or hand-written parsers.
        "python" => format!("python3 -c {}", shell_quote(&nest("(", "1", ")"))),
        "python-list" => format!("python3 -c {}", shell_quote(&nest("[", "1", "]"))),
        "node" => format!("node -e {}", shell_quote(&nest("[", "1", "]"))),
        "node-chain" => format!("node -e {}", shell_quote(&format!("1{}", "+1".repeat(n)))),
        "node-fn" => format!("node -e {}", shell_quote(&nest("(function(){", "1", "})"))),
        "ruby" => format!("ruby -e {}", shell_quote(&nest("[", "1", "]"))),
        "perl" => format!("perl -e {}", shell_quote(&nest("[", "1", "]"))),
        "pwsh" => format!("pwsh -Command {}", shell_quote(&nest("(", "1", ")"))),
        "pwsh-block" => format!("pwsh -Command {}", shell_quote(&nest("& {", "1", "}"))),
        "cmd" => format!("cmd /c {}", shell_quote(&nest("(", "dir", ")"))),
        "awk" => format!("awk {}", shell_quote(&nest("{", "print", "}"))),
        "jq" => format!("jq {}", shell_quote(&nest("(", ".", ")"))),
        "psql" => format!("psql -c {}", shell_quote(&format!("SELECT {}", nest("(", "1", ")")))),
        "sed" => format!("sed {}", shell_quote(&nest("{", "p", "}"))),
        "php" => format!("php -r {}", shell_quote(&format!("$x={};", nest("(", "1", ")")))),
        "lua" => format!("lua -e {}", shell_quote(&format!("x={}", nest("(", "1", ")")))),
        "julia" => format!("julia -e {}", shell_quote(&nest("(", "1", ")"))),
        "rscript" => format!("Rscript -e {}", shell_quote(&nest("(", "1", ")"))),
        "swift" => format!("swift -e {}", shell_quote(&nest("(", "1", ")"))),
        // Walks /.
        "mv-root" => "mv /* /tmp/x".to_owned(),
        "find-root" => "find / -delete".to_owned(),
        "rm-glob-root" => "rm -rf /*/*/*".to_owned(),
        _ => panic!("unknown case {case}"),
    })
}

/// A nested source file for an engine frontend: (file name, content, command).
fn source_file(case: &str, n: usize) -> Option<(&'static str, String, &'static str)> {
    let paren = format!("{}1{}", "(".repeat(n), ")".repeat(n));
    let list = format!("{}1{}", "[".repeat(n), "]".repeat(n));
    Some(match case {
        "file-py" => ("deep.py", format!("x = {paren}
"), "python3 deep.py"),
        "file-js" => ("deep.js", format!("x = {list};
"), "node deep.js"),
        "file-ts" => ("deep.ts", format!("let x = {paren};
"), "tsx deep.ts"),
        "file-rb" => ("deep.rb", format!("x = {list}
"), "ruby deep.rb"),
        "file-go" => ("deep.go", format!("package main
func main() {{ _ = {paren} }}
"), "go run deep.go"),
        "file-rs" => ("deep.rs", format!("fn main() {{ let _x = {paren}; }}
"), "rust-script deep.rs"),
        "file-java" => ("Deep.java", format!("class Deep {{ int x = {paren}; }}
"), "java Deep.java"),
        "file-php" => ("deep.php", format!("<?php $x = {paren};
"), "php deep.php"),
        "file-lua" => ("deep.lua", format!("x = {paren}
"), "lua deep.lua"),
        "file-sh" => ("deep.sh", format!("echo {}x{}
", "$(".repeat(n), ")".repeat(n)), "bash deep.sh"),
        "file-ps1" => ("deep.ps1", format!("{paren}
"), "pwsh -File deep.ps1"),
        "file-pl" => ("deep.pl", format!("my $x = {list};
"), "perl deep.pl"),
        _ => return None,
    })
}

/// Raw request bodies, for what the JSON layer sees.
fn raw_request(case: &str, n: usize, cwd: &str) -> Option<Vec<u8>> {
    let quoted = serde_json::to_string(cwd).unwrap();
    Some(match case {
        "nul" => format!(
            r#"{{"v":1,"tool":"Bash","input":{{"command":"rm\u0000 -rf /; echo \u0000"}},"cwd":{quoted}}}"#
        )
        .into_bytes(),
        "nul-many" => {
            let body = "\\u0000".repeat(n);
            format!(r#"{{"v":1,"tool":"Bash","input":{{"command":"{body}"}},"cwd":{quoted}}}"#)
                .into_bytes()
        }
        "invalid-utf8" => {
            let mut out = br#"{"v":1,"tool":"Bash","input":{"command":"rm "#.to_vec();
            out.extend_from_slice(&[0xff, 0xfe, 0xc0, 0xaf]);
            out.extend_from_slice(format!(r#" -rf /"}},"cwd":{quoted}}}"#).as_bytes());
            out
        }
        "lone-surrogate" => format!(
            r#"{{"v":1,"tool":"Bash","input":{{"command":"rm \ud800 -rf /"}},"cwd":{quoted}}}"#
        )
        .into_bytes(),
        "deep-json" => {
            let (open, close) = ("[".repeat(n), "]".repeat(n));
            format!(
                r#"{{"v":1,"tool":"Bash","input":{{"command":"x","extra":{open}{close}}},"cwd":{quoted}}}"#
            )
            .into_bytes()
        }
        "write-deep-py" => serde_json::to_vec(&json!({"v":1,"tool":"Write","input":{
            "file_path": format!("{cwd}/x.py"),
            "content": format!("x = {}1{}", "(".repeat(n), ")".repeat(n))
        },"cwd":cwd}))
        .unwrap(),
        "write-huge" => serde_json::to_vec(&json!({"v":1,"tool":"Write","input":{
            "file_path": format!("{cwd}/x.txt"), "content": "x".repeat(n)
        },"cwd":cwd}))
        .unwrap(),
        _ => return None,
    })
}

/// One case in this process. Prints a result line, or dies trying.
pub fn crash(args: &[String], config: &Config) {
    let case = flag(args, "--case").expect("--case");
    let n: usize = flag(args, "--n").map_or(1, |x| x.parse().unwrap());
    let stack = flag(args, "--stack").unwrap_or_else(|| "main".into());
    let cwd = cwd_flag(args);
    let body = if let Some((name, content, command)) = source_file(&case, n) {
        std::fs::write(std::path::Path::new(&cwd).join(name), content).unwrap();
        Some(request(command, &cwd))
    } else {
        raw_request(&case, n, &cwd).or_else(|| command(&case, n).map(|c| request(&c, &cwd)))
    };
    let Some(body) = body else {
        println!("{}", json!({"skipped": true}));
        return;
    };
    let config = config.clone();
    let size = body.len();
    let work = move || {
        let started = Instant::now();
        let result = catch_unwind(AssertUnwindSafe(|| engine::decide(&body, &config)));
        let ms = started.elapsed().as_millis() as u64;
        let line = match result {
            Ok(Ok(v)) => json!({
                "outcome":"ok","verdict":v["verdict"],"coverage":v["coverage"],
                "rules":v["policy_attributions"].as_array().map(|a| a.iter()
                    .filter_map(|x| x.get("name").cloned()).collect::<Vec<_>>()),
                "refusals":v["refusals"],"failures":v["failures"],
                "gaps": v["facts"]["gaps"].as_array().map(|g| g.iter()
                    .filter_map(|x| x.get("code").cloned()).take(3).collect::<Vec<_>>()),
                "ms":ms,"bytes":size
            }),
            Ok(Err(e)) => {
                let e: String = e.chars().take(120).collect();
                json!({"outcome":"error","error":e,"ms":ms,"bytes":size})
            }
            Err(p) => json!({"outcome":"panic-caught","panic":p.downcast_ref::<String>().cloned()
                .or_else(|| p.downcast_ref::<&str>().map(|s| (*s).to_owned())),"ms":ms,"bytes":size}),
        };
        println!("{line}");
        std::io::stdout().flush().unwrap();
    };
    if stack == "main" {
        work();
    } else {
        let mb: usize = stack.parse().expect("--stack");
        std::thread::Builder::new().stack_size(mb << 20).spawn(work).unwrap().join().unwrap();
    }
}

const LEVELS: &[usize] = &[100, 1_000, 10_000, 100_000];

fn cases() -> Vec<(&'static str, Vec<usize>)> {
    let mut out: Vec<(&'static str, Vec<usize>)> = [
        "cmdsub", "cmdsub-spaced", "dq-cmdsub", "subshell", "brace", "if", "while", "case",
        "funcdef", "arith", "param", "pipeline", "and-list", "semis", "env-chain", "eval-chain",
        "xargs-chain", "sudo-chain", "heredocs", "heredoc-in-cmdsub", "python", "python-list",
        "node", "node-chain", "node-fn", "ruby", "perl", "pwsh", "pwsh-block", "cmd", "awk", "jq",
        "psql", "sed", "php", "lua", "julia", "rscript", "swift", "file-py", "file-js", "file-ts",
        "file-rb", "file-go", "file-rs", "file-java", "file-php", "file-lua", "file-sh",
        "file-ps1", "file-pl", "nul-many", "deep-json", "write-deep-py",
    ]
    .into_iter()
    .map(|c| (c, LEVELS.to_vec()))
    .collect();
    out.push(("backtick", vec![4, 8, 12, 16, 20]));
    out.push(("bash-c-quoted", vec![4, 8, 12, 16, 20, 24]));
    for c in [
        "bytes-one-word", "bytes-words", "bytes-newlines", "bytes-unterminated", "bytes-heredoc",
        "write-huge",
    ] {
        out.push((c, vec![1 << 20, 16 << 20]));
    }
    for c in [
        "func-recursion", "nul", "invalid-utf8", "lone-surrogate", "mv-root", "find-root",
        "rm-glob-root",
    ] {
        out.push((c, vec![1]));
    }
    out
}

/// Every case in a child per size and stack; a case that dies or hangs at some
/// size is not run at larger sizes on that stack. One JSON object per line.
pub fn matrix(args: &[String]) {
    let exe = std::env::current_exe().unwrap();
    let timeout = Duration::from_secs(flag(args, "--timeout").map_or(40, |x| x.parse().unwrap()));
    let stacks = flag(args, "--stacks").unwrap_or_else(|| "main,2,64,256".into());
    let only = flag(args, "--only");
    let budgets = flag(args, "--budgets").unwrap_or_else(|| "none".into());
    let cwd = cwd_flag(args);
    for budget in budgets.split(',') {
        for stack in stacks.split(',') {
            for (case, sizes) in cases() {
                if only.as_deref().is_some_and(|o| !o.split(',').any(|c| c == case)) {
                    continue;
                }
                for n in sizes {
                    let mut cmd = Command::new(&exe);
                    cmd.args(["crash", "--case", case, "--n", &n.to_string()])
                        .args(["--stack", stack, "--cwd", &cwd])
                        .stdin(Stdio::null())
                        .stdout(Stdio::piped())
                        .stderr(Stdio::piped());
                    if budget != "none" {
                        cmd.args(["--budget-ms", budget]);
                    }
                    let started = Instant::now();
                    let mut child = cmd.spawn().unwrap();
                    // Children print little, so pipes will not fill before exit;
                    // panic messages are short too.
                    let mut hung = false;
                    let status = loop {
                        if let Some(status) = child.try_wait().unwrap() {
                            break Some(status);
                        }
                        if started.elapsed() > timeout {
                            hung = true;
                            let _ = child.kill();
                            let _ = child.wait();
                            break None;
                        }
                        std::thread::sleep(Duration::from_millis(5));
                    };
                    let ms = started.elapsed().as_millis() as u64;
                    let output = child.wait_with_output().unwrap();
                    let stdout = String::from_utf8_lossy(&output.stdout);
                    let stderr = String::from_utf8_lossy(&output.stderr);
                    let inner: Value = stdout
                        .lines()
                        .last()
                        .and_then(|l| serde_json::from_str(l).ok())
                        .unwrap_or(Value::Null);
                    let code = status.and_then(|s| s.code());
                    let kind = if hung {
                        "HANG"
                    } else if code != Some(0) {
                        "DIED"
                    } else if inner.is_null() {
                        "NOOUTPUT"
                    } else {
                        "ok"
                    };
                    let tail: String = {
                        let v: Vec<char> = stderr.chars().collect();
                        v[v.len().saturating_sub(160)..].iter().collect()
                    };
                    println!(
                        "{}",
                        json!({
                            "case":case,"n":n,"stack":stack,"budget":budget,"kind":kind,
                            "exit":code,"wall_ms":ms,"r":inner,"stderr":tail,
                        })
                    );
                    std::io::stdout().flush().unwrap();
                    if kind != "ok" || inner.get("skipped").is_some() {
                        break;
                    }
                }
            }
        }
    }
}

/// The hard-deadline shape: the decision runs on a big-stack thread, the main
/// thread waits with a timeout and on expiry writes the fallback and exits 2.
/// `--hang` blocks the worker forever, `--panic` panics it; otherwise
/// --case/--n are decided for real.
pub fn deadline(args: &[String], config: &Config) {
    let limit = Duration::from_millis(flag(args, "--limit-ms").map_or(500, |x| x.parse().unwrap()));
    let panic_inside = args.iter().any(|a| a == "--panic");
    let hang = args.iter().any(|a| a == "--hang");
    let case = flag(args, "--case").unwrap_or_else(|| "mv-root".into());
    let n: usize = flag(args, "--n").map_or(1, |x| x.parse().unwrap());
    let body = request(&command(&case, n).unwrap(), &cwd_flag(args));
    let config = config.clone();
    std::panic::set_hook(Box::new(|info| {
        println!(r#"{{"fallback":"panic","detail":{:?}}}"#, info.to_string());
        let _ = std::io::stdout().flush();
        std::process::exit(2);
    }));
    let (tx, rx) = std::sync::mpsc::channel();
    let started = Instant::now();
    std::thread::Builder::new()
        .stack_size(64 << 20)
        .spawn(move || {
            assert!(!panic_inside, "engine panicked");
            while hang {
                std::thread::sleep(Duration::from_secs(3600));
            }
            let _ = tx.send(engine::decide(&body, &config));
        })
        .unwrap();
    match rx.recv_timeout(limit) {
        Ok(result) => println!(
            "{}",
            json!({"decided": result.map(|v| v["verdict"].clone()), "ms": started.elapsed().as_millis() as u64})
        ),
        Err(_) => {
            println!("{}", json!({"fallback":"deadline","ms":started.elapsed().as_millis() as u64}));
            let _ = std::io::stdout().flush();
            std::process::exit(2);
        }
    }
}
