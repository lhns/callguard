//! The exec backend's test plugin. `exec_helper <mode>` reads a classify
//! request on stdin and misbehaves as the mode says. Built by `cargo test`,
//! never installed.

use std::io::{Read, Write};
use std::process::exit;
use std::time::Duration;

fn main() {
    let mode = std::env::args().nth(1).unwrap_or_default();
    match mode.as_str() {
        "ok" => {
            let mut stdin = String::new();
            let _ = std::io::stdin().read_to_string(&mut stdin);
            let Ok(v) = serde_json::from_str::<serde_json::Value>(&stdin) else {
                eprintln!("bad stdin");
                exit(3);
            };
            if v["schema"] != "callguard/classify/v1"
                || v["system"] != "sys"
                || v["prompt"] != "prompt"
                || v["labels"].is_null()
                || v["input"].is_null()
            {
                eprintln!("unexpected stdin {v}");
                exit(4);
            }
            print!(r#"{{"label":"ask","confidence":0.8,"rule":"x","reason":"y"}}"#);
        }
        "fail" => {
            eprint!("plugin exploded");
            exit(2);
        }
        "garbage" => print!("not json"),
        "big" => print!("{}", "a".repeat(70 << 10)),
        "hang" => std::thread::sleep(Duration::from_secs(60)),
        _ => {}
    }
    let _ = std::io::stdout().flush();
}
