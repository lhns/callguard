//! An exec judge for the tests: `record_judge FILE` writes the classify
//! request it gets on stdin to FILE and answers "ask". Built by `cargo test`,
//! never installed.

use std::io::Read;

fn main() {
    let file = std::env::args().nth(1).expect("record_judge FILE");
    let mut s = String::new();
    let _ = std::io::stdin().read_to_string(&mut s);
    std::fs::write(file, s).expect("write");
    print!(r#"{{"label":"ask","confidence":0.9,"rule":"x","reason":"recorded"}}"#);
}
