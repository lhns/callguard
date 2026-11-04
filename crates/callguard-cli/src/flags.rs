//! A command-line parser where `-name` and `--name` are the same flag, kept so
//! every spelling in existing scripts and policies keeps working: `-name`, `--name`, `-name=value`,
//! `-name value`, `--` to end the flags, and parsing stops at the first
//! argument that is not a flag.

use std::collections::HashMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Bool,
    Str,
    Int,
    Float,
    /// A repeatable `KEY=VALUE` flag.
    Pair,
}

#[derive(Debug, Clone, Copy)]
pub struct Spec {
    pub name: &'static str,
    pub kind: Kind,
}

pub const fn spec(name: &'static str, kind: Kind) -> Spec {
    Spec { name, kind }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FlagError {
    /// `-h`, `-help` or `--help`.
    Help,
    Bad(String),
}

impl std::fmt::Display for FlagError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FlagError::Help => f.write_str("help requested"),
            FlagError::Bad(m) => f.write_str(m),
        }
    }
}

#[derive(Debug, Default)]
pub struct Parsed {
    strs: HashMap<&'static str, String>,
    bools: HashMap<&'static str, bool>,
    ints: HashMap<&'static str, i64>,
    floats: HashMap<&'static str, f64>,
    pairs: HashMap<&'static str, Vec<(String, String)>>,
    /// The arguments after the flags.
    pub rest: Vec<String>,
}

impl Parsed {
    /// Whether the flag was given.
    pub fn is_set(&self, name: &str) -> bool {
        self.strs.contains_key(name)
    }

    pub fn str(&self, name: &str) -> String {
        self.strs.get(name).cloned().unwrap_or_default()
    }

    pub fn bool(&self, name: &str) -> bool {
        self.bools.get(name).copied().unwrap_or(false)
    }

    pub fn int(&self, name: &str, default: i64) -> i64 {
        self.ints.get(name).copied().unwrap_or(default)
    }

    pub fn float(&self, name: &str, default: f64) -> f64 {
        self.floats.get(name).copied().unwrap_or(default)
    }

    /// The `KEY=VALUE` entries in the order given.
    pub fn pairs(&self, name: &str) -> Vec<(String, String)> {
        self.pairs.get(name).cloned().unwrap_or_default()
    }
}

fn parse_bool(s: &str) -> Option<bool> {
    match s {
        "1" | "t" | "T" | "true" | "TRUE" | "True" => Some(true),
        "0" | "f" | "F" | "false" | "FALSE" | "False" => Some(false),
        _ => None,
    }
}

pub fn parse(specs: &[Spec], args: &[String]) -> Result<Parsed, FlagError> {
    let mut out = Parsed::default();
    let mut i = 0;
    while i < args.len() {
        let arg = &args[i];
        if !arg.starts_with('-') || arg == "-" {
            break;
        }
        i += 1;
        if arg == "--" {
            break;
        }
        let name = arg.trim_start_matches('-');
        if arg.len() - name.len() > 2 || name.is_empty() || name.starts_with('=') {
            return Err(FlagError::Bad(format!("bad flag syntax: {arg}")));
        }
        let (name, inline) = match name.split_once('=') {
            Some((n, v)) => (n, Some(v.to_owned())),
            None => (name, None),
        };
        let Some(sp) = specs.iter().find(|s| s.name == name) else {
            if matches!(name, "h" | "help") {
                return Err(FlagError::Help);
            }
            return Err(FlagError::Bad(format!(
                "flag provided but not defined: -{name}"
            )));
        };
        if sp.kind == Kind::Bool {
            let v = match inline {
                None => true,
                Some(v) => parse_bool(&v).ok_or_else(|| {
                    FlagError::Bad(format!("invalid boolean value {v:?} for -{name}"))
                })?,
            };
            out.bools.insert(sp.name, v);
            continue;
        }
        let value = match inline {
            Some(v) => v,
            None => {
                let v = args
                    .get(i)
                    .ok_or_else(|| FlagError::Bad(format!("flag needs an argument: -{name}")))?;
                i += 1;
                v.clone()
            }
        };
        match sp.kind {
            Kind::Str => {
                out.strs.insert(sp.name, value);
            }
            Kind::Int => {
                let v = value.parse::<i64>().map_err(|_| {
                    FlagError::Bad(format!(
                        "invalid value {value:?} for flag -{name}: parse error"
                    ))
                })?;
                out.ints.insert(sp.name, v);
            }
            Kind::Float => {
                let v = value.parse::<f64>().map_err(|_| {
                    FlagError::Bad(format!(
                        "invalid value {value:?} for flag -{name}: parse error"
                    ))
                })?;
                out.floats.insert(sp.name, v);
            }
            Kind::Pair => {
                let Some((k, v)) = value.split_once('=').filter(|(k, _)| !k.is_empty()) else {
                    return Err(FlagError::Bad(format!(
                        "invalid value {value:?} for flag -{name}: want KEY=VALUE"
                    )));
                };
                out.pairs
                    .entry(sp.name)
                    .or_default()
                    .push((k.to_owned(), v.to_owned()));
            }
            Kind::Bool => unreachable!("handled above"),
        }
    }
    out.rest = args[i..].to_vec();
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SPECS: &[Spec] = &[
        spec("policy", Kind::Str),
        spec("unattended", Kind::Bool),
        spec("n", Kind::Int),
        spec("usd", Kind::Float),
        spec("context", Kind::Pair),
    ];

    fn args(a: &[&str]) -> Vec<String> {
        a.iter().map(|s| (*s).to_owned()).collect()
    }

    #[test]
    fn flag_spellings() {
        let p = parse(
            SPECS,
            &args(&[
                "-policy",
                "a",
                "--unattended",
                "-n=3",
                "--usd",
                "0.5",
                "--context",
                "k=v",
                "-context=x=y=z",
                "rest",
                "-policy",
            ]),
        )
        .unwrap();
        assert_eq!(p.str("policy"), "a");
        assert!(p.bool("unattended"));
        assert_eq!(p.int("n", 0), 3);
        assert_eq!(p.float("usd", 0.0), 0.5);
        assert_eq!(
            p.pairs("context"),
            [
                ("k".to_owned(), "v".to_owned()),
                ("x".to_owned(), "y=z".to_owned())
            ]
        );
        assert_eq!(p.rest, ["rest", "-policy"]);
    }

    #[test]
    fn bool_values_and_terminator() {
        let p = parse(SPECS, &args(&["-unattended=false", "--", "-policy"])).unwrap();
        assert!(!p.bool("unattended"));
        assert_eq!(p.rest, ["-policy"]);
        assert!(parse(SPECS, &args(&["-unattended=maybe"])).is_err());
        assert_eq!(p.int("n", 7), 7);
    }

    #[test]
    fn errors() {
        for bad in [
            vec!["--bogus"],
            vec!["-policy"],
            vec!["-n", "x"],
            vec!["-usd=1.2.3"],
            vec!["-context", "novalue"],
            vec!["-context", "=v"],
            vec!["---policy", "a"],
            vec!["-=x"],
        ] {
            assert!(
                matches!(parse(SPECS, &args(&bad)), Err(FlagError::Bad(_))),
                "{bad:?}"
            );
        }
        assert_eq!(parse(SPECS, &args(&["-h"])).unwrap_err(), FlagError::Help);
        assert_eq!(
            parse(SPECS, &args(&["--help"])).unwrap_err(),
            FlagError::Help
        );
        // A lone "-" is an argument, not a flag.
        assert_eq!(parse(SPECS, &args(&["-"])).unwrap().rest, ["-"]);
    }
}
