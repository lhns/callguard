//! Built-in read-only commands (rule `read-only-command`): a shell call made
//! only of commands that read and print, on files inside the project.
//!
//! The call passes the same gate as an allow rule (`shell_gate`: nah and the
//! independent lexer agree on every command), with the table below in place of
//! rule matching. A command is in the table only with a list of the flags it
//! may carry; any other flag sends the call to the judge. That the program
//! itself only reads is what the table proves, so nah's gaps for code it cannot
//! read do not matter here.
//!
//! Where this is stricter than Claude Code: a path argument that leaves the
//! project (or its additional directories) goes to the judge, `..` and `~`
//! included, and so does a path that a deny or ask rule would stop a `Read` of
//! (`secret-read`). Claude's exclusions apply as well: `cd` elsewhere together
//! with `git`, network paths, and commands over 10,000 characters.

use super::{lexer, paths, shell_gate};
use crate::nah::NahResult;
use crate::rules::{Call, Env};

/// The longest command (in characters) that can be read-only.
const MAX_CHARS: usize = 10_000;

/// What a command's positional arguments are.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Args {
    /// Any text, no checks (`echo`).
    Free,
    /// Names that are not files (`which`).
    Names,
    /// None allowed (`pwd`, `git branch`).
    Nothing,
    /// Every one is a path.
    Paths,
    /// The first is a pattern unless `-e` gave one, the rest are paths (`grep`).
    PatternThenPaths,
    /// Revisions and paths mixed (`git`): those that look like a path are checked.
    Mixed,
    /// Start paths up to the first `-` word, then the predicates of [`FIND`].
    Find,
}

struct Cmd {
    prog: &'static str,
    /// The git subcommand, "" for other programs.
    sub: &'static str,
    /// Short flags without a value; they may be combined (`-la`).
    short: &'static str,
    /// Short flags with a value, joined (`-n5`) or as the next word.
    short_val: &'static str,
    /// `-5` for `-n 5`.
    digits: bool,
    /// Long flags without a value.
    long: &'static [&'static str],
    /// Long flags written `--name=value`.
    long_val: &'static [&'static str],
    args: Args,
}

const NONE: &[&str] = &[];

const fn cmd(prog: &'static str, sub: &'static str, args: Args) -> Cmd {
    Cmd {
        prog,
        sub,
        short: "",
        short_val: "",
        digits: false,
        long: NONE,
        long_val: NONE,
        args,
    }
}

/// The diff options `git diff`, `git show` and `git log -p` share.
const GIT_DIFF_LONG: &[&str] = &[
    "stat",
    "shortstat",
    "numstat",
    "name-only",
    "name-status",
    "patch",
    "no-patch",
    "no-color",
    "color",
    "summary",
    "ignore-all-space",
    "ignore-space-change",
    "no-ext-diff",
    "no-textconv",
    "word-diff",
    "minimal",
    "patience",
    "histogram",
    "raw",
    "compact-summary",
];
const GIT_DIFF_VAL: &[&str] = &[
    "unified",
    "stat",
    "word-diff",
    "diff-filter",
    "color",
    "abbrev",
];

const TABLE: &[Cmd] = &[
    Cmd {
        short: "alhFrtSR1dAp",
        long: &[
            "all",
            "almost-all",
            "human-readable",
            "classify",
            "reverse",
            "recursive",
            "directory",
            "group-directories-first",
            "full-time",
            "color",
        ],
        long_val: &["color", "sort", "time-style"],
        ..cmd("ls", "", Args::Paths)
    },
    Cmd {
        short: "nbsETvA",
        long: &[
            "number",
            "number-nonblank",
            "squeeze-blank",
            "show-all",
            "show-ends",
            "show-tabs",
            "show-nonprinting",
        ],
        ..cmd("cat", "", Args::Paths)
    },
    cmd("echo", "", Args::Free),
    Cmd {
        short: "LP",
        ..cmd("pwd", "", Args::Nothing)
    },
    Cmd {
        short: "qv",
        short_val: "nc",
        digits: true,
        long: &["quiet", "silent", "verbose"],
        long_val: &["lines", "bytes"],
        ..cmd("head", "", Args::Paths)
    },
    // Never `-f`, `-F`, `--follow`, `--pid`: they do not stop.
    Cmd {
        short: "qv",
        short_val: "nc",
        digits: true,
        long: &["quiet", "silent", "verbose"],
        long_val: &["lines", "bytes"],
        ..cmd("tail", "", Args::Paths)
    },
    // Never `-R` (follows links out of the project), `-f` (patterns from a
    // file), `-P`, `--exclude-from`.
    Cmd {
        short: "rnilLEFvcwxsqhHoIa",
        short_val: "eABCm",
        long: &[
            "recursive",
            "line-number",
            "ignore-case",
            "no-ignore-case",
            "files-with-matches",
            "files-without-match",
            "extended-regexp",
            "fixed-strings",
            "invert-match",
            "count",
            "word-regexp",
            "line-regexp",
            "no-messages",
            "quiet",
            "no-filename",
            "with-filename",
            "only-matching",
            "text",
        ],
        long_val: &[
            "regexp",
            "max-count",
            "after-context",
            "before-context",
            "context",
            "include",
            "exclude",
            "exclude-dir",
            "color",
            "colour",
            "binary-files",
        ],
        ..cmd("grep", "", Args::PatternThenPaths)
    },
    cmd("find", "", Args::Find),
    Cmd {
        short: "lwcmL",
        long: &["lines", "words", "bytes", "chars", "max-line-length"],
        ..cmd("wc", "", Args::Paths)
    },
    Cmd {
        short: "a",
        long: &["all"],
        ..cmd("which", "", Args::Names)
    },
    Cmd {
        short: "uqrsiwbBcy",
        short_val: "UC",
        long: &[
            "brief",
            "recursive",
            "ignore-case",
            "ignore-all-space",
            "ignore-space-change",
            "ignore-blank-lines",
            "report-identical-files",
            "side-by-side",
            "text",
            "minimal",
        ],
        long_val: &["unified", "context", "color"],
        ..cmd("diff", "", Args::Paths)
    },
    Cmd {
        short: "Lt",
        short_val: "c",
        long: &["dereference", "terse"],
        long_val: &["format", "printf"],
        ..cmd("stat", "", Args::Paths)
    },
    Cmd {
        short: "ashckmbx",
        short_val: "d",
        long: &[
            "all",
            "summarize",
            "human-readable",
            "total",
            "apparent-size",
            "one-file-system",
        ],
        long_val: &["max-depth"],
        ..cmd("du", "", Args::Paths)
    },
    // `git branch`: listing only. A name creates a branch, so none is allowed.
    Cmd {
        short: "arv",
        long: &[
            "all",
            "remotes",
            "verbose",
            "list",
            "show-current",
            "no-color",
        ],
        ..cmd("git", "branch", Args::Nothing)
    },
    Cmd {
        short: "sb",
        long: &[
            "short",
            "branch",
            "porcelain",
            "long",
            "ignored",
            "no-renames",
        ],
        long_val: &["porcelain", "untracked-files", "ignored"],
        ..cmd("git", "status", Args::Mixed)
    },
    Cmd {
        short: "pi",
        short_val: "n",
        digits: true,
        long: &[
            "oneline",
            "graph",
            "decorate",
            "no-decorate",
            "abbrev-commit",
            "no-abbrev-commit",
            "all",
            "branches",
            "tags",
            "remotes",
            "no-merges",
            "merges",
            "first-parent",
            "reverse",
            "topo-order",
            "date-order",
            "author-date-order",
            "follow",
            "left-right",
            "full-history",
            "simplify-by-decoration",
            "relative-date",
        ],
        long_val: &[
            "format",
            "pretty",
            "date",
            "max-count",
            "skip",
            "author",
            "committer",
            "grep",
            "since",
            "until",
            "after",
            "before",
        ],
        ..cmd("git", "log", Args::Mixed)
    },
    Cmd {
        short: "pwb",
        short_val: "U",
        long: &["cached", "staged", "quiet", "exit-code", "check"],
        ..cmd("git", "diff", Args::Mixed)
    },
    Cmd {
        short: "ps",
        long: &["oneline", "abbrev-commit", "no-abbrev-commit"],
        long_val: &["format", "pretty", "date"],
        ..cmd("git", "show", Args::Mixed)
    },
    Cmd {
        short: "q",
        long: &[
            "show-toplevel",
            "show-prefix",
            "show-cdup",
            "is-inside-work-tree",
            "is-inside-git-dir",
            "is-bare-repository",
            "verify",
            "quiet",
            "abbrev-ref",
            "short",
            "symbolic-full-name",
            "absolute-git-dir",
            "git-dir",
            "git-common-dir",
        ],
        long_val: &["abbrev-ref", "short"],
        ..cmd("git", "rev-parse", Args::Mixed)
    },
    Cmd {
        short: "cdmosuzi",
        long: &[
            "cached",
            "deleted",
            "modified",
            "others",
            "stage",
            "unmerged",
            "ignored",
            "exclude-standard",
            "full-name",
            "directory",
            "no-empty-directory",
            "deduplicate",
            "error-unmatch",
        ],
        ..cmd("git", "ls-files", Args::Mixed)
    },
    Cmd {
        short: "wlsep",
        short_val: "L",
        long: &[
            "porcelain",
            "line-porcelain",
            "incremental",
            "show-email",
            "show-name",
            "show-number",
        ],
        ..cmd("git", "blame", Args::Mixed)
    },
];

/// The git options that `git diff`, `git show` and `git log -p` share, added to
/// the table's own for those three subcommands.
fn git_diff_option(c: &Cmd, name: &str, valued: bool) -> bool {
    c.prog == "git"
        && matches!(c.sub, "diff" | "show" | "log")
        && if valued {
            GIT_DIFF_VAL.contains(&name)
        } else {
            GIT_DIFF_LONG.contains(&name)
        }
}

/// Find predicates that take no value, and those that take one. Not `-exec`,
/// `-execdir`, `-ok`, `-okdir`, `-delete`, `-fprint`, `-fprintf`, `-fprint0`,
/// `-fls`, `-files0-from`, `-newer` (a path) or `-L`.
const FIND: &[&str] = &[
    "-print",
    "-print0",
    "-empty",
    "-a",
    "-o",
    "-not",
    "-prune",
    "-depth",
    "-readable",
    "-writable",
    "-executable",
];
const FIND_VAL: &[&str] = &[
    "-name",
    "-iname",
    "-path",
    "-ipath",
    "-type",
    "-maxdepth",
    "-mindepth",
    "-size",
    "-mtime",
    "-mmin",
    "-perm",
];

/// The words after the program, split into options and positionals. None if an
/// option is not on the command's list.
struct Parsed<'a> {
    pos: Vec<&'a str>,
    /// The options that carried a value: `e` for `-e`, `regexp` for `--regexp=`.
    valued: Vec<String>,
}

fn parse<'a>(c: &Cmd, args: &'a [String]) -> Option<Parsed<'a>> {
    let mut out = Parsed {
        pos: Vec::new(),
        valued: Vec::new(),
    };
    let mut i = 0;
    while i < args.len() {
        let a = args[i].as_str();
        i += 1;
        if a == "--" {
            out.pos.extend(args[i..].iter().map(String::as_str));
            break;
        }
        if let Some(long) = a.strip_prefix("--") {
            let (name, value) = match long.split_once('=') {
                Some((n, v)) => (n, Some(v)),
                None => (long, None),
            };
            let ok = if value.is_some() {
                c.long_val.contains(&name) || git_diff_option(c, name, true)
            } else {
                c.long.contains(&name) || git_diff_option(c, name, false)
            };
            if !ok {
                return None;
            }
            if value.is_some() {
                out.valued.push(name.to_owned());
            }
        } else if let Some(body) = a.strip_prefix('-').filter(|b| !b.is_empty()) {
            if c.digits && body.bytes().all(|b| b.is_ascii_digit()) {
                continue;
            }
            for (j, ch) in body.char_indices() {
                if c.short.contains(ch) {
                    continue;
                }
                if !c.short_val.contains(ch) {
                    return None;
                }
                out.valued.push(ch.to_string());
                if body[j + ch.len_utf8()..].is_empty() {
                    args.get(i)?; // the value is the next word
                    i += 1;
                }
                break;
            }
        } else {
            out.pos.push(a); // `-` alone is stdin
        }
    }
    Some(out)
}

/// What the checks of one call share.
struct Cx<'a> {
    env: &'a Env,
    call: &'a Call,
    /// The directories a relative path may start from: the working directory
    /// and every `cd` target of the command.
    bases: Vec<String>,
    cwd_inside: bool,
    /// Whether a deny or ask rule would stop a `Read` of this normalized path.
    flagged: &'a dyn Fn(&str) -> bool,
}

impl Cx<'_> {
    /// Whether `arg` names something inside the project, by its name and by
    /// where it really is, from every base.
    fn inside(&self, arg: &str) -> bool {
        let env = self.env;
        if arg.is_empty()
            || arg.starts_with('~')
            // `rev:../x` names a path after the colon.
            || arg.split(['/', '\\', ':']).any(|part| part == "..")
            || paths::is_network(env, arg)
            || env.drive_relative(arg)
        {
            return false;
        }
        self.bases.iter().all(|base| {
            let p = env.clean_names(&env.normalize(arg, base));
            env.is_abs(&p)
                && self.call.roots.contains(env, &p)
                && env
                    .real(&p)
                    .is_some_and(|r| self.call.roots.contains_real(env, &r))
                && !(self.flagged)(&p)
        })
    }

    fn command(&self, argv: &[String]) -> bool {
        let Some(prog) = argv.first() else {
            return false;
        };
        if argv.iter().any(|a| paths::is_network(self.env, a)) {
            return false;
        }
        let args = &argv[1..];
        if prog == "cd" {
            return args.len() == 1 && !args[0].starts_with('-') && self.inside(&args[0]);
        }
        let (c, rest) = if prog == "git" {
            let Some(sub) = args.first() else {
                return false;
            };
            let Some(c) = TABLE.iter().find(|c| c.prog == "git" && c.sub == sub) else {
                return false;
            };
            (c, &args[1..])
        } else {
            let Some(c) = TABLE.iter().find(|c| c.prog == prog && c.sub.is_empty()) else {
                return false;
            };
            (c, args)
        };
        // Only `echo`, `pwd` and `which` leave the working directory alone.
        let touches_files =
            !matches!(c.args, Args::Free | Args::Names | Args::Nothing) || c.prog == "git";
        if touches_files && !self.cwd_inside {
            return false;
        }
        match c.args {
            Args::Free => true,
            Args::Find => self.find(rest),
            _ => {
                let Some(p) = parse(c, rest) else {
                    return false;
                };
                match c.args {
                    Args::Names => true,
                    Args::Nothing => p.pos.is_empty(),
                    Args::Paths => p.pos.iter().all(|a| *a == "-" || self.inside(a)),
                    Args::PatternThenPaths => {
                        let given = p.valued.iter().any(|v| v == "e" || v == "regexp");
                        p.pos
                            .iter()
                            .skip(usize::from(!given))
                            .all(|a| *a == "-" || self.inside(a))
                    }
                    Args::Mixed => p.pos.iter().all(|a| !looks_like_path(a) || self.inside(a)),
                    Args::Free | Args::Find => unreachable!("handled above"),
                }
            }
        }
    }

    fn find(&self, args: &[String]) -> bool {
        let starts = args.iter().take_while(|a| !a.starts_with('-')).count();
        if !args[..starts].iter().all(|a| self.inside(a)) {
            return false;
        }
        let mut rest = args[starts..].iter();
        while let Some(a) = rest.next() {
            if FIND_VAL.contains(&a.as_str()) {
                if rest.next().is_none() {
                    return false;
                }
            } else if !FIND.contains(&a.as_str()) {
                return false;
            }
        }
        true
    }
}

/// Whether a `git` word may be a file or directory rather than a revision or
/// an option value: it has a separator or starts like a path.
fn looks_like_path(a: &str) -> bool {
    let b = a.as_bytes();
    a.contains(['/', '\\']) || a.starts_with(['.', '~']) || (b.len() >= 2 && b[1] == b':')
}

/// Whether the shell call is made only of read-only commands on files inside
/// the project. `flagged` says whether a deny or ask rule would stop a `Read`
/// of a normalized path.
pub(crate) fn read_only(
    env: &Env,
    call: &Call,
    nah: Option<&NahResult>,
    flagged: &dyn Fn(&str) -> bool,
) -> bool {
    if call.raw_commands.len() != 1
        || call.raw_commands[0].chars().count() > MAX_CHARS
        || call.cwd.is_empty()
    {
        return false;
    }
    let Some(segs) = lexer::split(&call.raw_commands[0]) else {
        return false;
    };
    let cwd = env.clean_names(&env.normalize(&call.cwd, ""));
    let mut bases = vec![cwd.clone()];
    let (mut elsewhere, mut git) = (false, false);
    for seg in &segs {
        match seg[0].as_str() {
            "cd" => {
                if let Some(target) = seg.get(1) {
                    let last = bases.last().map_or("", String::as_str);
                    let dir = env.clean_names(&env.normalize(target, last));
                    elsewhere |= env.fold(&dir) != env.fold(&cwd);
                    bases.push(dir);
                }
            }
            "git" => git = true,
            _ => {}
        }
    }
    // Claude's exclusion: the repository may differ from the one `git` was
    // started in.
    if elsewhere && git {
        return false;
    }
    let cwd_inside = call.roots.contains(env, &cwd)
        && env
            .real(&cwd)
            .is_some_and(|r| call.roots.contains_real(env, &r));
    let cx = Cx {
        env,
        call,
        bases,
        cwd_inside,
        flagged,
    };
    shell_gate(env, call, nah, |argv| cx.command(argv).then_some(())).is_some()
}
