# callguard

callguard decides whether one pending coding-agent tool call may run without a human prompt. It answers `allow`, `ask` or `deny`, with a reason, the layer and rule that decided, and a confidence. It works as a peer of Claude Code's auto-mode classifier for any harness, through hook adapters for Claude Code, Hermes, opencode and pi.

**callguard is built on [nah](https://github.com/manuelschipper/nah)**, Manuel Schipper's deterministic guard against catastrophic agent actions (MIT). nah's engine is compiled into the binary and analyses every call: it follows `bash -c`, `xargs` and pipelines, works out what a command would really do to files and the network, and blocks the dangerous ones. callguard adds what sits around it: self-protection, policy rules in Claude Code's syntax, an LLM judge for what nah leaves open, and adapters for each harness.

## How it decides

The layers run in order, and the first that decides wins:

1. **Built-in rules**: hard denies and self-protection of callguard's own files.
2. **nah**: blocks what its analysis shows is dangerous, and hands the parse to the later layers. A call it cannot analyse can never match an allow rule.
3. **Policy rules**: regex rules and rules in Claude Code's permission syntax.
4. **LLM judge** (optional): decides what is left. It sees user messages, tool calls and how they ended, the agent's prose only where the user replied to it, and facts callguard computes itself (git status, repo visibility, nah's parse). It never sees tool output.

Any error becomes `ask`, or `deny` when nobody can answer a prompt. callguard never fails open.

The judge's prompt is adapted from a [published version](https://github.com/collinzrj/claude-code-auto-safeguard-prompt) of Claude Code's auto-mode classifier prompt (the source presents itself as that prompt; see [design §7](docs/design.md)).

More: [design](docs/design.md), [comparison with Claude Code's permissions](docs/claude-parity.md), [decisions](docs/adr).

## Install

Download the archive for your system from the [releases](https://github.com/lhns/callguard/releases) (Linux musl x64 and arm64, macOS x64 and arm64, Windows x64), check it against `SHA256SUMS`, and put `callguard` on your `PATH`. Each archive carries the licence and the third-party notices.

Or build from source with the Rust toolchain named in `rust-toolchain.toml` (rustup installs it on first use):

```sh
git clone https://github.com/lhns/callguard && cd callguard
cargo build --profile dist -p callguard-cli    # target/dist/callguard
```

The first build compiles nah and takes a long time: tens of minutes on a small machine, and several GB of memory during the final link with `dist`'s fat LTO (plain `--release` links faster). nah comes from [`lhns/nah`](https://github.com/lhns/nah), a fork of nah v1.7.0 that adds an analysis budget, so the build needs network access to GitHub. Set `CALLGUARD_VERSION=1.2.3` while building to have `callguard version` print it.

## Try it without enforcing anything

Set `"mode": "shadow"` in the policy to run every layer and only log. A shadowed verdict has `enforced: false`, and the harness behaves as without callguard, while the [decision log](#decision-log) records what callguard would have done. Without `mode`, rules and nah are enforced and only the judge starts in shadow.

```json
{
  "policy_version": 1,
  "mode": "shadow",
  "llm": {"enabled": true, "backend": "anthropic", "timeout_ms": 9000},
  "backends": {
    "anthropic": {"type": "anthropic", "model": "claude-haiku-5-5", "api_key_env": "CALLGUARD_ANTHROPIC_API_KEY",
                  "data_classes": ["open", "private"]}
  },
  "log": {"include_input": true}
}
```

Give the key its own variable, as here: with Claude Code, setting `ANTHROPIC_API_KEY` in the environment can change which key Claude Code itself uses. `include_input` stores commands as plain text in the log. Without a key, calls that would reach the judge are logged as fallbacks.

## Harness setup

All hook commands take the same flags:

| Flag | Meaning |
| --- | --- |
| `--policy PATH` | system policy file (default `/etc/callguard/policy.json`, `%ProgramData%\callguard\policy.json`) |
| `--no-user-policy` | skip the user policy layer |
| `--log PATH` | decision log path, `-` disables it |
| `--unattended` | nobody can answer a prompt: `ask` becomes `deny` |
| `--context key=value` | request context entry, repeatable (for example `trust=tainted`, `data_class=private`) |
| `--context-file PATH` | JSON object of strings merged into the context. **The file must be root-owned**: a file the agent can write lets it label its own calls. A missing or invalid file gives an ask/deny verdict, never a silent skip |
| `--add-dir PATH` | a directory besides the project that counts as inside it, repeatable (`decide` takes it too); not the home directory or a root |
| `--allow-in-auto` | Claude only: also emit `allow` in `permission_mode: auto` |
| `--review-in-auto` | Claude only: also review sub-agent reports in `permission_mode: auto` |

| Harness | Status |
| --- | --- |
| Claude Code | verified against the hooks docs and real sessions (2.1.318) |
| Hermes | verified against current docs, not run against a live Hermes; Hermes 0.19 unverified |
| opencode 2.x | unverified, untested (shape from docs and nah's adapter) |
| pi | untested (shape from the pi extension docs) |
| opencode 1.x | unsupported |

### Claude Code

In `~/.claude/settings.json` or managed settings. Only `PreToolUse` is required; the other two events are optional and run the same command:

```json
{"hooks":{
  "PreToolUse":[{"matcher":"*","hooks":[{"type":"command","command":"callguard hook claude --policy /etc/callguard/policy.json","timeout":15,"onFailure":"block"}]}],
  "InstructionsLoaded":[{"hooks":[{"type":"command","command":"callguard hook claude --policy /etc/callguard/policy.json","timeout":15}]}],
  "PostToolUse":[{"matcher":"Agent|Task","hooks":[{"type":"command","command":"callguard hook claude --policy /etc/callguard/policy.json","timeout":15}]}]
}}
```

- **`InstructionsLoaded`** gives the judge the instruction files Claude loads (CLAUDE.md, imports, rules), after Claude's own discovery and approvals. The judge gets the last 8 KiB as unverified context that never counts as user consent ([ADR 0009](docs/adr/0009-host-supplied-instructions-and-notes.md)). The event is asynchronous, so a session's first calls may run before any file is recorded, and it does not fire when Claude reads `AGENTS.md` directly.
- **`PostToolUse` on `Agent|Task`** has the judge read a sub-agent's final report as untrusted data. A flagged report, or one that could not be reviewed, adds a security warning to the parent's context; the review never blocks. It costs one judge call per report and needs the judge in `enforce` for the warning to appear. It is skipped in `permission_mode: auto`, where Claude reviews reports itself, unless you pass `--review-in-auto`.

How callguard's answers meet Claude's:

- A hook `allow` never overrides Claude's own deny or ask rules.
- In `permission_mode: auto` callguard emits nothing on `allow`, so Claude's classifier still runs; `--allow-in-auto` changes that.
- For `AskUserQuestion` and `ExitPlanMode` an `allow` is also dropped (they need `updatedInput`); `ask` and `deny` still apply.
- `permission_mode: dontAsk` counts as unattended.
- The hook exits 0 with a JSON decision, or 2 with the reason on stderr. Claude runs the tool after any other non-zero exit, so callguard never uses one: a usage error in the hook command (unknown harness, bad flag) or a mistyped verb also exits 2. Keep `onFailure: "block"` so a timeout blocks too; leave it out only while trying callguard in shadow mode.

### Hermes

`config.yaml`:

```yaml
hooks:
  pre_tool_call:
    - command: "callguard hook hermes --policy /etc/callguard/policy.json"
      timeout: 15
      fail_closed: true
```

Hermes asks for consent before it runs a new shell hook: approve it once (`~/.hermes/shell-hooks-allowlist.json`) or start with `--accept-hooks`. `ask` becomes Hermes' own approval prompt (`{"action":"approve"}`), `deny` becomes `{"action":"block"}` with exit 2.

### opencode and pi

```sh
callguard plugin opencode > ~/.config/opencode/plugins/callguard.js   # opencode 2.x
callguard plugin pi > ~/.pi/agent/extensions/callguard/index.js
```

The plugins run `callguard hook generic` (found via `CALLGUARD_BIN`, else `PATH`) and fail closed: a spawn error, a 12 s timeout, a non-zero exit or unparseable output blocks the call. opencode blocks on `ask` unless `CALLGUARD_OPENCODE_ASK=delegate`; pi asks through its confirm dialog and blocks without a UI. Policy flags for these are not exposed yet; point `callguard` at a wrapper script if you need `--policy`.

## Configuration

Policy is JSON (`"policy_version": 1`) in layers: built-in defaults, system (`--policy`), user (`<user config dir>/callguard/policy.json`), project (`<project>/.callguard/policy.json`). `callguard policy check` loads and lints them and reports dropped keys.

**User and project layers can only tighten.** They may add `deny` and `ask` rules, enable nah guards and raise `llm.min_confidence`; everything else in them is dropped with a warning. The user layer may also add `llm.block` entries and turn `llm.instructions` off. A project's `llm.block` is ignored, because it goes into the judge's prompt. The exception is `permissions.allow`, [below](#permission-rules). A system file with `"final": true` ignores the lower layers.

```json
{
  "policy_version": 1,
  "final": false,
  "mode": "enforce",
  "permissions": {
    "deny": ["Bash(git push:*)", "Read(~/.ssh/**)"],
    "ask": ["Bash(npm publish:*)"],
    "allow": ["Bash(git status)", "Edit(src/**)"]
  },
  "rules": [
    {"id": "no-prod-kubectl", "description": "kubectl against prod needs a human",
     "decision": "ask",
     "match": {"kind": ["shell"], "command": "\\bkubectl\\b.*--context[= ]prod"}}
  ],
  "llm": {
    "enabled": true, "mode": "shadow", "backend": "anthropic",
    "timeout_ms": 3000, "min_confidence": 0.7
  },
  "backends": {
    "anthropic": {"type": "anthropic", "model": "claude-haiku-5-5", "api_key_env": "ANTHROPIC_API_KEY",
                  "data_classes": ["open", "private"]}
  }
}
```

### nah

nah is part of the binary and always on (`nah.enabled: false` is for debugging). It runs in a child process with a 2 s analysis budget (`nah.budget_ms`), a 10 s hard kill (`nah.timeout_ms`) and a 512 MiB memory cap, so a crash or a hang in it cannot take callguard down. If it fails, rules still run but no allow can match, the judge is not asked, and the answer is the fail-safe one.

`nah.guards` switches nah's guards on or off (system layer; other layers can only switch them on). nah's own config files are not read.

### Default rules

Regex rules with ids, on the command, URL, path or a field, running after nah. `"defaults": false` removes them. The ones that allow:

- `read-in-project`: reads inside the project.
- `write-in-project`: writes inside the project, except protected directories and files such as `.git`, `.vscode`, `.husky`, `.bashrc` and `.mcp.json`, which go to the judge.
- `read-only-command`: `ls`, `cat`, `grep`, `git status` and so on, with a flag allowlist, on files inside the project.
- `docs-fetch`: WebFetch of about 30 documentation hosts over `https`.

One built-in matters here: **`rm-critical`** makes deleting a root, home, a drive, the working directory or a parent of it ask a human, whatever an allow rule or the judge says. Deny rules and nah's blocks still win.

### Permission rules

`permissions.deny`, `ask` and `allow` use Claude Code's syntax:

| Rule | Matches |
| --- | --- |
| `Bash(git push:*)` | a command prefix |
| `Bash(npm run build)` | an exact command |
| `Bash(git * main)` | a glob over words |
| `Read(~/.ssh/**)`, `Edit(src/**)` | paths: `//abs`, `~/`, `/project-relative`, `./cwd-relative` |
| `WebFetch(domain:example.com)` | a host |
| `mcp__server__tool`, or a bare tool name | that tool |

Deny and ask also take:

| Rule | Matches |
| --- | --- |
| `Agent(Explore)` | the subagent type |
| `Skill(name)` | the literal skill input |
| `Tool(param:value)` | a top-level scalar of the input, `*` allowed, such as `Bash(run_in_background:true)` |
| `PowerShell(...)` | aliases canonicalized, case ignored |
| `Read(!pattern)` after a path rule | carves paths out of the rules before it in the same layer; a project's `!` cannot touch a system or user rule |

`Bash` also covers a harness's own shell tool. Rules match nah's parse word by word, so `Bash(git push:*)` also catches `bash -c 'git push'` and `xargs`.

- **Deny and ask** match if any command of the call matches. One that cannot be read fails the policy (Claude skips it).
- **Allow** matches only if every command does and nah's parse and callguard's own lexer agree, so `git status; rm x` does not match `Bash(git status:*)`. It skips the judge, and never overrides a deny, nah or the built-in rules. Like Claude, an exact allow such as `Bash(npm test)` runs a command callguard cannot look into.
- **Dropped with a warning in every layer**: blanket and interpreter allows (`Bash(*)`, `Bash(python:*)`, ...), `npm run *`-style wildcards, `Agent`, `Monitor`, and PowerShell allows (nah has no PowerShell analysis).

[docs/claude-parity.md](docs/claude-parity.md) lists every difference from Claude's rules.

**`callguard trust`**: a project's `permissions.allow` rules and `permissions.additionalDirectories` do nothing until you run `callguard trust` in that project. It prints them and asks, and needs a real terminal (no `--yes`, no environment override). Trust is tied to a hash of the project path and the rules, so a changed rule or directory must be approved again. `callguard trust --list` and `--revoke` show and remove it. A project's deny and ask rules apply without trust, since they only tighten.

**Additional directories**: `permissions.additionalDirectories` (Claude's key), the request field `additional_dirs` and `--add-dir` make a directory count as inside the project for reads, writes and read-only commands. Protected names still apply there. The home directory, a root, a network path and (in a policy or request) a relative path are ignored with a warning.

### The judge

- **Modes**: `llm.mode` starts as `shadow`. Switch to `enforce` once the decision log and `callguard eval` justify it.
- **Verdicts** name the prompt rule that matched (`rule`, for example `git-destructive` or `data-exfiltration`). HARD rules deny; SOFT rules ask unless the user's own words (or a "yes" to the agent's proposal right before it) named the risky specifics.
- **Backends**: `anthropic` (default `claude-haiku-5-5`, exact model ids, `base_url` configurable), `openai` (any OpenAI-compatible server such as llama.cpp, vLLM, Ollama), `exec` (your own classifier command) and `fake` (tests). A request with `context.data_class` goes only to a backend that lists that class; otherwise the judge is skipped and the verdict falls back to ask/deny.
- **Input from the host**: a request may carry `instructions` (the host's consolidated CLAUDE.md-style text) and `notes` (`[{tool_use_id, text}]`, remarks on earlier results). The judge reads them as unverified context, at most the last 8 KiB and 2,000 characters per call. callguard discovers and parses nothing itself and has no CLI verb for notes ([ADR 0009](docs/adr/0009-host-supplied-instructions-and-notes.md)). `llm.instructions: false` (system or user layer) turns instructions off.
- **Eval**: `callguard eval --backend <name>` scores the labelled set (benign, overeager, exfiltration, tainted, injection, judge) per bucket. The `fake` backend runs offline but cannot judge the `judge` bucket. Against Claude, `ANTHROPIC_API_KEY=… callguard eval --backend anthropic --facts both` runs the set with and without nah's facts and reports precision, recall, false-positive rate and tokens per case; it stops at `--max-usd` (default 1).

### Unattended

When nobody can answer a prompt (`--unattended`, or Claude's `dontAsk` mode), `ask` becomes `deny` (`"unattended_ask": "deny"`, the default; only the system layer can set `"ask"`). Errors then deny too.

### Decision log

JSONL, default `<user state dir>/callguard/decisions.jsonl`. It stores an input hash, not arguments, transcript text or judge reasons, unless `log.include_input` is true.

## Fail-safe

Never `allow` on error. Bad input, a policy load error, a backend failure, a timeout or a panic in the hook yields an `ask` verdict, or `deny` when unattended, in the harness's native format. The overall deadline (`deadline_ms`, default 11000) sits below the harness timeouts. Raise the timeout of anything that runs the hook or `decide` (Switchboard's `judge.timeout`, a plugin's) to at least 12 s.

## Known limits

- **Shell guards read quotes and backslashes, not globs or variables.** The guards for callguard's own files (`trusted-*`, `$HOME/.c*/`) see the text after quotes are removed; a glob or an expansion that only the shell resolves is not seen.
- **`git $X push`**: a variable in place of the git subcommand is not recognised by rules that name `git push`; the call is left to the later layers (the judge, or an ask).
- **A pty can satisfy the terminal check of `callguard trust`.** An agent that can allocate a pseudo-terminal and type "yes" could trust its own project rules. The guard keeps the agent from writing the trust file and from running the verb directly (self-protection), but this is not a hard boundary. `callguard trust` cannot run under mintty on Windows.
- **Deep nesting**: nah follows `bash -c` three layers deep and gives up with partial coverage at four, and reads input nested past a limit not at all. The raw-text fallback still applies to deny and ask rules, an allow never matches, and unreadable input gets the fail-safe verdict.
- **Windows under heavy load** (a median call about 50 times slower) lost two `fs-project-root` blocks (PowerShell rows) in the load test. A walk of `C:\` or `/` can take up to 9 s idle and longer under load; the 10 s kill then gives the fail-safe verdict.
- **macOS caps memory by a watchdog**: `setrlimit` refuses it, so a thread in the nah child aborts it once it is past 512 MiB resident. The cap does not cover the processes the child starts, such as git.
- **Facts about git status need git 2.26 or newer** (`git config --show-scope`). With an older git the judge gets no `gitStatus`.
- **Policy regexes have a compile-size limit**, the default of the `regex` crate, so a huge counted repeat such as `\pL{1000}` is refused (a policy cannot make callguard spend time compiling).
- **Permission paths cover tool calls**, not what a shell command reads or writes. [docs/claude-parity.md](docs/claude-parity.md) has the details.

## Build and test

```sh
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --release --workspace --features callguard-cli/test-engines -- --include-ignored --test-threads=1
node adapters/selftest.mjs
```

The ignored tests run the real nah and need a release build to be fast. Four tests that walk the file system root are skipped by CI and run weekly (`slow.yml`): add `--skip` for them, as `ci.yml` does. `cargo test -p callguard-nah --test corpus_conformance -- --ignored` runs nah's own corpus through callguard's engine (about ten minutes). The first implementation of callguard is at tag `go-final`.

## License

Apache-2.0, see [LICENSE](LICENSE). The binary includes [nah](https://github.com/manuelschipper/nah) (MIT, Copyright (c) 2026 Manuel Schipper) and other crates. Their notices are in [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md), generated with `cargo about generate about.hbs -o THIRD-PARTY-NOTICES.md` (config in `about.toml`) and shipped in every release archive.
