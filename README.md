# callguard

callguard decides whether one pending coding-agent tool call may run without a human prompt: `allow`, `ask` or `deny`, with a reason, the layer and rule that decided, and a confidence. It is a peer of Claude Code's auto-mode classifier that works for any harness through hook adapters (Claude Code, Hermes, opencode, pi).

Layers run in order and the first that decides wins: built-in hard-deny and self-protection rules, nah (by Manuel Schipper, MIT; a deterministic shell and file guard, linked into the binary), policy rules (regex rules and rules in Claude Code's permission syntax), then an optional LLM judge. The judge sees user messages, tool calls and how they ended, the agent's prose only where the user replied to it, and facts callguard computes itself (git status, repo visibility, nah's parse), never tool output. Its prompt is adapted from a published version of Claude Code's auto-mode classifier prompt ([source](https://github.com/collinzrj/claude-code-auto-safeguard-prompt), which presents itself as that prompt; see [docs/design.md](docs/design.md) §7). Any error becomes `ask`, or `deny` when nobody can answer a prompt; callguard never fails open. Details: [docs/design.md](docs/design.md), decisions: [docs/adr](docs/adr).

## Install

Download the archive for your system from the [releases](https://github.com/lhns/callguard/releases) (Linux musl x64 and arm64, macOS x64 and arm64, Windows x64), check it against `SHA256SUMS`, and put `callguard` on your `PATH`. Each archive carries the licence and the third-party notices.

Or build from source with the Rust toolchain named in `rust-toolchain.toml` (rustup installs it on first use):

```sh
git clone https://github.com/lhns/callguard && cd callguard
cargo build --profile dist -p callguard-cli    # target/dist/callguard
```

The first build compiles nah and takes a long time (tens of minutes on a small machine, several GB of memory during the final link with `dist`'s fat LTO; plain `--release` links faster). nah is fetched from `github.com/lhns/nah` (a fork of nah v1.7.0 that adds an analysis budget), so the build needs network access to GitHub. Set `CALLGUARD_VERSION=1.2.3` while building to have `callguard version` print it.

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
| `--allow-in-auto` | Claude only, see below |

### Claude Code

`~/.claude/settings.json` (or managed settings):

```json
{"hooks":{"PreToolUse":[{"matcher":"*","hooks":[{"type":"command","command":"callguard hook claude --policy /etc/callguard/policy.json","timeout":15,"onFailure":"block"}]}]}}
```

- A hook `allow` never overrides Claude's own deny or ask rules.
- In `permission_mode: auto` callguard emits nothing on `allow`, so Claude's classifier still runs; `--allow-in-auto` changes that.
- For `AskUserQuestion` and `ExitPlanMode` an `allow` is also dropped (they need `updatedInput`); `ask` and `deny` still apply.
- `permission_mode: dontAsk` counts as unattended.
- Exit codes: the hook exits 0 with a JSON decision, or 2 with the reason on stderr. Claude runs the tool after any other non-zero exit, so callguard never uses one; a usage error in the hook command (unknown harness, bad flag) also exits 2. Keep `onFailure: "block"` so a timeout blocks too.

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

### Status

| Harness | Status |
| --- | --- |
| Claude Code | verified against the hooks docs |
| Hermes | verified against current docs, not run against a live Hermes; Hermes 0.19 unverified |
| opencode 2.x | unverified, untested (shape from docs and nah's adapter) |
| pi | untested (shape from the pi extension docs) |
| opencode 1.x | unsupported |

## Configuration

Policy is JSON (`"policy_version": 1`) in layers: built-in defaults, system (`--policy`), user (`<user config dir>/callguard/policy.json`), project (`<project>/.callguard/policy.json`). **User and project layers can only tighten**: they may add `deny`/`ask` rules, enable nah guards and raise `llm.min_confidence` (the user layer may also add `llm.block` entries; a project's are ignored, because they go into the judge's prompt); everything else in them is dropped with a warning. The exception is `permissions.allow`, below. A system file with `"final": true` ignores the lower layers.

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

- `callguard policy check` loads and lints the layers and reports dropped keys.
- **Rules** (`rules`) are regexes, with ids, on the command, URL, path or a field; the default rules are of this kind and run after nah.
- **Permission rules** (`permissions.deny`, `ask`, `allow`) use Claude Code's syntax: `Bash(git push:*)` (a command prefix), `Bash(npm run build)` (exact), `Bash(git * main)` (a glob over words), `Read(~/.ssh/**)`, `Edit(src/**)`, `WebFetch(domain:example.com)`, `mcp__server__tool`, or a bare tool name. Paths: `//abs`, `~/`, `/project-relative`, `./cwd-relative`. `Bash` also covers a harness's own shell tool. They match nah's parse word by word, so `Bash(git push:*)` also catches `bash -c 'git push'` and `xargs`. A deny or ask matches if any command of the call matches; an allow only if every command does and nah's parse and callguard's own lexer agree, so `git status; rm x` does not match `Bash(git status:*)`. An allow skips the judge; it never overrides a deny, nah or the built-in rules. Blanket and interpreter allows (`Bash(*)`, `Bash(python:*)`, ...), `npm run *`-style wildcards, `Agent` and `Monitor` are dropped with a warning in every layer.
- **`callguard trust`**: a project's `permissions.allow` rules do nothing until you run `callguard trust` in that project. It prints the rules and asks, and needs a real terminal (no `--yes`, no environment override). Trust is tied to a hash of the project path and the rules, so a changed rule must be approved again. `callguard trust --list` and `--revoke` show and remove it. Deny and ask rules from a project apply without trust, since they only tighten.
- **nah** is part of the binary and always on (`nah.enabled: false` is for debugging). It runs in a child process with a 2 s analysis budget (`nah.budget_ms`), a 10 s hard kill (`nah.timeout_ms`) and a 512 MiB memory cap. If it fails, rules still run but no allow can match, and the answer is the fail-safe one; the judge is not asked. `nah.guards` switches nah's guards on or off (system layer; other layers can only switch on). nah's own config files are not read.
- **Unattended**: when nobody can answer a prompt (`--unattended`, or Claude's `dontAsk` mode), `ask` becomes `deny` (`"unattended_ask": "deny"`, the default; only the system layer can set `"ask"`). Errors then deny too.
- **nah** is optional: with `"nah": {"enabled": true}` in the system policy, callguard runs `nah decide` after its built-in rules; without it callguard works alone.
- **Shadow mode**: rules are enforced while the LLM layer defaults to `shadow`. A shadowed verdict has `enforced: false` and the harness behaves as without callguard, while the decision log records what callguard would have done. A shadowed nah layer does not stop the pipeline: its would-be verdict is logged and the later layers decide. Switch `llm.mode` to `enforce` once the log and `callguard eval` justify it.
- **Decision log**: JSONL, default `<user state dir>/callguard/decisions.jsonl`. It stores an input hash, not arguments, transcript text or LLM reasons, unless `log.include_input` is true.
- **Eval**: `callguard eval --backend <name>` scores the labelled set (benign, overeager, exfiltration, tainted, injection, judge) per bucket; the `fake` backend runs offline but cannot judge the `judge` bucket. Against Claude: `ANTHROPIC_API_KEY=… callguard eval --backend anthropic --facts both` runs the set with and without nah's facts and reports precision, recall, false-positive rate and tokens per case for each; it stops at `--max-usd` (default 1).
- **Judge verdicts** name the prompt rule that matched (`rule`, for example `git-destructive` or `data-exfiltration`). HARD rules deny, SOFT rules ask unless the user's own words (or a "yes" to the agent's proposal right before it) named the risky specifics.
- **Backends**: `anthropic` (default `claude-haiku-5-5`, exact model ids, `base_url` configurable), `openai` (any OpenAI-compatible server such as llama.cpp, vLLM, Ollama), `exec` (your own classifier command) and `fake` (tests). A request with `context.data_class` goes only to a backend that lists that class; otherwise the LLM is skipped and the verdict falls back to ask/deny.

## Fail-safe

Never `allow` on error. Bad input, a policy load error, a backend failure, a timeout or a panic in the hook yields an `ask` verdict, or `deny` when unattended, in the harness's native format. The overall deadline (`deadline_ms`, default 11000) sits below the harness timeouts. Raise the timeout of anything that runs the hook or `decide` (Switchboard's `judge.timeout`, a plugin's) to at least 12 s.

## Known limits

- **Shell guards read quotes and backslashes, not globs or variables.** The guards for callguard's own files (`trusted-*`, `$HOME/.c*/`) see the text after quotes are removed; a glob or an expansion that only the shell resolves is not seen.
- **`git $X push`**: a variable in place of the git subcommand is not recognised by rules that name `git push`; the call is left to the later layers (the judge, or an ask).
- **A pty can satisfy the terminal check of `callguard trust`.** An agent that can allocate a pseudo-terminal and type "yes" could trust its own project rules. The guard keeps the agent from writing the trust file and from running the verb directly (self-protection), but this is not a hard boundary. `callguard trust` cannot run under mintty on Windows.
- **Deep nesting**: nah follows `bash -c` three layers deep and gives up with partial coverage at four, and reads input nested past a limit not at all. The raw-text fallback still applies to deny and ask rules, an allow never matches, and unreadable input gets the fail-safe verdict.
- **Windows under heavy load** (a median call about 50 times slower) lost two `fs-project-root` blocks (PowerShell rows) in the load test; a walk of `C:\` or `/` can take up to 9 s idle and longer under load, then the 10 s kill gives the fail-safe verdict.
- **macOS caps memory by a watchdog**: `setrlimit` refuses it, so a thread in the nah child aborts it once it is past 512 MiB resident. The cap does not cover the processes the child starts, such as git.
- **Permission paths cover tool calls**, not what a shell command reads or writes (the same as Claude Code).

## Build and test

```sh
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --release --workspace --features callguard-cli/test-engines -- --include-ignored --test-threads=1
node adapters/selftest.mjs
```

The ignored tests run the real nah; they need a release build to be fast. Four tests that walk the file system root are skipped by CI and run weekly (`slow.yml`): add `--skip` for them, as `ci.yml` does. `cargo test -p callguard-nah --test corpus_conformance -- --ignored` runs nah's own corpus through callguard's engine (about ten minutes). The first implementation of callguard is at tag `go-final`.

## License

Apache-2.0, see [LICENSE](LICENSE). The binary includes nah (MIT, Copyright (c) 2026 Manuel Schipper) and other crates; their notices are in [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md), generated with `cargo about generate about.hbs -o THIRD-PARTY-NOTICES.md` (config in `about.toml`) and shipped in every release archive. Five of those crates (`malachite*`, reached through nah) are LGPL-3.0-only; see the comment in `about.toml`.
