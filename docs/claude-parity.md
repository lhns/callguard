# callguard against Claude Code's permissions

Read on 2026-11-05 against callguard at 9c1b879. Sources: code.claude.com/docs/en/permissions (read 2026-11-05); for the classifier rows, permission-modes, auto-mode-config and hooks (read 2026-11-02, [design.md](design.md) §1). Claude changes these pages; recheck before relying on a row. The code comment at the top of `crates/callguard/src/permissions.rs` is the exact list of rule-matching differences.

Verdicts: **same** (behaves as Claude), **stricter** (callguard asks or denies where Claude allows), **looser** (callguard allows or skips a check where Claude prompts or blocks), **n/a** (no counterpart). callguard's `ask` is a hook `ask` in Claude, so a prompt there is a judge call or a human here.

## Rules

| Feature | Verdict | Why |
| --- | --- | --- |
| Precedence deny, ask, allow | same | The layers run builtin, nah, rules (deny > ask > allow), judge. An allow never beats a deny, nah or a built-in. |
| A hook `allow` cannot beat Claude's deny or ask | same | Claude enforces it; the bridge only emits `allow` when nothing above objected. |
| Bare tool and `Tool(specifier)` | same | Tool names map by kind across harnesses (`Bash` also covers `terminal`). |
| `Bash(prefix:*)`, `Bash(a * b)`, exact | same | `:*` and a trailing ` *` also match the bare command. Matching is on argv tokens, not text. |
| `Read`, `Edit` path rules and anchors (`//`, `~/`, `/`, `./`) | stricter | `/x` anchors at the project in every layer (Claude: at the settings source). `Write`, `NotebookEdit`, `MultiEdit` mean `Edit`, `Grep`, `Glob`, `LS` mean `Read` (Claude accepts them and never matches). |
| `{a,b}` alternatives | stricter | Unsupported; such a rule cannot be read and a deny or ask fails the policy. |
| `WebFetch(domain:...)` | same | Case-insensitive, `*` wildcards, a trailing dot ignored. Allow takes only the plain `https://host/` shape; deny and ask test every host a tricky URL could mean. |
| `mcp__server__tool` and globs | same | |
| `Agent(name)` | same | deny and ask on `subagent_type`. An `Agent` allow is dropped (auto mode drops it too). |
| `Skill(name)`, `Skill(skill:x)` | looser | Compared with the literal input; Claude's deny also matches a skill under its alias or display name, which callguard does not know. |
| `Tool(param:value)` | same | Deny and ask, top-level scalar, `*` wildcard, an omitted parameter never matches. A primary field makes the policy fail where Claude warns and ignores it. Shell, path and WebFetch tools take only known parameters, so `Bash(git:status)` stays a command. |
| `!` negation | same | Same limits as Claude (listed first, anchored, inside a blocked directory). Joined within its own layer, so a project `!` cannot cancel a system rule. |
| `PowerShell(...)` deny and ask | same | Aliases canonicalized, case ignored; matched on the raw text (nah has no PowerShell parse). |
| `PowerShell(...)` allow | stricter | Refused in every layer: there is no second parser to agree with the lexer. |
| `Cd(...)`, permission modes, sandboxing, `requiresUserInteraction`, connectors | n/a | Claude product features; callguard sits in a hook. |
| Unreadable rule | stricter | A deny or ask rule that cannot be read fails the policy; Claude skips it. |

## Bash

| Feature | Verdict | Why |
| --- | --- | --- |
| Wrappers in deny and ask rules | stricter | They see through every wrapper nah knows, `bash -c` and `find -exec` too, so `/bin/rm`, `sh -c 'rm ...'` and `git -C . push` are stopped, which Claude's rules do not do. |
| Wrappers in allow rules | stricter | An allow never looks through a wrapper (`timeout`, `nice`, `xargs`), an assignment or `cd x &&`: the call goes to the judge. |
| Compound commands | same | `&&`, `||`, `;`, `|`, `&` and newlines: deny and ask match any part, allow needs every part. A dangling `&&` is unparseable and allows nothing. |
| Script runners (`npm test`, `pytest`) | same | An exact allow runs without a look inside; partial coverage passes only for a short list of "runs repository code" gaps, and nah's block still wins. |
| Env-var assignments before a command | stricter | Claude strips known-safe ones for allow; callguard sends any assignment to the judge. |
| Read-only commands | stricter | Built-in table with flag allowlists (rule `read-only-command`), the same exclusions as Claude (`cd` elsewhere with `git`, UNC paths, over 10,000 characters). A path outside the project and additional directories, `..` and `~` go to the judge; unquoted globs are refused. A deny or ask rule on a file keeps its read-only reader away. |
| Redirect and `tee` targets | looser | Claude checks `> file` and `tee` targets against `Edit` rules, protected paths and working directories. callguard's path rules cover tool calls only, so a deny rule for a file does not stop `echo x > file` (nah's guards and the secret-read rule cover common cases). An allow rule never matches a call with a redirect, so the target goes to the judge. |
| `Read` deny rules on `cat`, `sed`, `head`, `tail` | looser | Claude applies them to those commands; callguard's path rules cover tool calls, not what a shell command reads. The default `secret-read-shell` rule and nah cover common secret locations. |
| `rm` of a critical target | same | `rm-critical` asks a human for the root, its direct children, home, drive roots, the working directory and their parents, and unknowable targets such as `"$DIR"/*`; no allow rule or judge passes it. |
| Windows 8.3 short names (`USERNA~1`) | looser | Not expanded, so `rm -rf USERNA~1` is not recognised as home. |
| Makefile and script recipes | same (blind) | Neither sees what a script or recipe runs. |

## Paths and directories

| Feature | Verdict | Why |
| --- | --- | --- |
| Protected paths | same | One list (`.git`, `.config/git`, `.vscode`, `.idea`, `.husky`, `.claude`, shell start-up files, `.mcp.json`, ...): writes go to the judge in the default rules, and allow rules and wildcards cannot reach them. callguard adds `.callguard`, `.opencode`, `.pi`, `.hermes`. |
| Symlinks | same | Allow needs the requested path and its target to match; deny and ask match either. A carved path is stopped when its target is not carved. |
| Additional directories | same | `permissions.additionalDirectories`, `additional_dirs` in the request, `--add-dir`. Home, roots and network paths are refused. A project's entries need `callguard trust`, as Claude's need the workspace trust dialog. |
| Reads inside the working directories | same | Rule `read-in-project`. |
| First read outside the working directories | looser | Claude prompts; callguard sends it to the judge, which may allow it. |
| Network paths (UNC, `/net`) | looser | Claude prompts even with an allow rule or a hook `allow`. callguard's read-only commands and allow rules refuse UNC paths, so they reach the judge, which may allow. Not special-cased in file tools. |
| Preapproved documentation sites | same | Rule `docs-fetch` with callguard's own list of about 30 hosts, not Claude's; turned off with the default rules. |

## Trust and dropped rules

| Feature | Verdict | Why |
| --- | --- | --- |
| Project allow rules and directories need trust | stricter | `callguard trust` in a real terminal, tied to a hash of the project path, the rules and the directories; a changed rule needs approval again. Deny and ask apply at once, as in Claude. |
| Dropped allows (`Bash(*)`, interpreters, `npm run *`, `Agent`, `Monitor`) | same | Dropped with a warning in every layer, as auto mode does. callguard also drops allows of protected paths in the user and project layers, and PowerShell allows. |
| User and project layers can only tighten | stricter | Claude's layers add allows freely; callguard accepts only `permissions.allow` after vetting. |

## Judge and classifier

| Feature | Verdict | Why |
| --- | --- | --- |
| Reasoning-blind input, user messages and tool calls only | same | Plus the assistant text a user replied to (ADR 0006), and no tool results. |
| CLAUDE.md as input | same on Claude Code | Through `InstructionsLoaded` (ADR 0009): Claude's own discovery and approvals, unverified context for the judge. Asynchronous, so the first calls may miss it; not sent when Claude reads `AGENTS.md` directly. Other harnesses: only from their host. |
| `git status` before commands that discard work | same | A `gitStatus` meta line, also for `git add`, `commit` and `push`. |
| `classifierContext` from PostToolUse | looser | Not read. The `notes` request field is the host-side counterpart and has no CLI verb (ADR 0009). |
| Failure blocks, never allows | same | A fallback verdict is `ask`, or `deny` when unattended. |
| Repeated-block fallback (3 in a row, 20 total) | same when set | `deny_streak` escalates judge denies to `ask` for interactive sessions; off by default and system-layer only. |
| Subagent checks | same | The hook runs on a subagent's calls like any other, and `PostToolUse` on `Agent|Task` reviews the report (advisory: a warning in the parent's context, skipped in auto mode unless `--review-in-auto`). Both warn and never block. |
| Read-only lookups sent to the classifier | stricter | The judge sees every call the deterministic layers leave to it. |

## Still looser or missing

- Network-path reads and the first read outside the working directories go to the judge where Claude prompts.
- Windows 8.3 short names are not expanded.
- `cd sub && ls` goes to the judge: nah gives no argv for `cd`, so the read-only gate cannot agree.
- PowerShell allow rules are refused: nah has no PowerShell analysis.
- Redirect and `tee` targets and `cat`/`sed`/`head` reads are not checked against path rules.
- `Skill(...)` deny rules do not know a skill's aliases.
- `classifierContext` annotations are not read.
- Makefile and script recipes are not seen (the same as Claude).
