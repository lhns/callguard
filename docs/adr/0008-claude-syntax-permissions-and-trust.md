# 0008 Claude-syntax permission rules, matched on nah's parse, and project trust

Status: Accepted (2026-11-04). Narrows ADR 0003: allow rules are no longer system-only.

## Context
Users know Claude Code's permission rules (`Bash(git push:*)`, `Read(~/.ssh/**)`). With nah linked (ADR 0007), callguard has a parse of every shell call, so rules can match on commands and arguments, not on joined text: `Bash(git push:*)` should see `bash -c 'git push'`. ADR 0003 let only the system layer allow things, because the agent's uid usually owns `~` and the repo. The owner wants it "similar" to Claude, where users and projects can allow.

## Decision
- Policy gains `permissions: {deny, ask, allow}` in Claude's syntax. Tool names map by kind across harnesses. The older regex `rules` remain, and the default rules stay regex rules with ids.
- Matching is on argv tokens. Deny and ask match if any command nah found matches, also behind wrappers nah sees through; with no parse or a hole in it, they also try the raw text. An allow needs full coverage, every command matching, and nah's parse and callguard's own lexer agreeing (nah's `commands` omit calls with unknown argv and hide assignments and redirects). An allow only skips the judge; it never overrides self-protection, nah or a deny.
- Every layer drops blanket and interpreter allows, package-manager run wildcards, `Agent`, `Task` and `Monitor` (Claude's auto mode drops the same). A deny or ask rule that cannot be read fails the policy.
- User-layer allows apply after that vetting. **Project-layer allows apply only after `callguard trust`**, run in a real terminal (no `--yes`, no environment override). Trust is a hash of the project path and the allow rules in order, stored per user and self-protected, so a changed rule must be approved again (stricter than Claude's workspace trust). After trust they get the user layer's vetting.
- A project's `llm.block` is ignored with a warning: it is repo-written text in the judge's prompt. User and system entries stay.

## Consequences
- A cloned repo cannot pre-approve anything; at worst it adds asks and denies.
- Known gaps: a pty can satisfy the terminal check; shell guards do not read globs or variables; path rules cover tool calls, not what a shell command touches.
- Differences from Claude's matching are listed at the top of `crates/callguard/src/permissions.rs`.
