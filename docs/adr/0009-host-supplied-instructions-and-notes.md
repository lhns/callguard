# 0009 Host-supplied instructions and notes

Status: Accepted (2026-11-05). Builds on ADR 0006 (the judge's input).

## Context
Claude's classifier also reads CLAUDE.md, and the owner wants "if Claude does it, we also want it". Reading instruction files means discovery (which files, which directories), `@import` parsing and an approval flow for imports outside the project; Claude already does all three, and hosts such as Switchboard consolidate their own instructions. Instruction text is repo-written, so it is also a way to steer the judge. Notes (a host's remarks on an earlier tool result) have the same trust problem.

## Decision
- The request gains `instructions` (a string) and `notes` (`[{tool_use_id, text}]`), additive within `callguard/request/v1`. The engine does no discovery, no import parsing and no approvals: it takes the string the host consolidated.
- The judge gets them in the user message as unverified host context that never counts as user consent, never clears a block and never lowers a bar. Caps: the last 8 KiB of instructions, 2,000 characters of notes per call, and only for calls the judge sees. `llm.instructions: false` (system or user layer) turns instructions off.
- Claude Code's payload carries no instructions, so its hook bridge reuses Claude's own discovery: `callguard hook claude` handles `InstructionsLoaded`, which fires per loaded file (imports included, Claude's approvals applied), records the paths per session beside the decision log, and PreToolUse reads those files.
- Notes have no CLI verb: an agent running as the same user could call it.

## Consequences
- No import parser or approval code to keep in step with Claude, and no second opinion on which files count.
- Other harnesses get instructions only from their host.
- The Claude event is asynchronous, so the first calls of a session may run without instructions, and it does not fire when Claude reads `AGENTS.md` directly.
- A hostile instruction file can still reach the judge, but only as labelled data; the deterministic layers decide first and the judge cannot loosen them. The recorded paths are limited to absolute `.md` files without `..`, and the state directory is self-protected.
