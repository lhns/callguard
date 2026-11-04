# 0006 Judge v2: assistant prose as referent only, host-computed meta lines, adapted auto-mode prompt

Status: Accepted (2026-11-03). Supersedes the input part of ADR 0005.

## Context
ADR 0005 kept all assistant text away from the judge. That makes consent unreadable: a user's "yes" only means something next to the proposal it answers, so a reasoning-blind judge either over-asks or reads a bare "yes" as approval of anything. A published prompt that presents itself as Claude Code's auto-mode classifier prompt shows a workable middle ground: assistant prose appears only as the referent of a user reply, never as consent, and the harness adds trusted facts (git status, repo visibility, call outcomes) as structured lines. The owner decided to adopt that prompt, adapted, including its text.

## Decision
- The judge prompt is `crates/callguard/assets/prompt.md`, adapted from github.com/collinzrj/claude-code-auto-safeguard-prompt, with a provenance note. HARD rules map to `deny`, SOFT rules to `ask`, everything else to `allow`; each rule has a stable id the verdict names.
- The judge input is a JSONL transcript with single-key lines: `user`, `assistant`, `call`, `outcome`, `meta`, and the pending `action` last, all produced by `json.Marshal`.
- Assistant text is included only as the referent of a following user message: the last assistant text before a user reply, with no third-party message in between. Assistant text after the last user message (the agent's narration of the pending action) is never included. Assistant entries are never consent.
- Tool results stay excluded. Only their harness-written status (`ok`, `error`, rejections, interrupts, denials) becomes an `outcome` line, mapped from fixed harness prefixes on error results.
- Meta lines (`gitStatus`, `repoVisibility`, `nah` facts, session) come only from callguard's own probes (≤300 ms in total, degrading to absent or `unknown`) or from host-set request fields (`meta`, `facts`), never from agent text. String values inside them are data.

## Consequences
- The agent can now put text in front of the judge through its prose. Mitigations: only prose a user replied to is shown, the prompt says it carries no intent, and every line is JSON-encoded so prose cannot imitate another line.
- The system prompt grows to roughly 19k tokens; it is a stable cached prefix, but latency and cost per uncached call rise. `llm.timeout_ms` may need raising for slower models.
- Outcome detection depends on Claude Code's undocumented error strings; unrecognised errors degrade to `error`.
- The source prompt's licence is unclear; the owner accepted that risk.
