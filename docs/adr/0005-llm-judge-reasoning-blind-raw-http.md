# 0005 LLM judge: reasoning-blind input, fixed labels, raw HTTP backends

Status: Accepted (2026-11-02)

## Context
A model in the tool-call path is a target for prompt injection and a source of latency, cost and outages. Claude Code's auto mode shows a working shape: the classifier sees user messages and tool calls only, and blocks when it cannot decide.

## Decision
- The judge sees the pending call, user text messages and earlier tool calls, host `context` and the policy's prose slots. It never sees assistant text or tool results.
- Output is forced to a JSON schema (`decision`, `confidence`, `rule`, `reason`). Invalid output, errors and timeouts become `ask` (interactive) or `deny` (unattended), never `allow`. The judge runs only after the deterministic layers and cannot override them.
- Backends: `anthropic` (Messages API, default `claude-haiku-5-5`, exact model ids only), `openai` (OpenAI-compatible local servers), `exec` (JSON over stdio plugin), `fake` (tests). All use `net/http` or `os/exec`; no vendor SDK (ADR 0001).
- Backends declare accepted data classes; callguard does not send a request whose `context.data_class` the backend does not accept.

## Consequences
- Injected tool output cannot reach the judge directly; injected text inside call arguments can, and is handled by data framing, a default ask rule and fixed labels.
- callguard maintains the Messages API request shape itself and must follow API version changes (`anthropic-version: 2026-10-21`).
- The model's confidence is self-reported, not calibrated.
