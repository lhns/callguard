# 0002 Request and verdict schema v1

Status: Accepted (2026-11-02)

## Context
Hosts and adapters in several languages call callguard. The contract has to outlive internal changes and be checkable.

## Decision
- JSON objects with `"schema": "callguard/request/v1"` / `"callguard/verdict/v1"` and `"v": 1`, as nah does with `nah/decide/v1`.
- A verdict's `decision` is always `allow`, `ask` or `deny`. `enforced: false` marks a verdict the caller must not act on (shadow mode or no layer decided); the harness's own flow then applies.
- Verdicts carry `reason`, `layer`, `rule`, `confidence`, `policy_rev`, `backend`, `latency_ms`, `id`, `warnings`.
- Requests carry an opaque `context` string map for host labels (taint, data class, principal) and an `unattended` flag. callguard interprets only `data_class`.
- Within v1, fields may be added but not removed or redefined. `callguard decide` exit codes (0 allow, 1 deny, 2 ask, 3 bad request) are a convenience; the JSON is authoritative. Hook subcommands follow each harness's own exit semantics.

## Consequences
- Switchboard can integrate by passing `context` without callguard knowing about it.
- A fourth outcome ("no opinion") is expressed by `enforced: false` rather than a new decision value, so the three-way decision stays simple for consumers.
