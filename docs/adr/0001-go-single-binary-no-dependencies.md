# 0001 Go, single static binary, no third-party dependencies

Status: Accepted (2026-11-02)

## Context
callguard runs once per tool call inside a harness hook, so process start time matters. Switchboard, its first host, is written in Go and wants to embed it. Supply-chain risk counts double for a security tool that sits in every agent's path.

## Decision
Write callguard in Go as one static binary plus an importable library. Use only the standard library: policy is JSON (ADR 0003) and backends speak HTTP with `net/http` (ADR 0005). A new third-party module needs an ADR.

## Consequences
- Millisecond start, trivial cross-compilation for Linux, macOS and Windows, `go install` works.
- callguard maintains its own small HTTP clients instead of using vendor SDKs.
- No YAML; policy files have no comments (rules carry a `description` field instead).
