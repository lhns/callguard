# 0004 nah as an optional subprocess layer, not a dependency

Status: Superseded by ADR 0007 (2026-11-04)

## Context
nah (MIT, Rust) is a mature deterministic guard with 48 guards, a large reviewed corpus and adapters for many harnesses. Its crates are not published; its stable surface is the `nah decide` CLI (`nah/decide/v1`). It has one maintainer and a CLA that grants a relicensing right. Requiring it would make callguard depend on a separately installed binary on every platform.

## Decision
- callguard ships its own small hard-deny set (catastrophic deletion, disk wipe, fork bomb, self-protection) and default rules, so it works alone.
- When `nah.enabled` is set, callguard runs `nah decide` as layer 1: `block` → deny with rule `nah:<guard>`, `delegate` → continue. Failures continue with a warning unless `nah.require` is set, which fails closed.
- callguard does not copy nah's guard logic. A few nah corpus commands seed the eval set, with attribution.

## Consequences
- Users get nah's depth by installing it, without callguard depending on its licence or release cadence.
- Two process spawns per call when nah is enabled.
- The owner confirmed (2026-11-03) that nah stays optional.
