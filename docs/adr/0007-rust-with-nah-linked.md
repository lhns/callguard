# 0007 Rust, with nah linked in and run as a supervised child

Status: Accepted (2026-11-04). Supersedes ADR 0001 and ADR 0004.

## Context
callguard started as Go with nah as an optional subprocess (`nah decide`). That gave the judge almost no parse, left nah's depth to users who installed it, and kept a second set of danger rules next to nah's. nah is Rust. A WebAssembly experiment showed it can be embedded, but with a 34 MB module, 3 to 60 s load, a nah patch and no Windows. A native build (evidence: `git show 145fe3e:docs/rust-phase0.md`) works on Windows and Linux with no logic disagreement against the official binary over 8,858 corpus rows.

Linking nah brings two new risks. nah recurses deeply, and a crafted `.rs` file overflows any stack; `catch_unwind` cannot catch that, and Claude Code runs the tool after any exit but 2. And nah's analysis budget is fixed at 100 ms of wall time, which under load turns blocks into delegates.

## Decision
- Write callguard in Rust, one binary, with a small set of dependencies (ADR 0001's "standard library only" ends). The toolchain is pinned.
- Link nah's crates (`nah-cli`, `nah-proto`, `nah-observe`) in `crates/callguard-nah`, the only crate that depends on them.
- **Supervised child.** nah runs in a copy of the binary (`callguard __engine`), never in the process that answers the harness. The parent kills the child at `nah.timeout_ms` (10 s), does not wait for pipe EOF after the kill, and treats a crash, timeout or bad output as "no parse". Self-protection and the catastrophic backstops run in the parent before nah.
- **nah is required.** With no parse, rules still run but no allow can match; if nothing decides, the verdict is the fail-safe one (ask, or deny when unattended) and the judge is skipped.
- **Memory cap.** The child limits itself to 512 MiB (`RLIMIT_AS`; a job object on Windows), so a runaway analysis ends as a crash (a `${x:-` nest grows 60 to 80 MB/s). macOS refuses `RLIMIT_AS`, so there a watchdog thread in the child aborts it past 512 MiB resident; that does not cover its git children.
- **Fork pin.** nah's crates are `publish = false`, so Cargo uses git: `github.com/lhns/nah`, branch `callguard-budget`, rev `c35eb6e`, nah v1.7.0 plus `decide_with_budget` (26 lines), which makes the analysis budget a parameter (default 2 s, kept by the load run). nah's `[patch.crates-io]` for `gosyn` is repeated in our workspace. Nothing goes upstream for now (owner decision); the patch can be offered later.
- Release builds use a `dist` profile with fat LTO and unwinding kept. `panic = "abort"` is forbidden: a panic must stay a crash the parent can see.
- nah's MIT notice and the licences of the other dependencies ship with each binary.

## Consequences
- One native binary on Linux (musl), macOS and Windows; `go install` is gone. The first build compiles nah and is slow.
- The judge gets nah's parse as facts. Where nah blocks, a former ask can become a deny.
- A call costs one extra process start. Under heavy load nah can lose a block or not answer; the fail-safe verdict and the parent's backstops then decide, never an allow.
- A nah bump may need wrapper fixes in `callguard-nah`; they fail at compile time or in the corpus conformance test (`cargo test -p callguard-nah --test corpus_conformance -- --ignored`), not silently.
- The fork must stay fetchable without credentials, since CI and builds depend on it.
- The Go implementation stays buildable at tag `go-final`.
