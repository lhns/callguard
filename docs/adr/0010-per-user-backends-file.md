# 0010 Per-user backends file

Status: Accepted (2026-11-05). Builds on ADR 0003 (policy layers) and ADR 0005 (the judge's backends).

## Context
The judge's API key could only come from an environment variable (`api_key_env`). A variable set for callguard reaches every child process of the shell or harness and, if set globally, every program of the user; with Claude Code a global `ANTHROPIC_API_KEY` can also change which key Claude itself uses. User and project policy layers cannot define backends (they may only tighten), so a developer had no private place for a key or a local endpoint short of root-owned system policy or their own `--policy` file.

## Decision
- A file `<user config dir>/callguard/backends.json` (`%APPDATA%\callguard\` on Windows, `$XDG_CONFIG_HOME` or `~/.config/callguard/` on Linux, `~/Library/Application Support/callguard/` on macOS) holds `{"default": name, "backends": {name: backend}}`. A backend has the fields of a policy backend plus `api_key`.
- It is read last, only from the user's own config directory (never from a project, the working directory or the policy directories) and not with `--no-user-policy`. A backend named there replaces the merged policy's backend of the same name as a whole entry; other names are added. `default` sets `llm.backend` unless the system layer set it. A system policy with `"final": true` ignores the file, as it ignores every lower layer.
- A missing file is silent. An unreadable or invalid file is a policy load error, so the fail-safe path applies (ask, deny when unattended); the message names the file and never quotes a value.
- `api_key` wins over `api_key_env`. It is a `Secret` type whose Debug and Serialize show `(set)`, so it appears in no printed policy, `policy_rev`, log, eval report or error. The policy field is the same type, so there is one code path; only the system layer can set backends in a policy.
- Writes to the file are denied and reads of it (Read tool, `cat`, `type`, `Get-Content`) ask, by a built-in that no allow rule outranks, like the trust-record guard. `callguard backends init` writes a template (mode 0600 in a 0700 directory on Unix) whose placeholder key counts as no key.

## Consequences
- The key no longer sits in the environment of child processes.
- The agent runs as the same user and can read the file by a route the guards do not see (a script it wrote, a glob, a variable in a shell command); the guards raise the bar, they do not remove the exposure. Mode 0600 protects against other users only.
- The file can redirect the judge (`base_url`) or point `default` at a permissive backend, which is why it is self-protected, read only from the user's own directory, and ignored under `final`.
- A replaced entry loses the built-in entry's `data_classes`; list them again, or calls with a data class fall back.
- The `policy_rev` does not change when only a key changes.
