# 0003 JSON policy with tighten-only user and project layers

Status: Accepted (2026-11-02)

## Context
Policy comes from an administrator (or a host such as Switchboard rendering it per zone), the user, and the project. In agent setups the agent's uid usually owns `~` and the repository, so anything there is attacker-writable. Claude Code's `autoMode` ignores project settings for this reason but merges the other scopes additively, which lets a user loosen an organization rule.

## Decision
- Policy files are JSON with `policy_version: 1`. Alternative considered: YAML through one pinned module (comments, nicer to hand-edit); rejected for ADR 0001 and because Claude Code settings and nah config are JSON too.
- Layers: built-in defaults < system (`--policy` or `/etc/callguard/policy.json`) < user < project. Only the system layer can add allow rules, configure backends, LLM slots that loosen (`environment`, `allow_exceptions`), modes and timeouts.
- User and project layers can only add deny and ask rules, append LLM block rules, and raise `min_confidence`. Other keys there are dropped with a warning.
- `final: true` in the system file stops reading lower layers.
- No environment variable selects the policy; only the hook command line does.

## Consequences
- A malicious repository can at worst cause extra prompts.
- A single developer configures backends through their own `--policy` file referenced from the harness hook config.
- Stricter than Claude Code's additive merge; documented in docs/design.md.
