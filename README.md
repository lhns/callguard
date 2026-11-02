# callguard

callguard decides whether one pending coding-agent tool call may run without a human prompt: `allow`, `ask` or `deny`, with a reason, the layer and rule that decided, and a confidence. It is a peer of Claude Code's auto-mode classifier that works for any harness through hook adapters (Claude Code, Hermes, opencode, pi).

Layers run in order and the first that decides wins: built-in hard-deny and self-protection rules, an optional nah subprocess, policy rules (regex, path and context matches), then an optional reasoning-blind LLM judge that only sees user messages and tool calls. Any error becomes `ask`, or `deny` when nobody can answer a prompt; callguard never fails open. Details: [docs/design.md](docs/design.md), decisions: [docs/adr](docs/adr).

## Install

```sh
go install github.com/lhns/callguard/cmd/callguard@<version>
```

Or from source: `git clone https://github.com/lhns/callguard && cd callguard && go build -o callguard ./cmd/callguard`. Go only, no other dependencies.

## Harness setup

All hook commands take the same flags:

| Flag | Meaning |
| --- | --- |
| `--policy PATH` | system policy file (default `/etc/callguard/policy.json`, `%ProgramData%\callguard\policy.json`) |
| `--no-user-policy` | skip the user policy layer |
| `--log PATH` | decision log path, `-` disables it |
| `--unattended` | nobody can answer a prompt: `ask` becomes `deny` |
| `--context key=value` | request context entry, repeatable (for example `trust=tainted`, `data_class=private`) |
| `--context-file PATH` | JSON object of strings merged into the context. **The file must be root-owned**: a file the agent can write lets it label its own calls. A missing or invalid file gives an ask/deny verdict, never a silent skip |
| `--allow-in-auto` | Claude only, see below |

### Claude Code

`~/.claude/settings.json` (or managed settings):

```json
{"hooks":{"PreToolUse":[{"matcher":"*","hooks":[{"type":"command","command":"callguard hook claude --policy /etc/callguard/policy.json","timeout":15,"onFailure":"block"}]}]}}
```

- A hook `allow` never overrides Claude's own deny or ask rules.
- In `permission_mode: auto` callguard emits nothing on `allow`, so Claude's classifier still runs; `--allow-in-auto` changes that.
- For `AskUserQuestion` and `ExitPlanMode` an `allow` is also dropped (they need `updatedInput`); `ask` and `deny` still apply.
- `permission_mode: dontAsk` counts as unattended.
- Exit codes: the hook exits 0 with a JSON decision, or 2 with the reason on stderr. Claude runs the tool after any other non-zero exit, so callguard never uses one, and bad flags exit 2. Keep `onFailure: "block"` so a timeout blocks too.

### Hermes

`config.yaml`:

```yaml
hooks:
  pre_tool_call:
    - command: "callguard hook hermes --policy /etc/callguard/policy.json"
      timeout: 15
      fail_closed: true
```

Hermes asks for consent before it runs a new shell hook: approve it once (`~/.hermes/shell-hooks-allowlist.json`) or start with `--accept-hooks`. `ask` becomes Hermes' own approval prompt (`{"action":"approve"}`), `deny` becomes `{"action":"block"}` with exit 2.

### opencode and pi

```sh
callguard plugin opencode > ~/.config/opencode/plugins/callguard.js   # opencode 2.x
callguard plugin pi > ~/.pi/agent/extensions/callguard/index.js
```

The plugins run `callguard hook generic` (found via `CALLGUARD_BIN`, else `PATH`) and fail closed: a spawn error, a 12 s timeout, a non-zero exit or unparseable output blocks the call. opencode blocks on `ask` unless `CALLGUARD_OPENCODE_ASK=delegate`; pi asks through its confirm dialog and blocks without a UI. Policy flags for these are not exposed yet; point `callguard` at a wrapper script if you need `--policy`.

### Status

| Harness | Status |
| --- | --- |
| Claude Code | verified against the hooks docs |
| Hermes | verified against current docs, not run against a live Hermes; Hermes 0.19 unverified |
| opencode 2.x | unverified, untested (shape from docs and nah's adapter) |
| pi | untested (shape from the pi extension docs) |
| opencode 1.x | unsupported |

## Configuration

Policy is JSON (`"policy_version": 1`) in layers: built-in defaults, system (`--policy`), user (`<user config dir>/callguard/policy.json`), project (`<project>/.callguard/policy.json`). **User and project layers can only tighten**: they may add `deny`/`ask` rules, add `llm.block` entries and raise `llm.min_confidence`; everything else in them is dropped with a warning. A system file with `"final": true` ignores the lower layers.

```json
{
  "policy_version": 1,
  "final": false,
  "mode": "enforce",
  "rules": [
    {"id": "no-prod-kubectl", "description": "kubectl against prod needs a human",
     "decision": "ask",
     "match": {"kind": ["shell"], "command": "\\bkubectl\\b.*--context[= ]prod"}}
  ],
  "llm": {
    "enabled": true, "mode": "shadow", "backend": "anthropic",
    "timeout_ms": 3000, "min_confidence": 0.7
  },
  "backends": {
    "anthropic": {"type": "anthropic", "model": "claude-haiku-5-5", "api_key_env": "ANTHROPIC_API_KEY",
                  "data_classes": ["open", "private"]}
  }
}
```

- `callguard policy check` loads and lints the layers and reports dropped keys.
- **Shadow mode**: rules are enforced while the LLM layer defaults to `shadow`. A shadowed verdict has `enforced: false` and the harness behaves as without callguard, while the decision log records what callguard would have done. Switch `llm.mode` to `enforce` once the log and `callguard eval` justify it.
- **Decision log**: JSONL, default `<user state dir>/callguard/decisions.jsonl`. It stores an input hash, not arguments, transcript text or LLM reasons, unless `log.include_input` is true.
- **Eval**: `callguard eval --backend <name>` scores the labelled set (benign, overeager, exfiltration, tainted, injection) per bucket; the `fake` backend runs offline.
- **Backends**: `anthropic` (default `claude-haiku-5-5`, exact model ids, `base_url` configurable), `openai` (any OpenAI-compatible server such as llama.cpp, vLLM, Ollama), `exec` (your own classifier command) and `fake` (tests). A request with `context.data_class` goes only to a backend that lists that class; otherwise the LLM is skipped and the verdict falls back to ask/deny.

## Fail-safe

Never `allow` on error. Bad input, a policy load error, a backend failure, a timeout or a panic in the hook yields an `ask` verdict, or `deny` when unattended, in the harness's native format. The overall deadline (`deadline_ms`, default 8000) sits below the harness timeouts.

## License

Apache-2.0, see [LICENSE](LICENSE).
