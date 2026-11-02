// callguard extension for pi.
//
// Install: callguard plugin pi > ~/.pi/agent/extensions/callguard/index.js
//
// UNTESTED against a live pi. Event and context fields (toolName, input,
// toolCallId, ctx.cwd, ctx.hasUI, ctx.ui.confirm) follow the pi extension
// docs.
//
// Fails CLOSED: any problem running callguard (spawn error, timeout,
// non-zero exit, unparseable output) blocks the call. "ask" opens a confirm
// dialog when pi has a UI and blocks otherwise. Environment:
//   CALLGUARD_BIN             callguard binary (default "callguard")
//   CALLGUARD_BIN_ARGS        JSON array of extra leading arguments (tests)
//   CALLGUARD_TIMEOUT_MS      timeout override (tests; default 12000)
import { spawn } from "node:child_process";

const MAX_STDOUT = 64 * 1024;
const DECISIONS = new Set(["allow", "ask", "deny"]);

function timeoutMs() {
  const n = Number.parseInt(process.env.CALLGUARD_TIMEOUT_MS ?? "", 10);
  return Number.isFinite(n) && n > 0 ? n : 12000;
}

// Runs `callguard hook generic` and resolves with the verdict, or rejects.
function callguard(request) {
  return new Promise((resolve, reject) => {
    let done = false;
    let timer;
    const finish = (fn, value) => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      fn(value);
    };
    try {
      const bin = process.env.CALLGUARD_BIN || "callguard";
      const extra = process.env.CALLGUARD_BIN_ARGS ? JSON.parse(process.env.CALLGUARD_BIN_ARGS) : [];
      if (!Array.isArray(extra) || extra.some((a) => typeof a !== "string")) {
        throw new Error("CALLGUARD_BIN_ARGS must be a JSON array of strings");
      }
      const child = spawn(bin, [...extra, "hook", "generic"], {
        stdio: ["pipe", "pipe", "pipe"],
        windowsHide: true,
      });
      timer = setTimeout(() => {
        child.kill("SIGKILL");
        finish(reject, new Error("timed out"));
      }, timeoutMs());
      const chunks = [];
      let size = 0;
      child.on("error", (e) => finish(reject, e));
      child.stdout.on("data", (c) => {
        size += c.length;
        if (size > MAX_STDOUT) {
          child.kill("SIGKILL");
          finish(reject, new Error("output too large"));
          return;
        }
        chunks.push(c);
      });
      child.stderr.resume();
      child.stdin.on("error", () => {}); // EPIPE: the exit status decides
      child.on("close", (code) => {
        if (code !== 0) return finish(reject, new Error(`exit status ${code}`));
        try {
          finish(resolve, JSON.parse(Buffer.concat(chunks).toString("utf8")));
        } catch (e) {
          finish(reject, new Error("unparseable output"));
        }
      });
      child.stdin.end(JSON.stringify(request));
    } catch (e) {
      finish(reject, e);
    }
  });
}

function describe(v) {
  const where = v.layer ? ` [${v.layer}${v.rule ? "/" + v.rule : ""}]` : "";
  return `callguard: ${v.reason ?? "no reason given"}${where}`;
}

export default function (pi) {
  pi.on("tool_call", async (event, ctx) => {
    let v;
    try {
      v = await callguard({
        harness: "pi",
        tool: event.toolName,
        input: event.input,
        cwd: ctx?.cwd || process.cwd(),
        session_id: "",
      });
      if (!v || !DECISIONS.has(v.decision)) throw new Error("verdict has no valid decision");
    } catch (e) {
      return { block: true, reason: `callguard: could not evaluate this call (${e.message}); blocked` };
    }
    if (v.enforced === false || v.decision === "allow") return undefined;
    if (v.decision === "ask") {
      if (ctx?.hasUI) {
        try {
          if (await ctx.ui.confirm("callguard", describe(v))) return undefined;
        } catch {
          // fall through to block
        }
        return { block: true, reason: `${describe(v)}. Not approved.` };
      }
      return { block: true, reason: `${describe(v)}. Needs human approval and pi has no UI.` };
    }
    return {
      block: true,
      reason: `${describe(v)}. Do not try to work around this block; if the action is needed, ask the user to run or approve it.`,
    };
  });
}
