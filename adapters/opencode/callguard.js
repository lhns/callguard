// callguard plugin for opencode 2.x ONLY (opencode 1.x uses another plugin
// shape and is not supported).
//
// Install: callguard plugin opencode > ~/.config/opencode/plugins/callguard.js
//
// UNTESTED against a live opencode. The module shape (`id`, `setup(ctx)`,
// `ctx.tool.hook("execute.before", ...)`) follows opencode 2 docs and nah's
// adapter. Not used: ctx.permission.hook("evaluate") could express "ask"
// natively later, but its event has no tool input.
//
// Fails CLOSED: any problem running callguard (spawn error, timeout,
// non-zero exit, unparseable output) blocks the call. Environment:
//   CALLGUARD_BIN             callguard binary (default "callguard")
//   CALLGUARD_OPENCODE_ASK    "delegate": on "ask", fall through to
//                             opencode's own permission flow instead of
//                             blocking
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

export default {
  id: "callguard",
  async setup(ctx) {
    await ctx.tool.hook("execute.before", async (event) => {
      let cwd = "";
      try {
        // Shape taken from nah's adapter, not from opencode docs: unverified.
        const s = await ctx.session.get({ sessionID: event.sessionID });
        cwd = s.location.directory;
      } catch {
        cwd = "";
      }
      let v;
      try {
        v = await callguard({
          harness: "opencode",
          tool: event.tool,
          input: event.input,
          cwd,
          session_id: event.sessionID,
        });
        if (!v || !DECISIONS.has(v.decision)) throw new Error("verdict has no valid decision");
      } catch (e) {
        throw new Error(`callguard: could not evaluate this call (${e.message}); blocked`);
      }
      if (v.enforced === false || v.decision === "allow") return;
      if (v.decision === "ask") {
        if (process.env.CALLGUARD_OPENCODE_ASK === "delegate") return;
        throw new Error(`${describe(v)}. Needs human approval; ask the user.`);
      }
      throw new Error(
        `${describe(v)}. Do not try to work around this block; if the action is needed, ask the user to run or approve it.`,
      );
    });
  },
};
