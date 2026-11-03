// Self-test for the opencode and pi plugins against a stub "callguard".
// Run: node adapters/selftest.mjs
//
// The stub is a node script run through CALLGUARD_BIN=<node> and
// CALLGUARD_BIN_ARGS=["<stub>"], which works the same on Windows and Linux.
// The scenario is chosen by the tool name in the request.
import assert from "node:assert/strict";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const dir = mkdtempSync(join(tmpdir(), "callguard-selftest-"));
const stub = join(dir, "stub.mjs");
writeFileSync(
  stub,
  `
import { readFileSync } from "node:fs";
const args = process.argv.slice(2);
if (args.join(" ") !== "hook generic") { process.exit(64); }
const req = JSON.parse(readFileSync(0, "utf8"));
const v = (decision, extra = {}) => ({ schema: "callguard/verdict/v1", v: 1, decision, enforced: true, reason: "stub", layer: "rules", rule: "r1", ...extra });
const out = (o) => process.stdout.write(JSON.stringify(o) + "\\n");
switch (req.tool) {
  case "allow": out(v("allow")); break;
  case "deny": out(v("deny")); break;
  case "ask": out(v("ask")); break;
  case "shadow-deny": out(v("deny", { enforced: false })); break;
  case "echo": out(v("deny", { reason: JSON.stringify({ harness: req.harness, cwd: req.cwd, sid: req.session_id, input: req.input }) })); break;
  case "garbage": process.stdout.write("not json"); break;
  case "no-decision": out({ schema: "callguard/verdict/v1", enforced: true }); break;
  case "bad-decision": out(v("maybe")); break;
  case "exit1": process.exit(1); break;
  case "huge": process.stdout.write("x".repeat(200 * 1024)); break;
  case "hang": setInterval(() => {}, 1000); break;
  default: process.exit(70);
}
`,
);
process.env.CALLGUARD_BIN = process.execPath;
process.env.CALLGUARD_BIN_ARGS = JSON.stringify([stub]);
process.env.CALLGUARD_TIMEOUT_MS = "10000"; // bounds the "hang" scenario; generous because node start can take seconds on a loaded host

let failures = 0;
async function test(name, fn) {
  try {
    await fn();
    console.log(`ok   ${name}`);
  } catch (e) {
    failures++;
    console.log(`FAIL ${name}\n${e.stack}`);
  }
}

const opencode = (await import(pathToFileURL(join(here, "opencode", "callguard.js")))).default;
const pi = (await import(pathToFileURL(join(here, "pi", "callguard.js")))).default;

// opencode: fake host.
async function opencodeHook({ sessionFails = false } = {}) {
  let hook;
  const ctx = {
    tool: { hook: async (name, fn) => { assert.equal(name, "execute.before"); hook = fn; } },
    session: {
      get: async ({ sessionID }) => {
        if (sessionFails) throw new Error("no session");
        return { location: { directory: "/work/" + sessionID } };
      },
    },
  };
  assert.equal(opencode.id, "callguard");
  await opencode.setup(ctx);
  return (tool, input = {}) => hook({ tool, input, sessionID: "s1" });
}

// pi: fake host.
function piHandler() {
  let handler;
  pi({ on: (name, fn) => { assert.equal(name, "tool_call"); handler = fn; } });
  return (toolName, ctx = {}, input = {}) => handler({ toolName, input, toolCallId: "t1" }, ctx);
}

const blocked = (e) => /^callguard: /.test(e.message);

await test("opencode: allow passes", async () => {
  const run = await opencodeHook();
  assert.equal(await run("allow"), undefined);
});
await test("opencode: not enforced passes", async () => {
  const run = await opencodeHook();
  assert.equal(await run("shadow-deny"), undefined);
});
await test("opencode: deny blocks with reason", async () => {
  const run = await opencodeHook();
  await assert.rejects(run("deny"), (e) => blocked(e) && e.message.includes("[rules/r1]") && e.message.includes("work around"));
});
await test("opencode: ask blocks by default", async () => {
  const run = await opencodeHook();
  delete process.env.CALLGUARD_OPENCODE_ASK;
  await assert.rejects(run("ask"), blocked);
});
await test("opencode: ask delegates when configured", async () => {
  const run = await opencodeHook();
  process.env.CALLGUARD_OPENCODE_ASK = "delegate";
  try {
    assert.equal(await run("ask"), undefined);
    await assert.rejects(run("deny"), blocked); // delegate never loosens deny
  } finally {
    delete process.env.CALLGUARD_OPENCODE_ASK;
  }
});
await test("opencode: request carries tool, input, session and cwd", async () => {
  const run = await opencodeHook();
  let message = "";
  try { await run("echo", { a: 1 }); } catch (e) { message = e.message; }
  const got = JSON.parse(message.slice(message.indexOf("{"), message.lastIndexOf("}") + 1));
  assert.deepEqual(got, { harness: "opencode", cwd: "/work/s1", sid: "s1", input: { a: 1 } });
});
await test("opencode: unknown session location sends an empty cwd", async () => {
  const run = await opencodeHook({ sessionFails: true });
  let message = "";
  try { await run("echo"); } catch (e) { message = e.message; }
  const got = JSON.parse(message.slice(message.indexOf("{"), message.lastIndexOf("}") + 1));
  assert.equal(got.cwd, "");
});
for (const scenario of ["garbage", "no-decision", "bad-decision", "exit1", "huge", "hang", "unknown-exit70"]) {
  await test(`opencode: ${scenario} blocks`, async () => {
    const run = await opencodeHook();
    await assert.rejects(run(scenario === "unknown-exit70" ? "other" : scenario), blocked);
  });
}
await test("opencode: missing binary blocks", async () => {
  const run = await opencodeHook();
  const saved = process.env.CALLGUARD_BIN;
  process.env.CALLGUARD_BIN = join(dir, "does-not-exist");
  try {
    await assert.rejects(run("allow"), blocked);
  } finally {
    process.env.CALLGUARD_BIN = saved;
  }
});

await test("pi: allow passes", async () => {
  assert.equal(await piHandler()("allow", { cwd: "/w" }), undefined);
});
await test("pi: not enforced passes", async () => {
  assert.equal(await piHandler()("shadow-deny", { cwd: "/w" }), undefined);
});
await test("pi: deny blocks", async () => {
  const r = await piHandler()("deny", { cwd: "/w", hasUI: true });
  assert.equal(r.block, true);
  assert.match(r.reason, /^callguard: /);
});
await test("pi: ask with UI and confirm proceeds", async () => {
  let asked;
  const ctx = { cwd: "/w", hasUI: true, ui: { confirm: async (title, msg) => { asked = [title, msg]; return true; } } };
  assert.equal(await piHandler()("ask", ctx), undefined);
  assert.equal(asked[0], "callguard");
  assert.match(asked[1], /^callguard: /);
});
await test("pi: ask with UI and refusal blocks", async () => {
  const ctx = { cwd: "/w", hasUI: true, ui: { confirm: async () => false } };
  assert.equal((await piHandler()("ask", ctx)).block, true);
});
await test("pi: ask with a throwing confirm blocks", async () => {
  const ctx = { cwd: "/w", hasUI: true, ui: { confirm: async () => { throw new Error("x"); } } };
  assert.equal((await piHandler()("ask", ctx)).block, true);
});
await test("pi: ask without UI blocks", async () => {
  assert.equal((await piHandler()("ask", { cwd: "/w", hasUI: false })).block, true);
  assert.equal((await piHandler()("ask", { cwd: "/w" })).block, true);
});
await test("pi: request carries tool, input and ctx.cwd", async () => {
  const r = await piHandler()("echo", { cwd: "/pi/cwd" }, { p: "x" });
  const got = JSON.parse(r.reason.slice(r.reason.indexOf("{"), r.reason.lastIndexOf("}") + 1));
  assert.deepEqual(got, { harness: "pi", cwd: "/pi/cwd", sid: "", input: { p: "x" } });
});
await test("pi: cwd falls back to process.cwd()", async () => {
  const r = await piHandler()("echo", {});
  const got = JSON.parse(r.reason.slice(r.reason.indexOf("{"), r.reason.lastIndexOf("}") + 1));
  assert.equal(got.cwd, process.cwd());
});
for (const scenario of ["garbage", "no-decision", "bad-decision", "exit1", "huge", "hang"]) {
  await test(`pi: ${scenario} blocks`, async () => {
    const ctx = { cwd: "/w", hasUI: true, ui: { confirm: async () => true } };
    const r = await piHandler()(scenario, ctx);
    assert.equal(r.block, true);
    assert.match(r.reason, /^callguard: /);
  });
}

rmSync(dir, { recursive: true, force: true });
if (failures) {
  console.log(`${failures} failed`);
  process.exit(1);
}
console.log("all passed");
