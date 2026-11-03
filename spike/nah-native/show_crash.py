#!/usr/bin/env python3
"""Summarise a crash-matrix JSONL: non-ok rows, then the slowest and verdict per case."""
import collections
import json
import sys

rows = [json.loads(l) for l in open(sys.argv[1], encoding="utf8")]
print("rows", len(rows), collections.Counter(r["kind"] for r in rows),
      collections.Counter((r["r"] or {}).get("outcome") for r in rows))
print("--- not ok, or panicked, or error")
for r in rows:
    inner = r["r"] or {}
    if r["kind"] != "ok" or inner.get("outcome") not in ("ok", None) and inner.get("outcome") != "error":
        print(r["case"], r["n"], "stack", r["stack"], "budget", r["budget"], r["kind"],
              "exit", r["exit"], r["wall_ms"], "ms", repr(r["stderr"][-110:]), inner.get("panic"))
print("--- errors")
seen = set()
for r in rows:
    inner = r["r"] or {}
    if inner.get("outcome") == "error" and (r["case"], inner["error"][:50]) not in seen:
        seen.add((r["case"], inner["error"][:50]))
        print(r["case"], r["n"], inner["error"][:110])
print("--- per case at largest size that ran (main stack, each budget)")
best = {}
for r in rows:
    if r["stack"] in ("main",) and r["kind"] == "ok" and (r["r"] or {}).get("outcome") == "ok":
        best[(r["case"], r["budget"])] = r
for (case, budget), r in sorted(best.items()):
    i = r["r"]
    print(f"{case:20} b={budget:5} n={r['n']:<9} {i['verdict']:9} {i['coverage']:8} {i['ms']:>7}ms "
          f"{(i.get('rules') or [])[:3]} ref={i.get('refusals')} gaps={(i.get('gaps') or [])[:2]}")
slow = sorted(rows, key=lambda r: -r["wall_ms"])[:15]
print("--- slowest")
for r in slow:
    print(r["case"], r["n"], r["stack"], r["budget"], r["kind"], r["wall_ms"], "ms")
