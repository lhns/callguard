#!/usr/bin/env python3
"""Compare conformance JSONL configs.

analyse.py agree FILE [A B]   agreement of config B with A (default oracle, none)
analyse.py flips BASE FILE    per config in FILE: rows whose verdict differs from
                              config BASE's in the BASE file (first config there
                              unless BASE file:config)
analyse.py time FILE          per-config p50/p95/max ms
"""
import collections
import json
import sys


def load(path):
    rows = collections.defaultdict(dict)
    for line in open(path, encoding="utf8"):
        r = json.loads(line)
        rows[r["ID"]][r["Config"]] = r
    return rows


def pct(values, p):
    values = sorted(values)
    return values[(len(values) - 1) * p // 100] if values else 0


def agree(path, a="oracle", b="none"):
    rows = load(path)
    same = verdict = compared = 0
    classes = collections.Counter()
    samples = collections.defaultdict(list)
    exp = collections.Counter()
    for rid, row in rows.items():
        if a not in row or b not in row:
            continue
        x, y = row[a], row[b]
        compared += 1
        for name, r in ((a, x), (b, y)):
            guard = r.get("ExpectedGuard")
            if r.get("Verdict") == r["Expected"] and (not guard or guard in (r.get("Rules") or [])):
                exp[name] += 1
        v_same = x.get("Verdict") == y.get("Verdict") and not x.get("Error") and not y.get("Error")
        verdict += v_same
        if v_same and (x.get("Rules") or []) == (y.get("Rules") or []):
            same += 1
            continue
        if x.get("Error") or y.get("Error"):
            cause = "error"
        else:
            dl = {True: "deadline", False: "no-deadline"}
            cause = f"{a}:{x.get('Verdict')}({dl[x['Deadline']]}) {b}:{y.get('Verdict')}({dl[y['Deadline']]})"
            if v_same:
                cause = "same verdict, different guards; " + cause
        classes[cause] += 1
        samples[cause].append((rid, x, y))
    print(f"{path}: {a} vs {b}: compared {compared}, same verdict+guards {same} "
          f"({100 * same / max(compared, 1):.2f}%), same verdict {verdict}")
    print(f"matching corpus expectation: {dict(exp)}")
    for cause, n in classes.most_common():
        print(f"  {n:5} {cause}")
        for rid, x, y in samples[cause][:6]:
            print(f"        {rid}: {x['Input'][:90]}")
            print(f"           {a} {x.get('Rules')} {x.get('Coverage')} {x.get('Error', '')[:150]} {x['MS']:.0f}ms")
            print(f"           {b} {y.get('Rules')} {y.get('Coverage')} {y.get('Error', '')[:150]} {y['MS']:.0f}ms")


def flips(base_spec, path):
    base_path, _, base_cfg = base_spec.partition(":")
    base = load(base_path)
    if not base_cfg:
        base_cfg = next(iter(next(iter(base.values()))))
    rows = load(path)
    configs = sorted({c for row in rows.values() for c in row})
    for cfg in configs:
        n = compared = deadline = 0
        flipped = collections.Counter()
        samples = []
        ms = []
        for rid, row in rows.items():
            if cfg not in row or base_cfg not in base.get(rid, {}):
                continue
            r, b = row[cfg], base[rid][base_cfg]
            compared += 1
            ms.append(r["MS"])
            deadline += r.get("Deadline", False)
            if r.get("Verdict") != b.get("Verdict"):
                n += 1
                flipped[f"{b.get('Verdict')}->{r.get('Verdict')}"] += 1
                samples.append((rid, r["Deadline"], r["Input"][:80]))
        print(f"{path} {cfg}: compared {compared}, verdict differs from {base_cfg}: {n} {dict(flipped)}, "
              f"deadline hit on {deadline}, ms p50 {pct(ms, 50):.1f} p95 {pct(ms, 95):.1f} max {max(ms or [0]):.0f}")
        for s in samples[:8]:
            print("     ", s)


def times(path):
    per = collections.defaultdict(list)
    for row in load(path).values():
        for cfg, r in row.items():
            per[cfg].append(r["MS"])
    for cfg, ms in per.items():
        print(f"{cfg}: n {len(ms)} p50 {pct(ms, 50):.1f} p95 {pct(ms, 95):.1f} max {max(ms):.0f}")


if __name__ == "__main__":
    verb, *args = sys.argv[1:]
    {"agree": agree, "flips": flips, "time": times}[verb](*args)
