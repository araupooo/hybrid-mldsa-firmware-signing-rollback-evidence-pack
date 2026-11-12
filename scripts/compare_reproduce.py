#!/usr/bin/env python3
"""compare_reproduce.py — compare re-derived (fresh-clone-*) headline numbers
against the shipped ones in pack/outputs/.

Usage: compare_reproduce.py <outputs-dir>
Prints one PASS/FAIL line per check and exits non-zero if any check fails.

Tolerances: sign/verify means within 25%; keypair means within 2x (first-call
warm-up makes keypair means outlier-sensitive — the stable figure is min,
checked within 25%). Exact match for sizes (OK lines), verify-failure
counts (0), and scenario PASS counts (11/11 each run).
"""
import csv
import re
import sys

OUT = sys.argv[1]
fails = []


def check(name, ok, detail=""):
    print(("PASS" if ok else "FAIL"), name, detail)
    if not ok:
        fails.append(name)


def read(p):
    with open(f"{OUT}/{p}", errors="ignore") as f:
        return f.read()


def bench_numbers(fn):
    t = read(fn)
    m = {}
    for scheme in ("ML-DSA-44", "ML-DSA-65", "ML-DSA-87", "Ed25519"):
        for op in ("keypair", "sign", "verify"):
            mm = re.search(rf"CSV: {re.escape(scheme)} {op},n=\d+,mean_us=([\d.]+),min_us=([\d.]+),max_us=([\d.]+),rate_ops_s=([\d.]+)", t)
            m[(scheme, op)] = (float(mm.group(1)), float(mm.group(2))) if mm else (None, None)
        mm = re.search(rf"\[{re.escape(scheme)}\] verify failures: (\d+) / (\d+)", t)
        m[(scheme, "verify_fail")] = int(mm.group(1)) if mm else None
    # size OK lines: 3 per ML-DSA scheme (sk/pk/sig) + 3 for Ed25519
    m["sizes_ok"] = t.count(" OK") >= 12
    m["sizes_fail"] = t.count("MISMATCH")
    return m


def scenario_numbers(fn):
    rows = list(csv.DictReader(open(f"{OUT}/{fn}")))
    ok = sum(1 for r in rows if r["result"] == "PASS")
    return {"n": len(rows), "pass": ok}


def close(a, b, rel=0.25, abs_tol=5.0):
    return a is not None and b is not None and abs(a - b) <= max(rel * abs(b), abs_tol)


for run in ("run1", "run2"):
    s = bench_numbers(f"bench-sig-{run}.log")
    f = bench_numbers(f"fresh-clone-bench-sig-{run}.log")
    check(f"bench {run} sizes OK (FIPS 204 Table 2 / RFC 8032)", f["sizes_ok"] and f["sizes_fail"] == 0, "fresh")
    check(f"bench {run} sizes OK (FIPS 204 Table 2 / RFC 8032)", s["sizes_ok"] and s["sizes_fail"] == 0, "shipped")
    for scheme in ("ML-DSA-44", "ML-DSA-65", "ML-DSA-87", "Ed25519"):
        check(f"bench {run} {scheme} verify failures 0",
              s[(scheme, "verify_fail")] == 0 and f[(scheme, "verify_fail")] == 0)
        # keypair: min within 25% (stable), mean within 2x (warm-up outlier)
        check(f"bench {run} {scheme} keypair min within 25% and mean within 2x",
              close(f[(scheme, "keypair")][1], s[(scheme, "keypair")][1])
              and f[(scheme, "keypair")][0] <= 2 * s[(scheme, "keypair")][0]
              and s[(scheme, "keypair")][0] <= 2 * f[(scheme, "keypair")][0],
              f"shipped mean={s[(scheme, 'keypair')][0]} min={s[(scheme, 'keypair')][1]} us; "
              f"fresh mean={f[(scheme, 'keypair')][0]} min={f[(scheme, 'keypair')][1]} us")
        for op in ("sign", "verify"):
            check(f"bench {run} {scheme} {op} mean within 25%",
                  close(f[(scheme, op)][0], s[(scheme, op)][0]),
                  f"shipped={s[(scheme, op)][0]} us fresh={f[(scheme, op)][0]} us")

for run in ("run1", "run2"):
    s = scenario_numbers(f"{run}-scenarios.csv")
    f = scenario_numbers(f"fresh-clone-{run}-scenarios.csv")
    check(f"scenarios {run} shipped 11/11 PASS", s["n"] == 11 and s["pass"] == 11,
          f"{s['pass']}/{s['n']}")
    check(f"scenarios {run} fresh 11/11 PASS", f["n"] == 11 and f["pass"] == 11,
          f"{f['pass']}/{f['n']}")
    # expected vs observed agreement per scenario
    for prefix, label in (("", "shipped"), ("fresh-clone-", "fresh")):
        rows = list(csv.DictReader(open(f"{OUT}/{prefix}{run}-scenarios.csv")))
        bad = [r["scenario"] for r in rows if r["expected"] != r["observed"]]
        check(f"scenarios {run} {label} expected==observed for all", len(bad) == 0,
              f"mismatches: {bad}")

print()
if fails:
    print(f"COMPARISON: {len(fails)} FAILURES: {', '.join(fails)}")
    sys.exit(1)
print("COMPARISON: ALL CHECKS PASSED")
