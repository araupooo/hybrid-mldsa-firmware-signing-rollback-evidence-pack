#!/usr/bin/env python3
"""make_index.py — generate docs/index.html from the measured logs.

Reads the CSV: lines in outputs/bench-sig-run{1,2}.log and the scenario
CSVs outputs/run{1,2}-scenarios.csv, and writes docs/index.html with
tables whose numbers are copied verbatim from those files. If
outputs/fresh-clone-compare.txt exists, its verdict line is included.
Run after scripts/run_all.sh (and after scripts/clean_reproduce.sh
when a reproduction is available).

Usage: make_index.py   (run from anywhere; operates on the pack root)
"""
import csv
import os
import re
import sys

PACK = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(PACK, "outputs")
DOCS = os.path.join(PACK, "docs")

SIZES = {
    "ML-DSA-44": ("FIPS 204 Table 2", 2560, 1312, 2420, 2),
    "ML-DSA-65": ("FIPS 204 Table 2", 4032, 1952, 3309, 3),
    "ML-DSA-87": ("FIPS 204 Table 2", 4896, 2592, 4627, 5),
    "Ed25519": ("RFC 8032 §1", 32, 32, 64, None),
}


def bench(run):
    path = os.path.join(OUT, f"bench-sig-{run}.log")
    rows = {}
    with open(path, errors="ignore") as f:
        text = f.read()
    for scheme in SIZES:
        for op in ("keypair", "sign", "verify"):
            m = re.search(rf"CSV: {re.escape(scheme)} {op},n=(\d+),mean_us=([\d.]+),"
                          rf"min_us=([\d.]+),max_us=([\d.]+),rate_ops_s=([\d.]+)", text)
            if not m:
                sys.exit(f"make_index: no CSV line for {scheme} {op} in {path}")
            rows[(scheme, op)] = (int(m.group(1)), float(m.group(2)), float(m.group(3)),
                                  float(m.group(4)), float(m.group(5)))
        m = re.search(rf"\[{re.escape(scheme)}\] verify failures: (\d+) / (\d+)", text)
        rows[(scheme, "verify_fail")] = (int(m.group(1)), int(m.group(2)))
    # measured sizes from the OK lines
    sizes = {}
    for scheme in ("ML-DSA-44", "ML-DSA-65", "ML-DSA-87"):
        sk = int(re.search(rf"\[{scheme}\] length_secret_key=(\d+)", text).group(1))
        pk = int(re.search(rf"\[{scheme}\] length_public_key=(\d+)", text).group(1))
        sg = int(re.search(rf"\[{scheme}\] length_signature=(\d+)", text).group(1))
        sizes[scheme] = (sk, pk, sg)
    pk = int(re.search(r"\[Ed25519\] public_key=(\d+) bytes", text).group(1))
    sk = int(re.search(r"\[Ed25519\] private_key=(\d+) bytes", text).group(1))
    sg = int(re.search(r"\[Ed25519\] signature=(\d+) bytes", text).group(1))
    sizes["Ed25519"] = (sk, pk, sg)
    return rows, sizes


def scenarios(run):
    path = os.path.join(OUT, f"{run}-scenarios.csv")
    with open(path, newline="") as f:
        return list(csv.DictReader(f))


b1, s1 = bench("run1")
b2, s2 = bench("run2")
sc1 = scenarios("run1")
sc2 = scenarios("run2")

compare = None
cmp_path = os.path.join(OUT, "fresh-clone-compare.txt")
if os.path.exists(cmp_path):
    with open(cmp_path, errors="ignore") as f:
        for line in f:
            if line.startswith("COMPARISON:"):
                compare = line.strip()
                break

html = []
a = html.append
a("<!DOCTYPE html>")
a("<html lang=\"en\"><head><meta charset=\"utf-8\">")
a("<title>Hybrid ML-DSA Firmware Signing and Rollback Assessment — Results</title>")
a("<style>body{font-family:system-ui,sans-serif;max-width:960px;margin:2em auto;padding:0 1em}"
  "table{border-collapse:collapse;margin:1em 0}th,td{border:1px solid #999;padding:.35em .6em;"
  "text-align:left}th{background:#eee}code{background:#f4f4f4;padding:0 .2em}</style>")
a("</head><body>")
a("<h1>Hybrid ML-DSA Firmware Signing and Rollback Assessment — Results</h1>")
a("<p>Every number below is copied verbatim from the unedited logs in "
  "<code>outputs/</code>. Sources: FIPS 204 Table 2 (ML-DSA sizes), "
  "RFC 8032 §1 (Ed25519 sizes). Method, limitations, and the "
  "claim-to-evidence map: <code>docs/methodology.md</code>, "
  "<code>docs/decision-memo.md</code>, <code>docs/evidence-index.md</code>.</p>")

a("<h2>1. Sizes vs the standards</h2>")
a("<table><tr><th>Scheme</th><th>Standard</th><th>Category</th>"
  "<th>Secret key (B)</th><th>Public key (B)</th><th>Signature (B)</th>"
  "<th>Run1</th><th>Run2</th></tr>")
for scheme, (std, esk, epk, esg, cat) in SIZES.items():
    a(f"<tr><td>{scheme}</td><td>{std}</td><td>{cat if cat else '—'}</td>"
      f"<td>{esk}</td><td>{epk}</td><td>{esg}</td>"
      f"<td>{'OK' if s1[scheme] == (esk, epk, esg) else 'MISMATCH'}</td>"
      f"<td>{'OK' if s2[scheme] == (esk, epk, esg) else 'MISMATCH'}</td></tr>")
a("</table>")
a("<p>Measured sizes (run1): " +
  "; ".join(f"{s}: sk {v[0]}, pk {v[1]}, sig {v[2]}" for s, v in s1.items()) + ".</p>")

a("<h2>2. Timing, N=100, fixed 64-byte message (µs)</h2>")
a("<table><tr><th>Scheme</th><th>Op</th>"
  "<th>Run1 mean</th><th>Run1 min</th><th>Run1 max</th>"
  "<th>Run2 mean</th><th>Run2 min</th><th>Run2 max</th>"
  "<th>Verify failures</th></tr>")
for scheme in SIZES:
    for op in ("keypair", "sign", "verify"):
        r1, r2 = b1[(scheme, op)], b2[(scheme, op)]
        vf = f"{b1[(scheme, 'verify_fail')][0]}/{b1[(scheme, 'verify_fail')][1]} (run1), " \
             f"{b2[(scheme, 'verify_fail')][0]}/{b2[(scheme, 'verify_fail')][1]} (run2)" if op == "verify" else "—"
        a(f"<tr><td>{scheme}</td><td>{op}</td>"
          f"<td>{r1[1]:.2f}</td><td>{r1[2]:.2f}</td><td>{r1[3]:.2f}</td>"
          f"<td>{r2[1]:.2f}</td><td>{r2[2]:.2f}</td><td>{r2[3]:.2f}</td>"
          f"<td>{vf}</td></tr>")
a("</table>")
a("<p>Full logs: <code>outputs/bench-sig-run1.log</code>, "
  "<code>outputs/bench-sig-run2.log</code>.</p>")

a("<h2>3. Scenarios (expected vs observed)</h2>")
a("<table><tr><th>ID</th><th>Name</th><th>Expected</th><th>Run1 observed</th>"
  "<th>Run2 observed</th><th>Run1</th><th>Run2</th></tr>")
for r1, r2 in zip(sc1, sc2):
    assert r1["scenario"] == r2["scenario"] and r1["name"] == r2["name"]
    a(f"<tr><td>{r1['scenario']}</td><td>{r1['name']}</td><td>{r1['expected']}</td>"
      f"<td>{r1['observed']}</td><td>{r2['observed']}</td>"
      f"<td>{r1['result']}</td><td>{r2['result']}</td></tr>")
a("</table>")
a(f"<p>Run1: {sum(1 for r in sc1 if r['result'] == 'PASS')}/{len(sc1)} PASS; "
  f"run2: {sum(1 for r in sc2 if r['result'] == 'PASS')}/{len(sc2)} PASS. "
  "Rejection reasons are in <code>outputs/run1-scenarios.csv</code> and "
  "<code>outputs/run2-scenarios.csv</code>; full console logs: "
  "<code>outputs/scenarios-run1.log</code>, <code>outputs/scenarios-run2.log</code>.</p>")

a("<h2>4. Clean reproduction</h2>")
if compare:
    a(f"<p><code>outputs/fresh-clone-compare.txt</code>: {compare}</p>")
else:
    a("<p>No clean reproduction has been run yet for this copy of the pack; "
      "run <code>bash scripts/clean_reproduce.sh</code>.</p>")
a("<p>Reproduce everything: <code>bash scripts/build_all.sh && "
  "bash scripts/run_all.sh && bash scripts/clean_reproduce.sh</code>. "
  "Verify file integrity: <code>bash scripts/verify_digests.sh</code>.</p>")
a("</body></html>")

out_path = os.path.join(DOCS, "index.html")
with open(out_path, "w") as f:
    f.write("\n".join(html) + "\n")
print(f"make_index: wrote {out_path}")
