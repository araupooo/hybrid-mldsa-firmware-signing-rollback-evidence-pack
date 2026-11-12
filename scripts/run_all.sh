#!/bin/bash
# run_all.sh — run the full measurement suite for this assessment and write
# every output under pack/outputs/:
#   1. bench_sig (ML-DSA-44/65/87 + Ed25519 sizes vs FIPS 204 Table 2 /
#      RFC 8032, timing, N=100) — run1 + run2
#   2. scenario suite (rollback, tampered counter/payload, wrong key,
#      truncated signatures, revocation, rotation) — run1 + run2
# Usage: run_all.sh [workdir] [log-prefix]
# workdir defaults to <task>/work. log-prefix (default "") is prepended to
# every output filename; scripts/clean_reproduce.sh passes "fresh-clone-"
# so a reproduction run never overwrites the shipped outputs.
set -u
PACK="$(cd "$(dirname "$0")/.." && pwd)"
WORK="${1:-$PACK/../work}"
PREFIX="${2:-}"
OUT="$PACK/outputs"
mkdir -p "$OUT"

[ -f "$WORK/bench_sig" ] || { echo "FATAL: bench_sig missing (run scripts/build_all.sh first)"; exit 1; }
[ -f "$WORK/release" ] || { echo "FATAL: release missing (run scripts/build_all.sh first)"; exit 1; }

echo "run_all: work=$WORK out=$OUT prefix=$PREFIX"
echo "run_all: date $(date -u '+%Y-%m-%d %H:%M:%S UTC')"

echo "=== bench_sig run1 ==="
"$WORK/bench_sig" 100 > "$OUT/${PREFIX}bench-sig-run1.log" 2>&1
echo "=== bench_sig run2 ==="
"$WORK/bench_sig" 100 > "$OUT/${PREFIX}bench-sig-run2.log" 2>&1

echo "=== scenarios run1 ==="
python3 "$PACK/scripts/run_scenarios.py" "$WORK/release" "$WORK/scenarios-${PREFIX}run1" "${PREFIX}run1" "$OUT" \
  > "$OUT/${PREFIX}scenarios-run1.log" 2>&1 || echo "run_all: WARNING scenarios run1 exited non-zero (see log)"
echo "=== scenarios run2 ==="
python3 "$PACK/scripts/run_scenarios.py" "$WORK/release" "$WORK/scenarios-${PREFIX}run2" "${PREFIX}run2" "$OUT" \
  > "$OUT/${PREFIX}scenarios-run2.log" 2>&1 || echo "run_all: WARNING scenarios run2 exited non-zero (see log)"

echo "run_all: DONE — outputs in $OUT"
ls -l "$OUT"
