# Hybrid ML-DSA Firmware Signing and Rollback Assessment

A runnable harness that signs release artifacts with Ed25519 **and**
ML-DSA-65 (hybrid classical + post-quantum), verifies each signature
independently, and enforces rollback protection and compromised-key
handling with a monotonic version counter, key rotation, and a
revocation list. Every measurement in this pack was produced by running
the scripts in this repository; see `docs/evidence-index.md` for the
claim-to-evidence map.

## Quick start (clean reproduction)

```sh
bash scripts/build_all.sh        # build liboqs 0.16.0 + harness binaries into ../work
bash scripts/run_all.sh          # bench (2 runs) + scenario suite (2 runs) -> outputs/
bash scripts/verify_digests.sh   # verify SHA256SUMS
bash scripts/clean_reproduce.sh  # full rebuild + rerun in a temp dir, compare headline numbers
```

Requirements: cmake, gcc, python3, OpenSSL 3.0.13. The build uses `-j2`
(the reference VM has 4 CPUs and tight RAM).

## Layout

- `scripts/` — `build_all.sh`, `run_all.sh`, `clean_reproduce.sh`,
  `compare_reproduce.py`, `verify_digests.sh`, `make_sha256sums.sh`,
  `run_scenarios.py`.
- `src/` — `bench_sig.c` (ML-DSA-44/65/87 + Ed25519 sizes vs FIPS 204
  Table 2 / RFC 8032, timing N=100), `release.c` (`genkey` / `sign` /
  `verify` hybrid release harness).
- `configs/` — release-manifest format, revocation-list format,
  monotonic version-counter policy.
- `docs/` — `methodology.md`, `decision-memo.md`, `evidence-index.md`,
  `citations.md`, `index.html` (results table, numbers match the logs).
- `fixtures/` — pinned liboqs 0.16.0 source tarball (SHA-256 verified).
- `outputs/` — unedited logs, scenario CSVs, signed artifacts and
  manifests, final state/revocation files, `fresh-clone-compare.txt`.

## Harness entry point

`scripts/run_all.sh` is the entry point: it runs the bench and the
scenario suite and writes every output under `outputs/`. The signing
harness itself is `src/release.c` (`release genkey|sign|verify`); the
measurement program is `src/bench_sig.c`.

## Headline results

See `docs/index.html` and `docs/decision-memo.md`. In brief: all three
ML-DSA parameter sets match FIPS 204 Table 2 sizes exactly; Ed25519
matches RFC 8032 (32-byte public key, 64-byte signature); the scenario
suite passes 11/11 in both runs (clean install accepts, rollback /
tampered counter / tampered payload / wrong key / truncated signatures /
revoked key all reject, rotated keys install cleanly).

## Keys

All keys are generated at runtime by the harness and live only in the
scratch work directory; they are never committed. Shipped files contain
only public keys and signatures (inside the manifests).
