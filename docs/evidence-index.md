# Evidence index

Every claim in this pack maps to a runnable script and its unedited
output. "Shipped" files are the run1/run2 outputs; "fresh-clone-*"
files are the independent clean reproduction
(`scripts/clean_reproduce.sh`, comparison in
`outputs/fresh-clone-compare.txt`).

## C1 — ML-DSA sizes match FIPS 204 Table 2

- **Claim.** ML-DSA-44: sk 2560, pk 1312, sig 2420. ML-DSA-65: sk 4032,
  pk 1952, sig 3309. ML-DSA-87: sk 4896, pk 2592, sig 4627.
- **Source.** FIPS 204 §4, Table 2 (`docs/citations.md`).
- **Evidence.** `outputs/bench-sig-run1.log`,
  `outputs/bench-sig-run2.log` — every size line ends `OK`
  (12 size lines plus 4 `sizes+roundtrip: OK` lines per log,
  0 `MISMATCH`).
  Reproduction: `outputs/fresh-clone-bench-sig-run1.log`,
  `outputs/fresh-clone-bench-sig-run2.log`.
- **Reproduce.** `bash scripts/build_all.sh && ./work/bench_sig 100`
  (binary `src/bench_sig.c`).

## C2 — Ed25519 sizes match RFC 8032

- **Claim.** Ed25519 public key 32 bytes, signature 64 bytes.
- **Source.** RFC 8032 §1 (`docs/citations.md`).
- **Evidence.** Same bench logs as C1: `public_key=32 bytes ... OK`,
  `signature=64 bytes ... OK`, 0 verify failures in 100 iterations
  per scheme per run.
- **Reproduce.** Same as C1.

## C3 — ML-DSA / Ed25519 timing (N=100, fixed 64-byte message)

- **Claim.** Mean sign/verify times per scheme (µs), averaged over
  run1 and run2 — see the table in `docs/decision-memo.md`
  (Ed25519 sign 57.2 / verify 150.0; ML-DSA-44 sign 111.8 / verify
  36.3; ML-DSA-65 sign 167.6 / verify 60.0; ML-DSA-87 sign 201.4 /
  verify 92.3).
- **Evidence.** `CSV:` lines in `outputs/bench-sig-run1.log` and
  `outputs/bench-sig-run2.log`; reproduction logs as in C1.
  Comparison tolerances (sign/verify means within 25%) are checked
  by `scripts/compare_reproduce.py`, result in
  `outputs/fresh-clone-compare.txt`.
- **Reproduce.** Same as C1.

## C4 — Hybrid signing and independent verification

- **Claim.** A release artifact can be signed with Ed25519 and
  ML-DSA-65 over the same canonical TBS, and each signature verifies
  independently of the other.
- **Evidence.** `outputs/run1-manifest-v2.json` (signed artifact
  `outputs/run1-firmware-v2.bin`, 64 KiB) and scenario S1 in
  `outputs/scenarios-run1.log` / `outputs/run1-scenarios.csv`:
  `VERDICT: ACCEPT`, both signatures `VALID`. Same for run2.
- **Reproduce.** `bash scripts/run_all.sh` (drives
  `scripts/run_scenarios.py`, which calls `src/release.c`).

## C5 — Rollback rejection

- **Claim.** Installing version 1 after version 2 is installed is
  rejected; the old artifact is still rejected after key rotation.
- **Evidence.** Scenarios S2 and S10 in `outputs/scenarios-run*.log`
  and `outputs/run*-scenarios.csv` (both runs PASS).
- **Reproduce.** Same as C4.

## C6 — Tampered version counter and tampered payload

- **Claim.** Editing the manifest `version` after signing is
  rejected (signature failure); flipping one payload byte is
  rejected (digest mismatch).
- **Evidence.** Scenarios S3 and S4 in the scenario logs/CSVs
  (both runs PASS).
- **Reproduce.** Same as C4.

## C7 — Wrong key and truncated signatures

- **Claim.** Verifying against a different classical public key is
  rejected; truncating either signature by one byte is rejected by
  the FIPS 204 §3.6.2 length checks.
- **Evidence.** Scenarios S5, S6, S7 in the scenario logs/CSVs
  (both runs PASS). S5–S7 reset the installed version to 1 first so
  the signature/length gate — not the rollback gate — rejects;
  the reset is printed in the logs (see `docs/methodology.md`).
- **Reproduce.** Same as C4.

## C8 — Compromised-key handling: revocation and rotation

- **Claim.** A manifest signed by a revoked key is rejected; signing
  the next version with fresh key ids installs cleanly; the old
  artifact stays rejected after rotation.
- **Evidence.** Scenarios S8, S9, S10, S10b in the scenario
  logs/CSVs (both runs PASS); final revocation list
  `outputs/run1-revocation-final.txt` (contains `mldsa65-rel-a`);
  final state `outputs/run1-state-final.txt` (`version=3`).
- **Reproduce.** Same as C4.

## C9 — Clean reproduction matches shipped numbers

- **Claim.** A fresh build from the pinned fixtures reproduces the
  shipped headline numbers within tolerance, and all 11 scenarios
  pass again.
- **Evidence.** `outputs/fresh-clone-compare.txt`
  (`COMPARISON: ALL CHECKS PASSED`), plus
  `outputs/fresh-clone-bench-sig-run*.log` and
  `outputs/fresh-clone-run*-scenarios.csv`.
- **Reproduce.** `bash scripts/clean_reproduce.sh`.

## C10 — No secret keys in the pack

- **Claim.** No secret key material is present in any shipped file.
- **Evidence.** Shipped manifests contain public keys and signatures
  only; `grep` the pack for `.sk` files: none. Secret keys live only
  in the scratch work directory (`work/scenarios-run*`), which is
  outside the pack and never published, and are regenerated on every
  run. Verify with `find pack -name '*.sk'` (empty) and
  `bash scripts/verify_digests.sh`.
