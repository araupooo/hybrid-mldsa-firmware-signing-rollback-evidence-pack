# Methodology

## Question

Can a release-signing flow use one classical scheme (Ed25519) and one
post-quantum scheme (ML-DSA) side by side — each verified independently —
while also rejecting rollback attempts and handling a compromised key
through revocation and rotation? What do the signature sizes and
verification times actually cost on this machine?

## Approach

1. **Research first.** Every spec-derived number was checked against a
   primary source before any code was written (see `citations.md`):
   FIPS 204 Table 2 for ML-DSA-44/65/87 sizes, RFC 8032 §1 for Ed25519
   sizes, the NIST CSRC PQC project page for migration guidance.
2. **Pinned stack.** liboqs 0.16.0 built from the SHA-256-verified
   tarball in `fixtures/` (see `SHA256SUMS`); system OpenSSL 3.0.13.
   No network access is needed after the build.
3. **Harness, not hand-waving.** Two C programs:
   - `src/bench_sig.c` — ML-DSA via the liboqs C API (`OQS_SIG`),
     Ed25519 via OpenSSL 3 EVP; asserts sizes against FIPS 204 Table 2
     and RFC 8032, times keypair/sign/verify over N=100 iterations on a
     fixed 64-byte message, verifies every produced signature.
   - `src/release.c` — `genkey` / `sign` / `verify`. Signs a canonical
     TBS string (see `configs/manifest-format.md`) with Ed25519 and
     ML-DSA; verify checks digest, monotonic version, revocation,
     FIPS 204 §3.6.2 length checks, then each signature independently.
4. **Scenario suite.** `scripts/run_scenarios.py` drives the `release`
   binary through 11 scenarios (clean install, rollback, tampered
   version counter, tampered payload, wrong classical key, truncated
   ML-DSA signature, truncated Ed25519 signature, revoked key,
   rotation install, old artifact after rotation, revocation gate
   in isolation), each with a stated expected verdict. Two full runs
   (run1, run2) with fresh keys.
5. **Reproduction.** `scripts/clean_reproduce.sh` rebuilds everything
   from the fixtures in a throwaway directory and re-runs the suite;
   `scripts/compare_reproduce.py` checks the fresh numbers against the
   shipped ones (tolerances in that script's header). The comparison
   result is `outputs/fresh-clone-compare.txt`.

## Environment

- VM: 4 CPUs, ~483 MB free RAM at build time, Ubuntu 24.04.
- Toolchain: gcc 13.3.0, cmake 3.28.3, python3 3.12.3, OpenSSL 3.0.13.
- liboqs 0.16.0, optimized build (`OQS_OPT_TARGET=auto`), library only.
- Builds use `-j2` to stay inside the RAM budget.

## What was measured

- `outputs/bench-sig-run1.log`, `outputs/bench-sig-run2.log`:
  ML-DSA-44/65/87 and Ed25519 public-key / secret-key / signature sizes
  against the standard, plus keypair/sign/verify mean, min, max, and
  rate over 100 iterations each. Machine-readable `CSV:` lines are
  embedded in the logs.
- `outputs/run1-scenarios.csv`, `outputs/run2-scenarios.csv`:
  expected vs observed verdict and rejection reason for each of the 11
  scenarios, plus the full console logs `outputs/scenarios-run1.log`
  and `outputs/scenarios-run2.log`.
- `outputs/run1-manifest-v*.json` and `outputs/run1-firmware-v*.bin`:
  the signed artifacts and manifests from run1 (public keys and
  signatures only; no secret keys). The same set exists for run2.

## Design decisions

- **Pure ML-DSA, not HashML-DSA.** FIPS 204 §5.4 states the pure
  version is preferred; the harness signs the TBS bytes directly.
  The artifact itself is hashed (SHA-256) into the TBS, so the signed
  data stays small and constant-size regardless of artifact size.
- **ML-DSA-65 as the release default.** Category 3 matches the
  classical ~128-bit level of Ed25519 (RFC 8032 §1) while keeping
  signatures at 3309 bytes rather than 4627 (ML-DSA-87). The bench
  covers all three parameter sets so the trade-off is measured, not
  assumed. See `decision-memo.md`.
- **Independent verification.** Each signature is verified on its own
  against the same TBS; a failure in either one rejects the release.
  Neither scheme's validity is inferred from the other.
- **Version check before revocation check.** The verifier gates on
  rollback first, then revocation (see `configs/manifest-format.md`).
  Scenarios that test a later gate reset the installed version to 1
  first (S5–S7, S8) or use a separate state file at version 1 (S10b),
  so that the gate under test — not the rollback gate — is what
  rejects the release; each reset is printed in the log.
- **Keys are runtime-only.** Every run generates fresh key pairs in
  the scratch work directory. Secret keys are never written into the
  pack, never committed, and never appear in any log (only public-key
  fingerprints are printed).

## Limitations

- **L1 — Single machine, single build.** All timings are from one VM
  (4 CPUs, shared host). Absolute microsecond figures are not portable;
  the size figures and the relative ordering of schemes are. The
  clean-reproduction run re-measures on the same class of machine.
- **L2 — Keypair mean is warm-up sensitive.** The first keypair call
  in a process can be much slower (RNG / library warm-up). The
  comparison script therefore checks the keypair *min* within 25% and
  the mean only within 2x; sign/verify means are checked within 25%.
- **L3 — No hardware security module.** Keys are plain files in a
  scratch directory. The harness demonstrates the signing and
  verification logic; it does not demonstrate secure key storage.
  A production deployment must hold signing keys in an HSM or
  equivalent and keep the verifier state file tamper-evident.
- **L4 — No on-device install tested.** The verifier logic (digest,
  version, revocation, signatures) is exercised end to end, but no
  actual firmware was flashed onto a device and no bootloader was
  involved. The "install" here is the state-file update on ACCEPT.
- **L5 — State-file protection is out of scope.** If the verifier's
  state file is deleted or rolled back, an older signed release would
  be accepted again. Protecting that state is a deployment
  requirement; see `configs/version-policy.md`.
- **L6 — Ed25519 only as the classical side.** ECDSA P-256/P-384 were
  not measured; Ed25519 was chosen because RFC 8032 gives fixed
  sizes (32/64 bytes) and OpenSSL 3 supports it natively without extra
  dependencies. The harness structure accepts a second classical
  scheme, but that measurement was not run.
- **L7 — Timing is wall-clock, not cycle-counted.** No CPU pinning or
  isolation was applied; background load on the shared host can shift
  means between runs. The 25% comparison tolerance accounts for this.
  This actually happened during this pack: the first clean
  reproduction failed 5 bench checks because the shipped run2 was
  systematically slow (host load), and a re-measurement passed all
  checks (see `outputs/run-manifest.md`).
