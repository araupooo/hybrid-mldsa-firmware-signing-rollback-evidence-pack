# Decision memo — hybrid firmware and release signing

## Recommendation

**Adopt hybrid signing for releases: Ed25519 + ML-DSA-65, both signatures
over the same canonical manifest, each verified independently; enforce a
monotonic version counter and a revocation list on the verifier.**

- Classical side: Ed25519 (RFC 8032) — 32-byte public key, 64-byte
  signature, ~128-bit classical security.
- Post-quantum side: ML-DSA-65 (FIPS 204, category 3) — 1952-byte
  public key, 3309-byte signature.
- Combined per-release signature payload: 3373 bytes (3309 + 64);
  combined public keys: 1984 bytes (1952 + 32). A complete signed
  manifest for a 64 KiB artifact is 7608 bytes (`outputs/run1-manifest-v2.json`).

## Why hybrid, why these two

1. **The classical scheme alone will not survive a large-scale quantum
   computer.** RFC 8032 §1 states plainly that a sufficiently large
   quantum computer would break Ed25519. NIST's PQC project page says
   the three 2024 PQC standards "can and should be put into use now"
   and that quantum-vulnerable algorithms will be deprecated and
   removed by 2035 under the NIST IR 8547 timeline. Signing with
   Ed25519 alone is a bet that no such computer appears during the
   lifetime of the signed releases.
2. **The post-quantum scheme alone is new.** ML-DSA was standardised
   in August 2024. Keeping Ed25519 alongside it means a break in
   either one — classical or post-quantum — does not by itself forge
   a release: both signatures must verify. The harness verifies each
   independently (scenarios S5–S7 show a failure in either one
   rejects the release).
3. **ML-DSA-65, not -44 or -87.** Category 3 matches the classical
   strength level Ed25519 is designed for (~128-bit, RFC 8032 §1),
   while ML-DSA-44 (category 2) is a step below that level and
   ML-DSA-87 (category 5) costs 4627-byte signatures and ~54% more
   verification time for strength the release flow does not need.
   Measured on this machine (N=100, means across run1/run2):

   | Scheme | pk (B) | sig (B) | sign mean (µs) | verify mean (µs) |
   |---|---|---|---|---|
   | Ed25519 | 32 | 64 | 57.2 | 150.0 |
   | ML-DSA-44 | 1312 | 2420 | 111.8 | 36.3 |
   | ML-DSA-65 | 1952 | 3309 | 167.6 | 60.0 |
   | ML-DSA-87 | 2592 | 4627 | 201.4 | 92.3 |

   Full numbers (mean/min/max, both runs) are in
   `outputs/bench-sig-run1.log` and `outputs/bench-sig-run2.log`;
   the sizes match FIPS 204 Table 2 and RFC 8032 §1 exactly in every
   run. Note the counter-intuitive result that Ed25519 verification
   (~150 µs) measured slower than ML-DSA-65 verification (~60 µs)
   here — that is the OpenSSL EVP call overhead on this VM versus
   the optimised liboqs build, not a property of the mathematics;
   either way, verification of both signatures costs ~210 µs per
   release, negligible against any real install step.
4. **Pure ML-DSA, not HashML-DSA.** FIPS 204 §5.4 prefers the pure
   version. The harness signs a short canonical TBS string that
   already contains the artifact's SHA-256, so artifact size never
   affects signing cost.

## What was demonstrated (all executed, 11/11 scenarios PASS in both runs)

- Clean install of a hybrid-signed release accepts (S1); the same
  flow under rotated keys accepts (S9).
- Rollback is rejected: version 1 after version 2 installed (S2);
  the old artifact is still rejected after rotation (S10).
- A tampered version counter is rejected — the version is covered
  by both signatures, so editing it invalidates them (S3).
- A tampered payload is rejected by the digest check (S4).
- A wrong classical public key is rejected by signature
  verification (S5); truncated signatures are rejected by the
  FIPS 204 §3.6.2 length checks (S6, S7).
- A revoked key is rejected (S8, S10b), and rotation to new key ids
  restores clean installs (S9).

Evidence: `outputs/run1-scenarios.csv`, `outputs/run2-scenarios.csv`,
`outputs/scenarios-run1.log`, `outputs/scenarios-run2.log`.

## What this does not claim

- No HSM or secure key storage was used or tested (limitation L3);
  signing keys here are plain files in a scratch directory.
- No firmware was flashed and no bootloader was involved (L4); the
  "install" is the verifier's state-file update on ACCEPT.
- The verifier state file must itself be protected against deletion
  or rollback, or an old signed release would be accepted again
  (L5). This is a deployment requirement, not a harness property.
- ECDSA P-256/P-384 were not measured (L6); Ed25519 was chosen for
  its fixed sizes and native OpenSSL 3 support.

## Migration note

Ship the hybrid manifest format now, with both signatures required.
When confidence in ML-DSA alone is sufficient (validated
implementations, wider ecosystem support), the classical signature
can be dropped by a format revision — the manifest already carries
per-scheme fields, so no verifier rewrite is needed. Do not drop
Ed25519 while any supported verifier cannot check ML-DSA.
