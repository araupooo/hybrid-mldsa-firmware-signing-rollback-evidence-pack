# Citations

Primary sources only. Every spec claim in this pack traces to one of
these; measured claims trace to the logs listed in `evidence-index.md`.

## ML-DSA

- **FIPS 204 — Module-Lattice-Based Digital Signature Standard**
  (NIST, 13 Aug 2024). https://csrc.nist.gov/pubs/fips/204/final
  (DOI: https://doi.org/10.6028/NIST.FIPS.204)
  - §4, Table 2: sizes in bytes — ML-DSA-44: private key 2560,
    public key 1312, signature 2420; ML-DSA-65: 4032 / 1952 / 3309;
    ML-DSA-87: 4896 / 2592 / 4627. Security strength categories 2 / 3 / 5.
    Verified against the liboqs implementation in
    `outputs/bench-sig-run*.log` (see `evidence-index.md` C1).
  - §3.6.2 (public-key and signature length checks): the basis for the
    length gate in `release verify`.
  - §5.2 (ML-DSA.Sign): signing takes a private key, a message, and a
    context string; the default hedged variant generates a 32-byte
    random value. The harness signs the TBS bytes with the default
    variant and an empty context.
  - §5.4 (pre-hash ML-DSA): "In general, the 'pure' ML-DSA version is
    preferred." The harness therefore signs the TBS directly rather
    than using HashML-DSA; the artifact digest is part of the TBS.
  - §5.3 (ML-DSA.Verify): verification outputs a Boolean, true only
    if the signature is valid for the message and public key.

## Classical signatures

- **RFC 8032 — Edwards-Curve Digital Signature Algorithm (EdDSA)**
  (Josefsson & Liusvaara, IRTF, Jan 2017).
  https://datatracker.ietf.org/doc/html/rfc8032
  - §1: "EdDSA uses small public keys (32 or 57 bytes) and signatures
    (64 or 114 bytes) for Ed25519 and Ed448, respectively"; Ed25519 is
    intended for around the 128-bit security level; "A sufficiently
    large quantum computer would be able to break both."
    Verified against the OpenSSL EVP implementation in
    `outputs/bench-sig-run*.log` (see `evidence-index.md` C2).

## Migration guidance

- **NIST CSRC — Post-Quantum Cryptography project page.**
  https://csrc.nist.gov/projects/post-quantum-cryptography
  - "NIST released the principal three PQC standards in 2024";
    "Organizations should begin applying these standards now to
    migrate their systems to quantum-resistant cryptography."
  - "NIST expects that the two digital signature standards (ML-DSA
    and SLH-DSA) and key-encapsulation mechanism standard (ML-KEM)
    will provide the foundation for most deployments of post-quantum
    cryptography. They can and should be put into use now."
  - Transition timeline (NIST IR 8547): quantum-vulnerable algorithms
    deprecated and ultimately removed from NIST standards by 2035,
    "with high-risk systems transitioning much earlier."

## Implementations

- **liboqs 0.16.0** — https://github.com/open-quantum-safe/liboqs —
  the library implementing ML-DSA. Version string printed in
  `outputs/bench-sig-run*.log` (`liboqs version: 0.16.0`). Parameter
  table in the pinned source tree
  (`docs/algorithms/sig/ml_dsa.md`) matches FIPS 204 Table 2 exactly.
- **OpenSSL 3.0.13** — https://www.openssl.org/ — the EVP API used
  for Ed25519 key generation, signing, and verification, and for
  SHA-256 artifact digests. Version string printed in the bench logs.

## Notes on sources

- FIPS 204, RFC 8032, and the NIST CSRC PQC page were fetched and read
  during research for this pack (12 Nov 2026). The FIPS 204 Table 2
  figures were confirmed both in the standard and independently by the
  measured liboqs sizes in this pack.
- No secondary sources (blogs, vendor pages, summaries) are cited for
  any claim in this pack.
