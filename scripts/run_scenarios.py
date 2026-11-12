#!/usr/bin/env python3
"""run_scenarios.py — rollback / compromised-key / negative-control scenarios
for the hybrid release-signing harness.

Usage: run_scenarios.py <release-bin> <workdir> <run-label> <outdir>
  release-bin : path to the compiled `release` binary
  workdir     : scratch dir for keys/state (runtime keys, never shipped)
  run-label   : e.g. "run1" (used in log lines and shipped filenames)
  outdir      : pack outputs dir; receives the scenario CSV, shipped
                artifacts/manifests, final state and revocation files.

Every scenario prints one line:
  SCENARIO <id> <name> EXPECTED=<x> OBSERVED=<y> RESULT=PASS|FAIL
and appends a row to <outdir>/<run-label>-scenarios.csv.
Exit code 0 iff every scenario's observed verdict matches its expected one.

Deterministic artifacts: firmware-v1/v2/v3.bin are 64 KiB of fixed
byte patterns (no randomness in the artifact content). Keys are generated
fresh per run by the harness (randomness comes from the OS/liboqs RNG);
only public keys and signatures appear in shipped files.

Check order inside `release verify` (see src/release.c): digest ->
monotonic version -> revocation -> length checks -> both signatures.
Scenarios S5-S7 and S10b reset the installed version to 1 first (or use
a separate state file at version 1), so the version gate passes and the
check under test — not the rollback gate — is what rejects the release;
each reset is logged.
"""
import base64
import csv
import json
import os
import shutil
import subprocess
import sys

RELEASE, WORK, LABEL, OUT = sys.argv[1:5]
os.makedirs(WORK, exist_ok=True)
os.makedirs(OUT, exist_ok=True)

# Scrub the absolute task-root prefix from everything this driver prints,
# so the shipped (unedited) logs never contain local filesystem paths:
# the task folder name carries an identifier that must not be published.
TASKROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def scrub(s):
    return s.replace(TASKROOT, ".")

KEYDIR = os.path.join(WORK, "keys")
os.makedirs(KEYDIR, exist_ok=True)
STATE = os.path.join(WORK, "state.txt")
REVOC = os.path.join(WORK, "revocation.txt")

results = []  # (id, name, expected, observed, reason, pass)


def run(args, expect_rc=None):
    p = subprocess.run(args, capture_output=True, text=True)
    print("$ " + scrub(" ".join(args)))
    print(scrub(p.stdout), end="")
    if p.stderr:
        print(scrub(p.stderr), end="")
    print(f"[exit {p.returncode}]")
    return p


def scenario(sid, name, expected, observed, reason):
    ok = expected == observed
    results.append((sid, name, expected, observed, reason, ok))
    print(f"SCENARIO {sid} {name} EXPECTED={expected} OBSERVED={observed} "
          f"REASON={reason} RESULT={'PASS' if ok else 'FAIL'}")
    return ok


def verdict(p):
    for line in p.stdout.splitlines():
        if line.startswith("VERDICT:"):
            return line.split(":", 1)[1].strip()
    return f"NO-VERDICT(exit {p.returncode})"


def reason(p):
    for line in p.stdout.splitlines():
        if line.startswith("REASON:"):
            return line.split(":", 1)[1].strip()
    return ""


def write_artifact(path, seed):
    with open(path, "wb") as f:
        f.write(bytes(((i * seed + 1) % 256) for i in range(65536)))


def load_manifest(path):
    with open(path) as f:
        return json.load(f)


def save_manifest(m, path):
    with open(path, "w") as f:
        json.dump(m, f, indent=2)
        f.write("\n")


def trunc_b64(b64, nbytes=1):
    raw = base64.b64decode(b64)
    return base64.b64encode(raw[:-nbytes]).decode()


print(f"run_scenarios: label={LABEL} release={scrub(RELEASE)} work={scrub(WORK)} out={scrub(OUT)}")
print(f"run_scenarios: check order in verify: digest -> version -> revocation -> lengths -> signatures")

# --- deterministic artifacts ---
art1 = os.path.join(WORK, "firmware-v1.bin")
art2 = os.path.join(WORK, "firmware-v2.bin")
art3 = os.path.join(WORK, "firmware-v3.bin")
write_artifact(art1, 7)
write_artifact(art2, 13)
write_artifact(art3, 29)
print(f"artifacts: v1={scrub(art1)} v2={scrub(art2)} v3={scrub(art3)} (64 KiB deterministic patterns)")

# --- keys (runtime-generated, never shipped) ---
run([RELEASE, "genkey", "Ed25519", "ed25519-rel-a", KEYDIR])
run([RELEASE, "genkey", "ML-DSA-65", "mldsa65-rel-a", KEYDIR])
run([RELEASE, "genkey", "Ed25519", "ed25519-rel-b", KEYDIR])
run([RELEASE, "genkey", "ML-DSA-65", "mldsa65-rel-b", KEYDIR])
run([RELEASE, "genkey", "Ed25519", "ed25519-rel-c", KEYDIR])  # wrong-key control

# --- manifests v1, v2 ---
man1 = os.path.join(WORK, "manifest-v1.json")
man2 = os.path.join(WORK, "manifest-v2.json")
run([RELEASE, "sign", art1, "1", "ed25519-rel-a", KEYDIR, "ML-DSA-65", "mldsa65-rel-a", KEYDIR, man1])
run([RELEASE, "sign", art2, "2", "ed25519-rel-a", KEYDIR, "ML-DSA-65", "mldsa65-rel-a", KEYDIR, man2])

# --- empty revocation list, fresh state ---
open(REVOC, "w").write("# revocation list: one key id per line\n")
if os.path.exists(STATE):
    os.remove(STATE)

# S1: clean install of v2 -> ACCEPT
p = run([RELEASE, "verify", man2, art2, STATE, REVOC])
scenario("S1", "clean-install-v2", "ACCEPT", verdict(p), reason(p))

# S2: rollback — install v1 after v2 is installed -> REJECT
p = run([RELEASE, "verify", man1, art1, STATE, REVOC])
scenario("S2", "rollback-v1-after-v2", "REJECT", verdict(p), reason(p))

# S3: tampered version counter — v2 manifest with version 99, not re-signed -> REJECT
m = load_manifest(man2)
m["version"] = 99
man2_v99 = os.path.join(WORK, "manifest-v2-version99.json")
save_manifest(m, man2_v99)
p = run([RELEASE, "verify", man2_v99, art2, STATE, REVOC])
scenario("S3", "tampered-version-counter-99", "REJECT", verdict(p), reason(p))

# S4: tampered payload — one byte flipped in the artifact -> REJECT
art2_tampered = os.path.join(WORK, "firmware-v2-tampered.bin")
shutil.copyfile(art2, art2_tampered)
with open(art2_tampered, "r+b") as f:
    f.seek(12345)
    b = f.read(1)
    f.seek(12345)
    f.write(bytes([b[0] ^ 0xFF]))
p = run([RELEASE, "verify", man2, art2_tampered, STATE, REVOC])
scenario("S4", "tampered-payload-byteflip", "REJECT", verdict(p), reason(p))

# S5: wrong classical key — manifest with another Ed25519 public key -> REJECT.
# Reset installed version to 1 first so the version gate passes and the
# signature check — not the rollback gate — is what rejects the release.
with open(STATE, "w") as f:
    f.write("version=1\n")
print("S5-S7: state reset to version=1 to isolate the signature checks from the rollback check")
m = load_manifest(man2)
with open(os.path.join(KEYDIR, "ed25519-rel-c.pk"), "rb") as f:
    wrong_pk = base64.b64encode(f.read()).decode()
m["classical_public_key_b64"] = wrong_pk
man2_wrongkey = os.path.join(WORK, "manifest-v2-wrongkey.json")
save_manifest(m, man2_wrongkey)
p = run([RELEASE, "verify", man2_wrongkey, art2, STATE, REVOC])
scenario("S5", "wrong-classical-public-key", "REJECT", verdict(p), reason(p))

# S6: truncated ML-DSA signature -> REJECT
m = load_manifest(man2)
m["pq_signature_b64"] = trunc_b64(m["pq_signature_b64"])
man2_truncpq = os.path.join(WORK, "manifest-v2-trunc-pq.json")
save_manifest(m, man2_truncpq)
p = run([RELEASE, "verify", man2_truncpq, art2, STATE, REVOC])
scenario("S6", "truncated-mldsa-signature", "REJECT", verdict(p), reason(p))

# S7: truncated Ed25519 signature -> REJECT
m = load_manifest(man2)
m["classical_signature_b64"] = trunc_b64(m["classical_signature_b64"])
man2_trunced = os.path.join(WORK, "manifest-v2-trunc-ed.json")
save_manifest(m, man2_trunced)
p = run([RELEASE, "verify", man2_trunced, art2, STATE, REVOC])
scenario("S7", "truncated-ed25519-signature", "REJECT", verdict(p), reason(p))

# S8: compromised key — revoke mldsa65-rel-a; reset installed version to 1
# so the revocation check (not the rollback check) is the rejecting gate.
with open(STATE, "w") as f:
    f.write("version=1\n")
print("S8: state reset to version=1 to isolate the revocation check from the rollback check")
with open(REVOC, "a") as f:
    f.write("mldsa65-rel-a\n")
p = run([RELEASE, "verify", man2, art2, STATE, REVOC])
scenario("S8", "revoked-pq-key-v2", "REJECT", verdict(p), reason(p))

# S9: key rotation — new key ids, sign v3, verify -> ACCEPT
man3 = os.path.join(WORK, "manifest-v3.json")
run([RELEASE, "sign", art3, "3", "ed25519-rel-b", KEYDIR, "ML-DSA-65", "mldsa65-rel-b", KEYDIR, man3])
p = run([RELEASE, "verify", man3, art3, STATE, REVOC])
scenario("S9", "rotated-keys-install-v3", "ACCEPT", verdict(p), reason(p))

# S10: old artifact signed by the revoked key, after rotation -> REJECT
p = run([RELEASE, "verify", man2, art2, STATE, REVOC])
scenario("S10", "old-artifact-revoked-key-after-rotation", "REJECT", verdict(p), reason(p))

# S10b: the same old artifact, but with a state file at version 1 so the
# version gate passes and the revocation gate is what rejects it. Uses a
# separate state file so the shipped final state still records version 3.
state_s10b = os.path.join(WORK, "state-s10b.txt")
with open(state_s10b, "w") as f:
    f.write("version=1\n")
print("S10b: separate state file at version=1 to isolate the revocation check from the rollback check")
p = run([RELEASE, "verify", man2, art2, state_s10b, REVOC])
scenario("S10b", "old-artifact-revocation-gate", "REJECT", verdict(p), reason(p))

# --- ship evidence (public keys/signatures only; secret keys stay in WORK) ---
for src, dst in (
    (art1, f"{LABEL}-firmware-v1.bin"),
    (art2, f"{LABEL}-firmware-v2.bin"),
    (art3, f"{LABEL}-firmware-v3.bin"),
    (man1, f"{LABEL}-manifest-v1.json"),
    (man2, f"{LABEL}-manifest-v2.json"),
    (man3, f"{LABEL}-manifest-v3.json"),
    (REVOC, f"{LABEL}-revocation-final.txt"),
    (STATE, f"{LABEL}-state-final.txt"),
):
    shutil.copyfile(src, os.path.join(OUT, dst))
    print(f"shipped: {dst}")

csv_path = os.path.join(OUT, f"{LABEL}-scenarios.csv")
with open(csv_path, "w", newline="") as f:
    w = csv.writer(f)
    w.writerow(["scenario", "name", "expected", "observed", "reason", "result"])
    for r in results:
        w.writerow([r[0], r[1], r[2], r[3], r[4], "PASS" if r[5] else "FAIL"])
print(f"scenarios csv: {scrub(csv_path)}")

npass = sum(1 for r in results if r[5])
print(f"run_scenarios: {npass}/{len(results)} scenarios PASS")
print(f"run_scenarios: {'DONE' if npass == len(results) else 'FAIL'}")
sys.exit(0 if npass == len(results) else 1)
