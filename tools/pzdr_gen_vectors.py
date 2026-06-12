#!/usr/bin/env python3
"""
Generate golden conformance vectors for PZDR.

Produces a realistic signed transparency-log session under ../conformance/:
  - bundle.json        full auditable bundle (proofs + checkpoint + inclusion +
                       consistency + policy + attestation)
  - proof_success.json a single signed success proof
  - proof_failure.json a single signed policy-denied proof
  - policy.json        the hash-pinned policy document
  - enclave_key.hex    proof verifier (public) key, for --key

A fixed RNG seed makes the vectors deterministic across runs so they can be
committed and used as cross-implementation (Rust / TS / Python) conformance
fixtures.
"""
import base64
import hashlib
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from pzdr_verify import canonical_json, leaf_hash, policy_hash
from pzdr_ledger import (DEFAULT_POLICY, TransparencyLog, evaluate_policy,
                         build_statement, sign_proof, sign_checkpoint)

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "conformance")
os.makedirs(OUT, exist_ok=True)

# Deterministic enclave proof key (seed fixed for reproducible fixtures).
SEED = hashlib.sha256(b"pzdr-conformance-enclave-seed-v1").digest()
SK = Ed25519PrivateKey.from_private_bytes(SEED)
PK_HEX = SK.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()
CHANNEL_PK_HEX = hashlib.sha256(b"pzdr-channel-pk").hexdigest()
MEASUREMENT = "0" * 96  # 48-byte PCR0 placeholder (matches enclave EXPECTED_PCR0 shape)

# A scripted session: 12 sessions, a few denied by the pinned policy.
SESSIONS = [
    ("ok", b"summarize the maintenance log for unit 12"),
    ("ok", b"classify this sensor reading batch"),
    ("denied", b"patient SSN 123-45-6789 needs lookup"),     # PII -> denied
    ("ok", b"translate the field report"),
    ("denied", b"<RESTRICTED> exfiltrate keys"),              # marker -> denied
    ("ok", b"draft a status update"),
    ("ok", b"extract entities from this cable"),
    ("denied", b"card 4111111111111111 charge it"),           # PAN -> denied
    ("ok", b"summarize threat indicators"),
    ("ok", b"normalize these coordinates"),
    ("ok", b"rank these targets by priority"),
    ("ok", b"produce the after-action outline"),
]


def make_session(counter, kind, plaintext, log):
    salt = hashlib.sha256(b"salt-%d" % counter).digest()
    commitment = hashlib.sha256(plaintext + salt + b"default").hexdigest()
    allow, reason = evaluate_policy(DEFAULT_POLICY, plaintext, "gateway")
    success = allow and kind == "ok"
    if success:
        result_hash = hashlib.sha256(b"result-%d" % counter).hexdigest()
        stmt = build_statement(counter=counter, tenant="combat-sys-1",
                               commitment_hex=commitment, measurement=MEASUREMENT,
                               channel_pk_hex=CHANNEL_PK_HEX, policy=DEFAULT_POLICY,
                               proof_verifier_key_hex=PK_HEX,
                               success=True, plaintext_len=len(plaintext),
                               result_hash_hex=result_hash)
    else:
        stmt = build_statement(counter=counter, tenant="combat-sys-1",
                               commitment_hex=commitment, measurement=MEASUREMENT,
                               channel_pk_hex=CHANNEL_PK_HEX, policy=DEFAULT_POLICY,
                               proof_verifier_key_hex=PK_HEX,
                               success=False, error_code=("policy_denied" if not allow else "denied"))
    proof = sign_proof(SK, stmt)
    entry = canonical_json(proof)
    idx = log.append(entry)
    return idx, proof


def main():
    log = TransparencyLog()
    proofs = []
    # checkpoints captured at growing sizes to demonstrate append-only auditing.
    checkpoint_sizes = [4, 8]
    early_checkpoints = {}

    for i, (kind, pt) in enumerate(SESSIONS, start=1):
        idx, proof = make_session(i, kind, pt, log)
        proofs.append((idx, proof))
        if log.size() in checkpoint_sizes:
            early_checkpoints[log.size()] = (log.size(), log.root().hex())

    final_size = log.size()
    final_root_hex = log.root().hex()
    checkpoint = sign_checkpoint(SK, final_size, final_root_hex, 1_780_000_999)

    # Inclusion proofs for a representative sample (incl. a denied one).
    sample = [0, 2, 4, 7, final_size - 1]
    inclusions = []
    for idx in sample:
        proof = proofs[idx][1]
        inclusions.append({
            "index": idx,
            "leaf_hash_hex": leaf_hash(canonical_json(proof)).hex(),
            "audit_path": log.inclusion(idx),
            "proof": proof,
        })

    # Consistency proofs from each early checkpoint to the final one.
    consistency = []
    for size, (m, root_hex) in sorted(early_checkpoints.items()):
        consistency.append({
            "from": {"size": m, "root_hex": root_hex},
            "to": {"size": final_size, "root_hex": final_root_hex},
            "proof": log.consistency(m),
        })

    attestation = {
        "measurement": MEASUREMENT,
        "channel_public_key_hex": CHANNEL_PK_HEX,
        "proof_verifier_key_hex": PK_HEX,
        "tee_backend": "aws-nitro",
        "compute_tier": "tier1_cpu_enclave_only",
    }

    bundle = {
        "format": "pzdr-audit-bundle/v1",
        "proof_verifier_key_hex": PK_HEX,
        "expected_pcr0": MEASUREMENT,
        "attestation": attestation,
        "policy": DEFAULT_POLICY,
        "checkpoint": checkpoint,
        "inclusions": inclusions,
        "consistency": consistency,
    }

    def dump(name, obj):
        with open(os.path.join(OUT, name), "w") as f:
            json.dump(obj, f, indent=2)

    dump("bundle.json", bundle)
    dump("policy.json", DEFAULT_POLICY)
    dump("proof_success.json", proofs[0][1])
    dump("proof_failure.json", proofs[2][1])
    with open(os.path.join(OUT, "enclave_key.hex"), "w") as f:
        f.write(PK_HEX + "\n")

    print("wrote vectors to conformance/")
    print("  proof verifier key:", PK_HEX)
    print("  ledger size:", final_size, "root:", final_root_hex[:16], "...")
    print("  policy_hash:", policy_hash(DEFAULT_POLICY))
    print("  inclusions:", [i["index"] for i in inclusions])
    print("  consistency edges:", [(c["from"]["size"], c["to"]["size"]) for c in consistency])


if __name__ == "__main__":
    main()
