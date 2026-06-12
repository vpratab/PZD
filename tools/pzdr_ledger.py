#!/usr/bin/env python3
"""
PZDR reference ledger + policy engine (pure Python).

This is the executable specification the Rust enclave (`services/pzdr-enclave`)
and the TypeScript SDK conform to. It mirrors, byte-for-byte, the canonical-JSON
signing rules and the RFC 6962 transparency-log hashing in pzdr_verify.py, and it
is what generates the golden conformance vectors.

Nothing here touches AWS or a real enclave; it models the in-enclave logic so the
proof/receipt/checkpoint format can be tested and audited offline.
"""
from __future__ import annotations

import json
import re

from pzdr_verify import (canonical_json, leaf_hash, merkle_root, inclusion_path,
                         consistency_path, policy_hash)


# --------------------------------------------------------------------------- #
# Hash-pinned policy engine
# --------------------------------------------------------------------------- #
# The published policy document is hashed (sha256 over canonical JSON) and that
# hash is recorded in every proof's policy_decision. An auditor re-hashes the
# policy they were given and confirms it matches — so the rules the gateway
# claims to enforce are pinned and non-repudiable.
DEFAULT_POLICY = {
    "policy_id": "pzdr-default",
    "policy_version": 1,
    "default": "deny",
    "max_input_bytes": 100_000,
    "deny_markers": ["<RESTRICTED"],
    # Regexes that, if present in plaintext, force a policy_denied failure. These
    # run INSIDE the enclave on plaintext; the auditor never sees the plaintext,
    # only the pinned ruleset and the recorded decision.
    "deny_patterns_pii": [
        r"\b\d{3}-\d{2}-\d{4}\b",                 # US SSN
        r"\b\d{16}\b",                            # bare PAN
    ],
    "allowed_processors": ["gateway"],
}


def evaluate_policy(policy: dict, plaintext: bytes, processor: str):
    """Return (allow: bool, reason: str). Default-deny contract."""
    if processor not in policy.get("allowed_processors", []):
        return False, "processor_not_allowed"
    if len(plaintext) > policy.get("max_input_bytes", 1 << 30):
        return False, "input_too_large"
    text = plaintext.decode("utf-8", "ignore")
    for marker in policy.get("deny_markers", []):
        if marker in text:
            return False, "restricted_marker"
    for pat in policy.get("deny_patterns_pii", []):
        if re.search(pat, text):
            return False, "pii_detected"
    return True, "allow"


# --------------------------------------------------------------------------- #
# Transparency log (append-only, RFC 6962)
# --------------------------------------------------------------------------- #
class TransparencyLog:
    def __init__(self):
        self.entries = []      # entry_bytes
        self.leaves = []       # leaf hashes

    def append(self, entry_bytes: bytes) -> int:
        idx = len(self.entries)
        self.entries.append(entry_bytes)
        self.leaves.append(leaf_hash(entry_bytes))
        return idx

    def size(self):
        return len(self.leaves)

    def root(self):
        return merkle_root(self.leaves)

    def inclusion(self, idx):
        return [h.hex() for h in inclusion_path(self.leaves, idx)]

    def consistency(self, m):
        return [h.hex() for h in consistency_path(self.leaves, m)]


# --------------------------------------------------------------------------- #
# Proof construction (mirrors services/pzdr-enclave/src/main.rs ProofStatement)
# --------------------------------------------------------------------------- #
def build_statement(*, counter, tenant, commitment_hex, measurement,
                    channel_pk_hex, policy, success, proof_verifier_key_hex=None,
                    plaintext_len=0,
                    result_hash_hex=None, error_code=None, timestamp=1_780_000_000):
    ph = policy_hash(policy)
    if success:
        decision = {"allow": True, "reason": "allowed", "policy_id": policy["policy_id"],
                    "policy_version": policy["policy_version"], "policy_hash": ph,
                    "tenant": tenant, "processor": "gateway"}
        zeroization = {"input_buffer_wiped": True, "response_buffer_wiped": False,
                       "response_buffer_returned": True}
        gov = {"retention_policy": "returned-only", "expires_at": timestamp}
    else:
        decision = {"allow": False, "reason": error_code, "policy_id": policy["policy_id"],
                    "policy_version": policy["policy_version"], "policy_hash": ph,
                    "tenant": tenant, "processor": "gateway"}
        zeroization = {"input_buffer_wiped": True, "response_buffer_wiped": False,
                       "response_buffer_returned": False}
        gov = {}
    return {
        "proof_id": "%032x" % (counter * 2654435761 & (1 << 128) - 1),
        "proof_version": 3,
        "schema_url": "pzdr://proof/v3",
        "session_id": "%016x" % (counter * 40503 & (1 << 64) - 1),
        "tenant_id": tenant,
        "counter": counter,
        "timestamp": timestamp + counter,
        "commitment_hex": commitment_hex,
        "processor_id": "gateway",
        "upstream_model": "mock-claude-sonnet-4.5" if success else None,
        "upstream_tokens_in": (plaintext_len // 4) if success else None,
        "upstream_tokens_out": 16 if success else None,
        "measurement": measurement,
        "channel_public_key_hex": channel_pk_hex,
        "proof_verifier_key_hex": proof_verifier_key_hex,
        "tee_backend": "aws-nitro",
        "compute_tier": "tier1_cpu_enclave_only",
        "proof_mode": "attestation",
        "success": success,
        "error_code": error_code,
        "policy_decision": decision,
        "zeroization_report": zeroization,
        "result_hash_hex": result_hash_hex if success else None,
        "output_governance": gov,
        "failure_detail": None if success else {"code": error_code},
    }


def sign_proof(signing_key, statement):
    sig = signing_key.sign(canonical_json(statement))
    import base64
    return {
        "statement": statement,
        "signer_key_id": "enclave-proof-v1",
        "signature_b64": base64.b64encode(sig).decode(),
    }


def sign_checkpoint(signing_key, size, root_hex, timestamp):
    import base64
    msg = canonical_json({"root_hex": root_hex, "size": size, "timestamp": timestamp})
    return {
        "size": size,
        "root_hex": root_hex,
        "timestamp": timestamp,
        "checkpoint_signature_b64": base64.b64encode(signing_key.sign(msg)).decode(),
    }
