#!/usr/bin/env python3
"""
PZDR adversarial self-test.

Synthesizes forged / tampered evidence in memory and asserts the independent
verifier flags every case. No fixtures, no AWS, no Rust. Run:

    python3 pzdr_verify.py self-test      (or)      python3 pzdr_selftest.py

Each case documents the real attack it models against a "Provable Zero Data
Retention" audit trail.
"""
import base64
import copy
import hashlib
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

import pzdr_verify as pv
from pzdr_ledger import (DEFAULT_POLICY, TransparencyLog, evaluate_policy,
                         build_statement, sign_proof, sign_checkpoint)

MEAS = "0" * 96
CHAN = hashlib.sha256(b"chan").hexdigest()


def _b64(b):
    return base64.b64encode(b).decode()


def build_session(sk, n=8, policy=DEFAULT_POLICY):
    """Honest signed ledger of n proofs. Returns (log, proofs, pk_hex)."""
    pk_hex = sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()
    log = TransparencyLog()
    proofs = []
    for i in range(1, n + 1):
        stmt = build_statement(counter=i, tenant="t", commitment_hex="%064x" % i,
                               measurement=MEAS, channel_pk_hex=CHAN, policy=policy,
                               proof_verifier_key_hex=pk_hex,
                               success=True, plaintext_len=40,
                               result_hash_hex="%064x" % (i * 7))
        proof = sign_proof(sk, stmt)
        log.append(pv.canonical_json(proof))
        proofs.append(proof)
    return log, proofs, pk_hex


def run_self_test():
    print("PZDR adversarial self-test")
    sk = Ed25519PrivateKey.from_private_bytes(hashlib.sha256(b"honest").digest())
    attacker = Ed25519PrivateKey.from_private_bytes(hashlib.sha256(b"attacker").digest())
    log, proofs, pk = build_session(sk, 8)
    root = log.root()
    cp = sign_checkpoint(sk, log.size(), root.hex(), 1_780_000_000)

    results = []  # (expect_pass, got_pass, name)

    def case(name, expect_pass, got_pass):
        results.append((expect_pass, got_pass, name))

    # 1. Honest proof verifies.
    ok, _ = pv.check_proof_signature(proofs[0], pk)
    case("honest proof signature verifies", True, ok and not pv.check_statement_invariants(proofs[0]["statement"]))

    # 2. Forged signature by attacker key.
    forged = copy.deepcopy(proofs[0])
    forged["signature_b64"] = _b64(attacker.sign(pv.canonical_json(forged["statement"])))
    ok, _ = pv.check_proof_signature(forged, pk)
    case("forged signature (attacker key) rejected", False, ok)

    # 3. Tampered statement after signing (flip success false->keeps old sig).
    tam = copy.deepcopy(proofs[0])
    tam["statement"]["tenant_id"] = "attacker-tenant"
    ok, _ = pv.check_proof_signature(tam, pk)
    case("post-sign statement tamper breaks signature", False, ok)

    # 4. Honest inclusion verifies.
    idx = 3
    leaf = pv.leaf_hash(pv.canonical_json(proofs[idx]))
    path = [bytes.fromhex(h) for h in log.inclusion(idx)]
    case("honest inclusion verifies", True,
         pv.verify_inclusion(leaf, idx, log.size(), path, root))

    # 5. Inclusion with a tampered audit-path node.
    bad_path = list(path)
    bad_path[0] = pv.leaf_hash(b"evil")
    case("tampered audit path rejected", False,
         pv.verify_inclusion(leaf, idx, log.size(), bad_path, root))

    # 6. Inclusion against a forged root (operator claims a different tree).
    forged_root = pv.leaf_hash(b"forged-root")
    case("inclusion against forged root rejected", False,
         pv.verify_inclusion(leaf, idx, log.size(), path, forged_root))

    # 7. Leaf substitution: claim a DIFFERENT proof sits at index idx using the
    #    honest path (a back-dated record swap).
    other_leaf = pv.leaf_hash(pv.canonical_json(proofs[idx + 1]))
    case("leaf substitution at fixed index rejected", False,
         pv.verify_inclusion(other_leaf, idx, log.size(), path, root))

    # 8. Honest consistency verifies (append-only 4 -> 8).
    sub = TransparencyLog()
    for e in log.entries[:4]:
        sub.append(e)
    cproof = [bytes.fromhex(h) for h in log.consistency(4)]
    case("honest append-only consistency verifies", True,
         pv.verify_consistency(4, sub.root(), 8, root, cproof))

    # 9. Equivocation / split-view: operator rewrites history — same size 8 but a
    #    different leaf 7 — and tries to pass the old consistency proof.
    forked = TransparencyLog()
    for e in log.entries[:7]:
        forked.append(e)
    forked.append(pv.canonical_json({"forged": "leaf"}))
    case("equivocating (rewritten) tree rejected", False,
         pv.verify_consistency(4, sub.root(), 8, forked.root(), cproof))

    # 10. Shrinking tree (history deletion): size goes backwards.
    case("shrinking ledger rejected", False,
         pv.verify_consistency(8, root, 4, sub.root(), cproof))

    # 11. Checkpoint signature forgery.
    bad_cp = dict(cp)
    bad_cp["checkpoint_signature_b64"] = _b64(attacker.sign(pv._checkpoint_msg(cp)))
    case("forged checkpoint signature rejected", False,
         pv.check_checkpoint_signature(bad_cp, pk))

    # 12. Checkpoint root swapped but old signature kept.
    swapped_cp = dict(cp, root_hex=forged_root.hex())
    case("checkpoint root swap breaks its signature", False,
         pv.check_checkpoint_signature(swapped_cp, pk))

    # 13. Policy-hash mismatch (operator edits the published ruleset after the fact).
    edited_policy = dict(DEFAULT_POLICY, max_input_bytes=10_000_000)
    case("edited policy fails hash pin", False,
         not pv.check_policy(proofs[0], edited_policy))

    # 14. Invariant: success proof that claims NO zeroization.
    no_wipe = copy.deepcopy(proofs[0])
    no_wipe["statement"]["zeroization_report"] = {"input_buffer_wiped": False}
    case("success without zeroization flagged", False,
         not pv.check_statement_invariants(no_wipe["statement"]))

    # 15. Invariant: failure proof carrying a result_hash (claims it processed data).
    leaky_fail = build_statement(counter=99, tenant="t", commitment_hex="ab" * 32,
                                 measurement=MEAS, channel_pk_hex=CHAN,
                                 proof_verifier_key_hex=pk,
                                 policy=DEFAULT_POLICY, success=False,
                                 error_code="policy_denied")
    leaky_fail["result_hash_hex"] = "cc" * 32
    case("failure leaking a result_hash flagged", False,
         not pv.check_statement_invariants(leaky_fail))

    # 16. Invariant: success whose own policy_decision says allow=false.
    contradiction = copy.deepcopy(proofs[0])
    contradiction["statement"]["policy_decision"]["allow"] = False
    case("success contradicting its policy decision flagged", False,
         not pv.check_statement_invariants(contradiction["statement"]))

    # 17. Attestation binding: proof bound to a DIFFERENT channel key than attested.
    att = {"measurement": MEAS, "channel_public_key_hex": hashlib.sha256(b"other").hexdigest(),
           "proof_verifier_key_hex": pk}
    case("channel-key/attestation mismatch flagged", False,
         not pv.check_attestation_binding(att, proofs[0], MEAS, pk))

    # 18. Attestation measurement != pinned PCR0 (wrong/rogue enclave image).
    att2 = {"measurement": "f" * 96, "channel_public_key_hex": CHAN,
            "proof_verifier_key_hex": pk}
    case("rogue enclave measurement flagged", False,
         not pv.check_attestation_binding(att2, proofs[0], MEAS, pk))

    # ---- report ----
    passed = 0
    for expect_pass, got_pass, name in results:
        # "got_pass" is whatever the relevant check returned as a boolean for the
        # forged artifact; the verifier behaves correctly when got == expect.
        good = (bool(got_pass) == bool(expect_pass))
        passed += good
        print("  [%s] %s" % ("PASS" if good else "FAIL", name))
    failed = len(results) - passed
    print("  ----")
    print("  self-test: %d passed, %d failed" % (passed, failed))
    print("  RESULT: %s" % ("PASS" if failed == 0 else "FAIL"))
    return failed == 0


if __name__ == "__main__":
    raise SystemExit(0 if run_self_test() else 1)
