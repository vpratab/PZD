#!/usr/bin/env python3
"""
PZDR independent verifier — turns the gateway's receipts into something a third
party can actually audit, with no AWS account and no Rust toolchain.

Background
----------
PZDR's pitch is "Provable Zero Data Retention": every inference session emits a
signed deletion proof and a Merkle receipt. Verifying the *signature* proves the
enclave authored the statement. It does NOT prove:
  (a) the proof is actually recorded in the append-only ledger at the published
      root  (inclusion), or
  (b) the ledger has only ever grown — that the operator did not rewrite history
      or show different roots to different auditors  (consistency / split-view).
Without (a) and (b) the "Merkle receipt" is decorative and the audit story is
trust-me. This verifier closes that gap using the RFC 6962 (Certificate
Transparency) hashing rules, plus proof-signature and policy/attestation
binding checks.

Transparency-log hashing (RFC 6962 sec 2.1)
-------------------------------------------
    leaf_hash(entry)   = SHA256( 0x00 || entry_bytes )
    node_hash(l, r)    = SHA256( 0x01 || l || r )
    entry_bytes        = canonical_json(SignedProof)   (sorted keys, compact)

A *checkpoint* (signed tree head) is { size, root_hex, timestamp } signed by the
enclave proof key. Inclusion proofs bind one leaf to a checkpoint root;
consistency proofs bind an old checkpoint to a newer one and prove append-only.

Commands
--------
    pzdr_verify.py verify-proof       <proof.json> --key <hex>
    pzdr_verify.py verify-inclusion   <bundle.json> [--key <hex>]
    pzdr_verify.py verify-consistency <bundle.json> [--key <hex>]
    pzdr_verify.py verify-policy      <proof.json> <policy.json>
    pzdr_verify.py verify-bundle      <bundle.json>          # all of the above
    pzdr_verify.py self-test                                 # adversarial suite

Exit code is non-zero on any failure.
"""
from __future__ import annotations

import hashlib
import json
import sys


# --------------------------------------------------------------------------- #
# Canonical JSON — byte-identical to the Rust signer (serde_json sorted/compact)
# and the TypeScript SDK's canonicalJSON. Payload strings are ASCII, so UTF-8
# escaping never diverges across the three implementations.
# --------------------------------------------------------------------------- #
def canonical_json(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


# --------------------------------------------------------------------------- #
# RFC 6962 transparency-log primitives
# --------------------------------------------------------------------------- #
def leaf_hash(entry_bytes: bytes) -> bytes:
    return hashlib.sha256(b"\x00" + entry_bytes).digest()


def node_hash(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + left + right).digest()


def _split(n: int) -> int:
    """Largest power of two strictly less than n (RFC 6962 split point)."""
    k = 1
    while k < n:
        k <<= 1
    return k >> 1


def merkle_root(leaves) -> bytes:
    """Root hash (MTH) over a list of leaf hashes, RFC 6962 sec 2.1."""
    n = len(leaves)
    if n == 0:
        return hashlib.sha256(b"").digest()
    if n == 1:
        return leaves[0]
    k = _split(n)
    return node_hash(merkle_root(leaves[:k]), merkle_root(leaves[k:]))


def inclusion_path(leaves, m) -> list:
    """Audit path for leaf index m within a tree of len(leaves) (RFC 6962 sec 2.1.1)."""
    n = len(leaves)
    if n == 1:
        return []
    k = _split(n)
    if m < k:
        return inclusion_path(leaves[:k], m) + [merkle_root(leaves[k:])]
    return inclusion_path(leaves[k:], m - k) + [merkle_root(leaves[:k])]


def verify_inclusion(leaf, index, size, path, root) -> bool:
    """Recompute the root from a leaf + audit path; compare to claimed root."""
    if index >= size or size <= 0:
        return False
    fn, sn = index, size - 1
    h = leaf
    for sibling in path:
        if fn % 2 == 1 or fn == sn:
            h = node_hash(sibling, h)
            while fn % 2 == 0 and fn != 0:
                fn >>= 1
                sn >>= 1
        else:
            h = node_hash(h, sibling)
        fn >>= 1
        sn >>= 1
    return h == root and sn == 0


def consistency_path(leaves, m) -> list:
    """Consistency proof between first m leaves and all len(leaves) (RFC 6962 sec 2.1.2)."""
    n = len(leaves)
    if m == n:
        return []
    return _subproof(m, leaves, True)


def _subproof(m, leaves, b) -> list:
    n = len(leaves)
    if m == n:
        return [] if b else [merkle_root(leaves)]
    k = _split(n)
    if m <= k:
        return _subproof(m, leaves[:k], b) + [merkle_root(leaves[k:])]
    return _subproof(m - k, leaves[k:], False) + [merkle_root(leaves[:k])]


def verify_consistency(first_size, first_root, second_size, second_root, proof) -> bool:
    """Verify an append-only transition (first_size,root) -> (second_size,root)."""
    if first_size > second_size:
        return False
    if first_size == second_size:
        return first_root == second_root and list(proof) == []
    if first_size == 0:
        return True
    pr = list(proof)
    if first_size & (first_size - 1) == 0:
        pr = [first_root] + pr
    fn, sn = first_size - 1, second_size - 1
    while fn % 2 == 1:
        fn >>= 1
        sn >>= 1
    fr = pr[0]
    sr = pr[0]
    for c in pr[1:]:
        if sn == 0:
            return False
        if fn % 2 == 1 or fn == sn:
            fr = node_hash(c, fr)
            sr = node_hash(c, sr)
            while fn % 2 == 0 and fn != 0:
                fn >>= 1
                sn >>= 1
        else:
            sr = node_hash(sr, c)
        fn >>= 1
        sn >>= 1
    return fr == first_root and sr == second_root and sn == 0


# --------------------------------------------------------------------------- #
# Ed25519 (proof + checkpoint signatures)
# --------------------------------------------------------------------------- #
def _load_ed25519():
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

        def verify(pk_hex, sig, msg):
            try:
                Ed25519PublicKey.from_public_bytes(bytes.fromhex(pk_hex)).verify(sig, msg)
                return True
            except InvalidSignature:
                return False
            except Exception:
                return False

        return verify
    except Exception as exc:
        return None, str(exc)


_loaded = _load_ed25519()
if isinstance(_loaded, tuple):
    _VERIFY, _VERIFY_ERROR = _loaded
else:
    _VERIFY, _VERIFY_ERROR = _loaded, None


def _b64d(s):
    import base64
    return base64.b64decode(s)


# --------------------------------------------------------------------------- #
# High-level checks
# --------------------------------------------------------------------------- #
def check_proof_signature(proof, key_hex):
    if _VERIFY is None:
        return False, "UNAVAILABLE Ed25519 verifier: %s" % _VERIFY_ERROR
    if not key_hex:
        return False, "missing proof verifier key"
    msg = canonical_json(proof["statement"])
    sig = _b64d(proof["signature_b64"])
    ok = _VERIFY(key_hex, sig, msg)
    return ok, ("valid signature by %s.." % key_hex[:16]) if ok else "BAD signature"


def check_statement_invariants(stmt):
    """Semantic guards an auditor expects PZDR statements to satisfy."""
    fails = []
    z = stmt.get("zeroization_report") or {}
    if stmt.get("success") is True:
        if not z.get("input_buffer_wiped"):
            fails.append("success proof without wiped input buffer")
        retention = (stmt.get("output_governance") or {}).get("retention_policy")
        if retention == "returned-only":
            if z.get("response_buffer_wiped"):
                fails.append("returned-only response falsely marked already wiped")
            if not z.get("response_buffer_returned"):
                fails.append("returned-only response missing returned marker")
        elif not z.get("response_buffer_wiped"):
            fails.append("non-returned response without wiped response buffer")
        if not stmt.get("result_hash_hex"):
            fails.append("success proof missing result_hash_hex")
        if not (stmt.get("policy_decision") or {}).get("allow"):
            fails.append("success proof whose policy_decision did not allow")
    else:
        if stmt.get("result_hash_hex"):
            fails.append("failure proof carrying a result_hash_hex")
        if not stmt.get("error_code"):
            fails.append("failure proof without error_code")
    if stmt.get("proof_version") != 3:
        fails.append("unexpected proof_version %r" % stmt.get("proof_version"))
    return fails


def policy_hash(policy):
    return hashlib.sha256(canonical_json(policy)).hexdigest()


def check_policy(proof, policy):
    """Re-run the published, hash-pinned policy contract against the decision."""
    fails = []
    stmt = proof["statement"]
    decided = stmt.get("policy_decision") or {}
    ph = policy_hash(policy)
    if decided.get("policy_hash") != ph:
        fails.append("policy_hash mismatch: proof=%s recomputed=%s"
                     % (decided.get("policy_hash"), ph))
    if stmt.get("success") and decided.get("allow") is not True:
        fails.append("success under non-allow decision")
    if not stmt.get("success") and decided.get("allow") is True:
        fails.append("failure under allow decision")
    return fails


def check_attestation_binding(att, proof, expected_pcr0, key_hex):
    """Bind the proof to the attested enclave identity."""
    fails = []
    stmt = proof["statement"]
    if att.get("channel_public_key_hex") != stmt.get("channel_public_key_hex"):
        fails.append("channel key in proof != channel key in attestation")
    if att.get("measurement") != stmt.get("measurement"):
        fails.append("measurement in proof != measurement in attestation")
    if expected_pcr0 and att.get("measurement") != expected_pcr0:
        fails.append("attested measurement != pinned PCR0")
    if key_hex and att.get("proof_verifier_key_hex") not in (None, key_hex):
        fails.append("attestation advertises a different proof verifier key")
    if key_hex and stmt.get("proof_verifier_key_hex") != key_hex:
        fails.append("proof verifier key in statement != attested verifier key")
    return fails


# --------------------------------------------------------------------------- #
# Commands
# --------------------------------------------------------------------------- #
def _entry_bytes(proof):
    return canonical_json(proof)


def _checkpoint_msg(cp):
    return canonical_json({"root_hex": cp["root_hex"], "size": cp["size"],
                           "timestamp": cp["timestamp"]})


def check_checkpoint_signature(cp, key_hex):
    if not (_VERIFY and key_hex and "checkpoint_signature_b64" in cp):
        return False
    return _VERIFY(key_hex, _b64d(cp["checkpoint_signature_b64"]), _checkpoint_msg(cp))


def cmd_verify_proof(path, key_hex):
    proof = json.load(open(path))
    ok, msg = check_proof_signature(proof, key_hex)
    print("  signature: %s" % msg)
    inv = check_statement_invariants(proof["statement"])
    for f in inv:
        print("  INVARIANT FAIL: %s" % f)
    ok = ok and not inv
    print("  RESULT: %s" % ("PASS" if ok else "FAIL"))
    return ok


def cmd_verify_inclusion(bundle, key_hex=None):
    cp = bundle["checkpoint"]
    root = bytes.fromhex(cp["root_hex"])
    key_hex = key_hex or bundle.get("proof_verifier_key_hex")
    all_ok = True
    cs_ok = check_checkpoint_signature(cp, key_hex)
    print("  checkpoint signature: %s" % ("valid" if cs_ok else "BAD OR UNAVAILABLE"))
    all_ok = all_ok and cs_ok
    for item in bundle["inclusions"]:
        proof = item["proof"]
        leaf = leaf_hash(_entry_bytes(proof))
        if "leaf_hash_hex" in item and item["leaf_hash_hex"] != leaf.hex():
            print("  leaf %d: leaf-hash mismatch" % item["index"])
            all_ok = False
            continue
        path = [bytes.fromhex(h) for h in item["audit_path"]]
        inc = verify_inclusion(leaf, item["index"], cp["size"], path, root)
        sig_ok = True
        if key_hex:
            sig_ok, _ = check_proof_signature(proof, key_hex)
        ok = inc and sig_ok
        all_ok = all_ok and ok
        print("  leaf %d (%s): inclusion=%s signature=%s"
              % (item["index"], proof["statement"]["error_code"] or "success",
                 "OK" if inc else "FAIL", "OK" if sig_ok else "FAIL"))
    print("  RESULT: %s" % ("PASS" if all_ok else "FAIL"))
    return all_ok


def cmd_verify_consistency(bundle, key_hex=None):
    all_ok = True
    for t in bundle["consistency"]:
        a, b = t["from"], t["to"]
        proof = [bytes.fromhex(h) for h in t["proof"]]
        ok = verify_consistency(a["size"], bytes.fromhex(a["root_hex"]),
                                b["size"], bytes.fromhex(b["root_hex"]), proof)
        all_ok = all_ok and ok
        print("  append-only %d->%d: %s" % (a["size"], b["size"], "OK" if ok else "FAIL"))
    print("  RESULT: %s" % ("PASS" if all_ok else "FAIL"))
    return all_ok


def cmd_verify_policy(proof_path, policy_path):
    proof = json.load(open(proof_path))
    policy = json.load(open(policy_path))
    fails = check_policy(proof, policy)
    for f in fails:
        print("  POLICY FAIL: %s" % f)
    ok = not fails
    print("  pinned policy_hash: %s" % policy_hash(policy))
    print("  RESULT: %s" % ("PASS" if ok else "FAIL"))
    return ok


def cmd_verify_bundle(bundle_path):
    bundle = json.load(open(bundle_path))
    key_hex = bundle.get("proof_verifier_key_hex")
    print("== proof signatures + invariants ==")
    ok = True
    for item in bundle["inclusions"]:
        s_ok, _ = check_proof_signature(item["proof"], key_hex)
        inv = check_statement_invariants(item["proof"]["statement"])
        ok = ok and s_ok and not inv
    print("  %d proofs checked" % len(bundle["inclusions"]))
    print("== inclusion vs signed checkpoint ==")
    ok = cmd_verify_inclusion(bundle, key_hex) and ok
    print("== consistency (append-only / anti-equivocation) ==")
    ok = cmd_verify_consistency(bundle, key_hex) and ok
    if "policy" in bundle:
        print("== hash-pinned policy ==")
        pf = 0
        for item in bundle["inclusions"]:
            f = check_policy(item["proof"], bundle["policy"])
            pf += len(f)
            ok = ok and not f
        print("  policy_hash %s applied to %d proofs (%d failures)"
              % (policy_hash(bundle["policy"]), len(bundle["inclusions"]), pf))
    if "attestation" in bundle:
        print("== attestation binding ==")
        exp = bundle.get("expected_pcr0")
        bf = 0
        for item in bundle["inclusions"]:
            f = check_attestation_binding(bundle["attestation"], item["proof"], exp, key_hex)
            bf += len(f)
            ok = ok and not f
            for x in f:
                print("  BIND FAIL: %s" % x)
        print("  binding checked for %d proofs (%d failures)"
              % (len(bundle["inclusions"]), bf))
    print("=" * 56)
    print("BUNDLE RESULT: %s" % ("PASS" if ok else "FAIL"))
    return ok


def main(argv):
    if len(argv) < 2:
        print(__doc__)
        return 2
    cmd = argv[1]
    key_hex = None
    if "--key" in argv:
        i = argv.index("--key")
        key_hex = argv[i + 1]
        argv = argv[:i] + argv[i + 2:]
    try:
        if cmd == "verify-proof":
            ok = cmd_verify_proof(argv[2], key_hex)
        elif cmd == "verify-inclusion":
            ok = cmd_verify_inclusion(json.load(open(argv[2])), key_hex)
        elif cmd == "verify-consistency":
            ok = cmd_verify_consistency(json.load(open(argv[2])), key_hex)
        elif cmd == "verify-policy":
            ok = cmd_verify_policy(argv[2], argv[3])
        elif cmd == "verify-bundle":
            ok = cmd_verify_bundle(argv[2])
        elif cmd == "self-test":
            import os
            sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
            from pzdr_selftest import run_self_test
            ok = run_self_test()
        else:
            print("unknown command: %s" % cmd)
            return 2
    except (ValueError, KeyError, FileNotFoundError) as exc:
        print("ERROR: %s" % exc)
        return 1
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
