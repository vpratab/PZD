# PZDR Provability Model

PZDR's name is a promise: **Provable** Zero Data Retention. This document defines
exactly what "provable" means here, what a third party can verify without trusting
the operator, and what still requires the live Nitro bring-up.

## The gap this closes

Before this change, every session emitted a signed deletion proof plus a Merkle
receipt with only an index, leaf, root, and size. The current receipt is
`{index, leaf_hash_hex, audit_path, checkpoint}`. Verifying the proof
*signature* shows the enclave authored the statement. But the receipt proved
nothing checkable: there was no inclusion proof, no signed checkpoint, and no
consistency proof. An operator could therefore:

- show auditor A one ledger root and auditor B a different one (**equivocation /
  split-view**),
- silently drop or rewrite past proofs (**history rewrite**),
- hand out a `root_hex` that no client could tie their own receipt to.

For a system whose entire value to a Zero-Trust or compliance customer is
*audit-admissible evidence*, that is the core gap.

## What is now provable (offline, no AWS, no Rust toolchain)

The ledger is an **RFC 6962 (Certificate Transparency) transparency log**:

```
leaf_hash(entry) = SHA256(0x00 || canonical_json(SignedProof))
node_hash(l, r)  = SHA256(0x01 || l || r)
```

1. **Inclusion** — given a proof and an audit path, anyone recomputes the tree
   root and confirms the proof is recorded at a specific, signed checkpoint root.
2. **Consistency / append-only** — given two signed checkpoints, anyone confirms
   the newer tree is a pure extension of the older one. This is what defeats
   equivocation and history-rewrite: a forked or shrunk ledger fails the proof.
3. **Signed checkpoints** — the `{size, root_hex, timestamp}` tree head is signed
   by the enclave proof key (the same key bound into the Nitro attestation), so a
   checkpoint cannot be forged or back-dated.
4. **Hash-pinned policy** — the enforced policy document is hashed (sha256 over
   canonical JSON) and that `policy_hash` is recorded in every proof. An auditor
   re-hashes the published ruleset and confirms the gateway enforced exactly it.
5. **Statement invariants** — a *success* proof must record a wiped input,
   truthful returned-response lifecycle state, a result hash, and an allow
   decision; a *failure* must carry an error code and no result hash.
6. **Attestation binding** — PCR0, the channel key, and proof-verification key
   must match the signed Nitro document.

All six are checked by `tools/pzdr_verify.py verify-bundle` and by the TypeScript
SDK (`verifyReceipt`, `verifyCheckpoint`, and `verifyConsistency`). Three independent
implementations — Python, Rust (`services/pzdr-enclave/src/transparency.rs`), and
TypeScript (`sdk/typescript/transparency.ts`) — agree byte-for-byte on the hashing
and canonical JSON; the cross-language conformance test proves it against committed
golden vectors.

## Adversarial assurance

`tools/pzdr_verify.py self-test` synthesizes 18 forged/tampered artifacts in memory
and asserts the verifier rejects each: forged signatures, post-sign tampering,
tampered audit paths, forged roots, leaf substitution, **equivocating and shrunk
ledgers**, forged/swapped checkpoints, edited policy docs, false zeroization claims,
result-leaking failures, self-contradicting decisions, and attestation/channel-key
mismatches. The RFC 6962 primitives are additionally checked against brute force
over every tree up to size 40 (820 inclusion + 820 consistency proofs, plus
negative controls).

## What is still NOT proven (honest boundary — unchanged)

- **Live enclave evidence.** Rust and TypeScript validate Nitro certificate
  paths, COSE signatures, freshness, PCR0, and both bound keys. A real
  AWS-produced document and published EIF measurement still require the live
  EC2 bring-up (`docs/DAY2_NITRO_BRINGUP.md`).
- **Plaintext-level policy correctness.** The auditor verifies the *decision* and
  the *pinned ruleset*, not the plaintext (by design — the auditor never sees it).
  Confidence that the rule fired correctly rests on the enclave running the
  attested image.
- **KMS-bound decryption, real model integration, persistent externally-anchored
  ledger storage.** These remain on the bring-up roadmap. The transparency log here
  is in-memory per process; production should persist entries and periodically
  anchor a signed checkpoint to an external log for cross-operator non-repudiation.

In short: the **evidence format and its verification are now real and adversarially
tested end-to-end**; the remaining work is deployment binding, not protocol design.

## Mapping to target solicitations

- **Navy "Real-time Zero Trust Data & Access Control" (DON26BZ03-NV059):** every
  data access yields a signed, independently verifiable, append-only-proven record
  with an enforced, hash-pinned access policy — Zero-Trust "never trust, always
  verify" applied to the audit trail itself.
- **OSD "GenAI for Secure Workflow Automation & Compliance" / DLA RMF
  pre-adjudication:** the signed checkpoints + inclusion/consistency proofs are
  drop-in RMF/compliance evidence artifacts that an assessor re-verifies offline.
