# PZDR Gateway Security Notes

## Security Goal

The goal is to give a customer-verifiable receipt that a specific payload was
processed inside an attested compute boundary and that the gateway emitted a
signed deletion proof after processing.

## Trust Boundary

Trusted:

- AWS Nitro Enclave runtime and NSM attestation mechanism
- Enclave binary matching the pinned PCR0 measurement
- Cryptographic implementations used for X25519, HKDF-SHA256,
  XChaCha20-Poly1305, SHA-256, and Ed25519

Not trusted:

- EC2 parent partition
- ALB and network path
- Operator shell access on the parent instance
- Logs, metrics, and observability systems outside the enclave

## Controls

- Plaintext payloads are decrypted only inside the enclave.
- Client payloads are encrypted to an attested enclave channel key.
- The request commitment binds plaintext, salt, and context.
- Success and failure paths return signed proofs.
- Proof signatures can be verified offline using the attested verifier key.
- Receipts bind proofs to an append-only Merkle log root.

## Required Production Hardening

- Keep the pinned AWS Nitro trust anchors current and alert on attestation
  validation failures.
- Persist Merkle state and anchor ledger roots outside the enclave.
- Add KMS decrypt with `kms:RecipientAttestation` measurement conditions.
- Add Marketplace onboarding, entitlement checks, and batched metering.
- Add operational alerting for failed proof generation, ledger append errors,
  enclave restart loops, and metering failures.
- Complete external legal/compliance review before making regulated-industry
  claims.

## Non-Claims

This code does not by itself make the service HIPAA compliant, FedRAMP
authorized, SOC 2 audited, ISO 27001 certified, or legally sufficient for any
specific customer. Those outcomes require contracts, controls, audits, and
deployment evidence outside this repository.
