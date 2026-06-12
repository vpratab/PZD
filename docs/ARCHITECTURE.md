# PZDR Gateway Architecture

## Summary

PZDR Gateway is a confidential-computing proxy for AI inference. The parent EC2
instance accepts HTTPS traffic and forwards framed JSON over vsock into an AWS
Nitro Enclave. The enclave decrypts the client payload, verifies the plaintext
commitment, runs policy checks, calls the model path, wipes sensitive buffers,
signs a deletion proof, and appends the canonical proof to an RFC 6962 log.

## Components

- `vsock-parent-proxy`: parent-partition HTTP server. It terminates the ALB
  target connection and forwards requests to the enclave over vsock. It should
  not receive plaintext prompts.
- `pzdr-enclave`: enclave-side binary. It owns the X25519 channel key, Ed25519
  proof signing key, hash-pinned policy, proof generation, and transparency log.
- `nitro-attestation`: parser/generator for AWS Nitro attestation documents.
  Clients validate the AWS certificate path and COSE signature, pin PCR0, and
  bind both public keys to the enclave measurement.
- TypeScript SDK: fetches attestation, encrypts requests, submits inference,
  and verifies attestation, proof signatures, signed checkpoints, and inclusion.
- Marketplace metering helper: prepares parent-side usage events and
  `BatchMeterUsage` payloads after billable success proofs.

## Request Flow

1. Client fetches `/v1/attestation`.
2. Client verifies the Nitro attestation document and pins the expected PCR0.
3. Client derives an ephemeral X25519 shared secret with the enclave channel
   public key.
4. Client encrypts the prompt with XChaCha20-Poly1305 and submits
   `/v1/gateway/inference`.
5. Enclave decrypts, verifies commitment, evaluates policy, and produces the
   model response.
6. Enclave wipes the input buffer, signs a v3 deletion proof, appends the
   canonical proof to the log, and returns the response, proof, and receipt.
   The proof explicitly records that the response was returned and does not
   falsely claim that output memory was securely wiped before delivery.

## Deployment Shape

Production deployment uses:

- AWS Application Load Balancer
- Nitro-enabled EC2 parent instance
- AWS Nitro Enclave launched from a signed EIF
- Security groups that expose only the parent proxy to the ALB
- KMS policy conditions bound to the enclave measurement for secret unwrap

The Week 1 milestone is a real Nitro enclave running with the mock upstream
model path. Bedrock `InvokeModel` and Marketplace metering are follow-on
integrations.

## Current Limitations

- The bundled upstream model call is deterministic mock logic.
- Nitro certificate validation checks time validity, issuer/subject linkage,
  issuer signatures, and the COSE signature against the pinned AWS Nitro root.
  Production should still keep the AWS root bundle current and add alerting for
  attestation validation failures.
- The Merkle log is in-memory in the enclave prototype. Production should
  persist and externally anchor roots.
- No HIPAA, FedRAMP, SOC 2, ISO 27001, or legal compliance status is claimed by
  this repository alone.
