# PZDR Gateway Architecture

## Summary

PZDR Gateway is a confidential-computing proxy for AI inference. The parent EC2
instance accepts HTTPS traffic and forwards framed JSON over vsock into an AWS
Nitro Enclave. The enclave decrypts the client payload, verifies the plaintext
commitment, runs policy checks, calls the model path, wipes sensitive buffers,
signs a deletion proof, and appends the proof hash to a Merkle log.

## Components

- `vsock-parent-proxy`: parent-partition HTTP server. It terminates the ALB
  target connection and forwards requests to the enclave over vsock. It should
  not receive plaintext prompts.
- `pzdr-enclave`: enclave-side binary. It owns the X25519 channel key, Ed25519
  proof signing key, policy gate, proof generation, and Merkle append path.
- `nitro-attestation`: parser/generator for AWS Nitro attestation documents.
  Clients use attestation to bind the channel public key to an expected enclave
  measurement.
- TypeScript SDK: fetches attestation, encrypts requests, submits inference,
  and verifies returned proof signatures offline.
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
6. Enclave zeroizes sensitive buffers, signs a v3 deletion proof, appends the
   proof hash to the Merkle log, and returns the response, proof, and receipt.

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
- Certificate chain validation parses the Nitro certificate chain and verifies
  the COSE signature; full production-grade path validation should be completed
  before a public compliance claim.
- The Merkle log is in-memory in the enclave prototype. Production should
  persist and externally anchor roots.
- No HIPAA, FedRAMP, SOC 2, ISO 27001, or legal compliance status is claimed by
  this repository alone.
