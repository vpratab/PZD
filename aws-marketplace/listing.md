# AWS Marketplace Listing Draft - PZDR Gateway

## Product Title

PZDR Gateway - Provable Zero Data Retention for AI Inference

## Short Description

Attested AI inference gateway that returns signed deletion proofs and Merkle
receipts for customer-verifiable audit evidence.

## Long Description

PZDR Gateway is a confidential-computing gateway for AI inference workflows
where customers need evidence, not just policy language, about how sensitive
inputs were handled.

The gateway uses an AWS Nitro Enclave trust boundary. Clients fetch attestation,
encrypt prompts to an attested X25519 channel key, submit inference requests,
and receive a model response with a signed deletion proof and Merkle receipt.
Proofs can be verified offline using the published proof verification key.

The v0.1 release is intended for pilots, security review, and controlled
deployment work. The initial upstream model path is mock/deterministic while
production Bedrock integration, persistent ledger anchoring, Marketplace
metering, and compliance evidence packages are completed.

## Core Capabilities

- AWS Nitro Enclave attestation document support
- Parent HTTP to enclave vsock proxy
- Encrypted client-to-enclave payload channel
- SHA-256 commitment verification
- Success and failure deletion proofs
- Ed25519 proof signatures
- Merkle receipt generation
- TypeScript SDK for encryption and offline proof verification

## Intended Pilot Use Cases

- Regulated AI application teams evaluating confidential inference patterns
- Healthcare, legal, financial, and public-sector teams assessing audit evidence
- SaaS teams that need proof receipts for sensitive AI inference workflows
- Security teams reviewing Nitro Enclave based data-handling controls

## What This Listing Does Not Claim Yet

This draft does not claim HIPAA compliance, FedRAMP authorization, SOC 2 audit
status, ISO 27001 certification, GDPR legal sufficiency, or attorney-client
privilege protection. Those require customer-specific deployment evidence,
contracts, audits, and legal review.

## Pricing Draft

- Dimension API identifier: `inference_request`
- Unit: request
- Draft public price target: `$0.0008` per request

Private offers can use pilot pricing while production compliance and support
terms are finalized.

## Support

- Standard support: business-hours email, best-effort 4-business-day response
- Support email: `support@assurezero.com`
- Support URL: `https://github.com/assurezero/pzdr/issues`

## Categories

- Security / Data Protection
- Machine Learning
- Compliance / Governance

## Keywords

`zero data retention`, `confidential computing`, `AWS Nitro Enclaves`,
`attestation`, `verifiable deletion`, `AI inference`, `deletion proof`,
`Merkle ledger`, `audit evidence`, `Bedrock`, `security`

## Screenshots To Prepare

1. Terminal showing attestation fetch and proof verification.
2. JSON proof and receipt envelope.
3. Architecture diagram showing ALB, parent proxy, Nitro Enclave, KMS, model
   provider, and ledger.

## Integration Example

```typescript
import { PZDRClient } from "@pzdr/gateway-client";

const client = new PZDRClient({
  url: "https://gateway.example.com",
  apiKey: "...",
});

const attestation = await client.getAttestation();
const result = await client.process({
  prompt: "summarize this regulated note",
  tenant: "pilot-tenant",
});

const valid = await client.verifyProof(
  result.proof,
  attestation.proof_verifier_key_hex,
);
console.log({ response: result.modelResponse, valid, receipt: result.receipt });
```
