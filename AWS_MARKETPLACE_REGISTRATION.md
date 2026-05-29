# AWS Marketplace Registration Walkthrough

Use this for Day 1. Block two focused hours. The parts involving EIN, tax,
banking, root account, and legal authority must be done by the owner.

## Pre-Flight

- AWS account for AssureZero LLC with MFA enabled.
- Administrative access to AWS Marketplace Management Portal.
- LLC EIN and tax classification.
- LLC bank ACH details.
- Public website URL, support email, and support URL.
- Basic logo image.
- Draft EULA or a placeholder plan for legal review.

Prefer an admin IAM user or IAM Identity Center role for day-to-day portal work.
Use the AWS root user only where AWS explicitly requires it.

## Step 1 - Open The Management Portal

1. Go to https://aws.amazon.com/marketplace/management/
2. Sign in with the AssureZero AWS account.
3. Start seller registration.
4. Confirm you are authorized to register on behalf of the organization.

Expected outcome: seller registration is started and the portal asks for
business, tax, payout, and public profile information.

## Step 2 - Complete Seller Profile

Legal/business profile:

- Legal entity name: `AssureZero LLC`
- Public seller name: `AssureZero`
- Country: United States
- State: Georgia
- Tax classification: match the IRS/EIN records
- EIN: enter from the IRS letter

Public profile:

- Website: `https://assurezero.com`
- Support email: `support@assurezero.com`
- Support URL: `https://github.com/assurezero/pzdr/issues`
- Short seller description: `Provable Zero Data Retention for AI inference. Cryptographic deletion receipts per request.`

Payout:

- Use the LLC bank account, not a personal account.
- Save any verification instructions or micro-deposit requirements.

Expected outcome: seller profile moves to pending or submitted verification.

## Step 3 - Complete Tax Interview

1. Open the portal tax section.
2. Complete the US W-9 flow.
3. Use the exact legal name, EIN, and address from the LLC tax records.
4. Sign electronically.

Expected outcome: tax status becomes submitted or verified. If rejected, compare
every field against the IRS EIN letter before resubmitting.

## Step 4 - Create SaaS Product Placeholder

1. Go to Products -> SaaS products.
2. Create a SaaS product.
3. Choose `SaaS contracts with pay-as-you-go` if the first public offer will
   combine a base contract with metered overage.
4. Do not publish public pricing until the listing, EULA, and metering path are
   ready.

Important: AWS says the pricing model cannot be changed after a listing is
created and published to limited visibility.

## Step 5 - Define Metering Dimension

Use one usage dimension for the v0.1 offer:

- API identifier: `inference_request`
- Display name: `Inference request`
- Unit: `Request`
- Description: `One inference request processed by the PZDR Gateway`
- Initial public price target: `$0.0008` per request

For SaaS metering, implement `BatchMeterUsage`. AWS expects sellers to batch
usage records, and AWS Marketplace Operations can test that metering records
are delivered before public publishing.

This bundle includes `crates/marketplace-metering` and
`docs/MARKETPLACE_METERING.md` to prepare validated usage payloads. The actual
AWS API submission should run in the parent control plane, not inside the
enclave.

Do not create long-lived root-account credentials for this. Use a least
privilege IAM role or IAM user for the metering service and store secrets in a
password manager until the production secret store is ready.

## Step 6 - Start Product Listing Draft

Create a draft with conservative claims:

- Title: `PZDR Gateway`
- Category: Security / Data Protection, Machine Learning, Compliance
- Short description: `Provable zero data retention gateway for AI inference with signed deletion receipts.`
- Product URL: `https://assurezero.com/pzdr`
- Support email: `support@assurezero.com`
- Support URL: `https://github.com/assurezero/pzdr/issues`

Use `aws-marketplace/listing.md` only after reviewing it for claim discipline.
Do not claim HIPAA, FedRAMP, SOC 2, ISO 27001, or legal privilege outcomes
until counsel and audits support those claims.

## Step 7 - Prepare Vendor Insights / FTR Materials

AWS Marketplace Vendor Insights can help buyers assess SaaS risk posture, but
do not treat it as a hard blocker for drafting a basic listing unless AWS tells
you so in the portal or support case.

Use these local docs as starter evidence:

- `docs/ARCHITECTURE.md`
- `docs/SECURITY.md`
- `docs/RUNBOOK.md`

## End-Of-Day Checklist

- Seller registration submitted.
- Tax interview submitted.
- Payout details submitted or pending bank verification.
- SaaS product placeholder created.
- Pricing model chosen deliberately.
- Usage dimension drafted.
- Product code/customer identifiers saved when available.
- Metering integration work item created for `BatchMeterUsage`; local payload
  helper verified.
- Listing draft started with conservative claims.
- Vendor Insights/FTR evidence docs saved.

## Human-Only Items

Codex cannot complete these because they require account ownership, tax, bank,
or legal authority:

- Sign into AWS with the AssureZero account.
- Enter EIN, W-9, and bank information.
- Accept AWS Marketplace seller agreements.
- Submit legal/EULA material.
- Submit the final public listing.
