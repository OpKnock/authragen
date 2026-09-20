---
layout: home
hero:
  name: AuthraGen
  text: Vendor-neutral Agent Passport trust layer
  tagline: Exact-authority identity, cryptographic authorization, and accountability for autonomous agents
  actions:
    - theme: brand
      text: Get Started
      link: /guide/quickstart
    - theme: alt
      text: API Reference
      link: /api/overview
    - theme: alt
      text: View on GitHub
      link: https://github.com/OpKnock/authragen
features:
  - title: Self-Custody Passports
    details: Agents generate Ed25519 keys locally; server only attests via CSR. Private keys never leave your process.
  - title: Exact-Intent Authorization
    details: Signed intent binds action + resource + params + amount + destination + audience + nonce. No ambient authority.
  - title: Single-Use Credentials
    details: Action tokens are single-use, audience-bound, with nonce replay protection. Post-approval swaps fail.
  - title: Narrowing Delegation
    details: Client-signed delegation chains monotonically narrow scope/spend/expiry/depth. Authority confusion rejected.
  - title: Policy Engine
    details: Deny-by-default with versioned policies, simulation, conflict detection, and dry-run preflight.
  - title: Audit & Accountability
    details: Hash-chained receipts, signed checkpoints, versioned revocation feed, offline verifier with freshness flags.
  - title: Multi-Runtime Adapters
    details: OpenAI, Anthropic, Gemini, MCP, A2A, n8n — one exact-intent flow across all.
  - title: Production Ready
    details: Rate limiting, CSP, structured errors, request IDs, KMS interface, Postgres/Redis adapters documented.
---