# Introduction

AuthraGen is a **private, vendor-neutral trust layer** for autonomous agents. It issues portable, cryptographically verifiable agent credentials and enforces **exact-action authorization**: an agent can only execute the precise operation that was authorized, with least-privilege delegation, single-use execution, and independently verifiable receipts.

## What AuthraGen Is

- A self-hosted control plane for agent identity and authorization
- Portable credentials (`did:authragen:`) that verify offline with the org public key
- Exact-intent binding: action + canonical resource + exact params + amount + destination + audience + nonce
- Single-use action credentials with nonce replay protection
- Narrowing-only delegation chains with monotone attenuation
- Hash-chained audit receipts with signed checkpoints
- Multi-runtime adapters (OpenAI, Anthropic, Gemini, MCP, A2A, n8n)
- JS/Python SDKs with offline verification

## What AuthraGen Is Not

- ❌ A global registry or official standard
- ❌ Universally trusted (credentials matter when relying parties choose to verify them)
- ❌ An AI safety oracle (risk is a triage heuristic)
- ❌ Immutable logs (tamper-evident; full rewrite protection needs external anchors)
- ❌ A replacement for Entra/Conditional Access (complementary, federate via OIDC)

## Core Invariant

> **An agent can only execute the exact authority that was cryptographically granted to it, and nobody can silently increase that authority.**

## Quick Links

- [Quickstart](/guide/quickstart) — Running in 60 seconds
- [Core Concepts](/guide/concepts) — Mental model
- [API Reference](/api/overview) — Complete endpoint documentation
- [SDKs](/sdk/javascript) — JavaScript & Python clients
- [Deployment](/deployment/docker) — Docker, Kubernetes, production checklist

## License

Apache-2.0