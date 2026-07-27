# Security Audit — 2026-07-27

## Result

This review found no open Critical or High finding in the reviewed SDK scope
after the remediations listed below. That result is evidence from this review,
not a guarantee, certification, or claim of military/government accreditation.
Independent review and deployment-specific testing remain required.

## Scope

The review covered:

- ES256 and legacy HS256 signing and verification.
- Access, refresh, guest, and agent token separation.
- Session persistence, rotation, replay response, revocation, and quarantine.
- OAuth state, provider exchange, account creation, and provider linking.
- Authorization, tenant checks, audit delivery, and risk-state handling.
- Proxy trust, client-IP resolution, allowlists, and rate limiting.
- Redis key construction, atomic operations, failure behavior, and isolation.
- Package dependencies, published files, public entry points, and CI behavior.

The host application, its custom adapters and policies, Redis deployment, edge
proxy, secret manager, operating system, and application routes were not
independently penetration-tested.

## Method

The audit combined manual data-flow and trust-boundary review with abuse-case
tests. It checked authentication decisions before and after persistence,
one-time and concurrent operations, untrusted string and collection bounds,
algorithm and token-purpose confusion, proxy-chain spoofing, Redis key
ambiguity, stored-record integrity, error handling, and package supply-chain
exposure.

## Findings Remediated

### Token and session integrity

- Enforced exact token-purpose, issuer, audience, algorithm, canonical compact
  encoding, token size, claim size, and lifetime bounds.
- Required independent 32-4096 byte HMAC secrets and rejected shared access and
  refresh secrets.
- Stored SHA-256 bearer-token fingerprints instead of newly issued raw tokens.
- Added field-to-record session ID integrity checks and rejected malformed
  persisted metadata.
- Replaced ambiguous compound refresh and lock keys with SHA-256 pair
  identifiers. Refresh-family revocation uses bounded concurrency.
- Bounded authorization arrays and strings at both issuance and verification.
- Restricted local verification JWKS to bounded, unique, public P-256 keys and
  remote JWKS to credential-free HTTPS URLs.

### OAuth and identity integrity

- Made state 256-bit, five-minute, exact-shape, bounded, and atomically
  consumable before exchange.
- Bounded provider HTTP time and decompressed JSON response size.
- Required explicit authenticated link mode; provider email never chooses the
  link target.
- Made identity creation and provider linking atomic and cluster-slot safe.
- Cross-checked email/provider indexes against the resolved record and
  validated all adapter-returned users before any token issuance.
- Disabled automatic email linking by default. Policy flags and provider email
  verification must be actual booleans; truthy strings are not accepted.
- Bounded identities, roles, provider identifiers, and provider count.
- Detached validated identity and agent records from caller-owned mutable
  objects.

### Network, policy, and audit integrity

- Resolved client addresses from the socket and explicitly trusted proxy CIDRs,
  walking forwarding chains from right to left.
- Rejected malformed trusted forwarding headers and ignored headers from
  untrusted peers.
- Canonicalized IPv4/IPv6/CIDR entries, removed implicit loopback trust, made
  exact membership/expiry atomic, and batched CIDR maintenance.
- Distinguished actual rate-limit decisions from storage/protocol failures;
  failures return 503 instead of being mislabeled as 429.
- Bounded and validated audit envelopes, recursively detached metadata, and
  contained synchronous and asynchronous sink failures.
- Validated persisted risk state, principals, counters, policy enums, and
  deduplication fingerprints. Invalid security state fails closed.

### Distribution and CI

- Removed obsolete alternative identity/password stores and stateless admin or
  guest verification fallbacks.
- Restricted package exports to the reviewed root API and `package.json`,
  preventing unsupported internal deep imports through the package resolver.
- Removed import-time dotenv behavior.
- CI integration tests use `ioredis-mock`; no Redis service or readiness probe
  is required.
- Updated the lockfile to patched dependencies. A live
  `npm audit --package-lock-only --audit-level=low` reported zero known
  vulnerabilities on 2026-07-27.

## Verification Gates

The release gates are:

```sh
npm run typecheck
npm run lint
npm test
npm run build
npm audit --package-lock-only --audit-level=low
npm pack --dry-run
```

CI also enables GitLab SAST, dependency scanning, and secret detection. The
test suite uses mocked Redis deliberately; a separate production qualification
must exercise the selected Redis version and topology.

## Residual Risks

- A stolen bearer token can be used until expiry, revocation, or quarantine.
  Proof-of-possession and TLS channel binding are not implemented.
- Cookie authentication requires application-owned CSRF protection and secure
  cookie policy.
- Redis, signing-key storage, custom identity/state adapters, authorization
  callbacks, and delegation callbacks remain in the trusted computing base.
- Signature-only offline JWKS verification cannot observe online revocation.
- IP controls are defense in depth and are limited by NAT, address rotation,
  and distributed attackers.
- The SDK does not provide TLS termination, durable tamper-evident audit
  storage, secret-manager/HSM integration, host hardening, incident response,
  or deployment accreditation.
- Mocked Redis verifies SDK logic but cannot qualify Lua/version differences,
  cluster routing, persistence, failover, latency, or disaster recovery.

See the [full threat model](../THREAT_MODEL.md) for operator responsibilities.

[Back to the documentation index](../README.md#documentation)
