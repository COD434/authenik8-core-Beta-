# Authenik8-core Threat Model

This document describes the controls implemented by the SDK and the security
responsibilities that remain with its operator. It is not a certification or a
claim of compliance with a military, government, or industry assurance scheme.
Those claims require independently defined requirements, accredited assessment,
deployment review, and operational evidence.

## Assets

- Access, refresh, and agent signing keys.
- Human, guest, administrator, and agent identities.
- Active sessions, refresh families, revocation markers, and quarantine state.
- OAuth state, identity records, provider links, and email/provider indexes.
- Authorization claims, tenant boundaries, and audit-event integrity.
- Redis availability and integrity.

## Adversaries

- Unauthenticated attackers sending malformed tokens, OAuth parameters,
  forwarding headers, IP values, or high request volumes.
- Authenticated users attempting claim, tenant, role, permission, or account-link
  escalation.
- Token thieves replaying access, refresh, guest, or agent bearer credentials.
- Concurrent attackers racing refresh, OAuth-state, identity-create, or
  provider-link operations.
- Compromised agents attempting scope or delegation escalation.
- Attackers with partial infrastructure access, including an untrusted proxy or
  the ability to submit data consumed by an audit sink.

## Trust Boundaries

The application, its signing-key source, its identity adapter, and Redis are in
the trusted computing base. Redis compromise can alter sessions, OAuth indexes,
refresh state, rate limits, and quarantine records; it can therefore cause
account takeover, forced logout, policy bypass, or denial of service.

Google and GitHub responses are trusted only after HTTPS success checks and
provider-specific identity verification. Forwarding headers are trusted only
when the direct socket peer and each intervening hop match explicitly configured
proxy CIDRs.

## Enforced Security Invariants

### Tokens and sessions

- New deployments use ES256 P-256 JWKs with bounded key rings, unique `kid`
  values, issuer, audience, expiry, and exact `tokenUse` verification.
- Published JWKS documents contain only allowlisted public EC fields. Local
  verification rejects private or oversized key sets; remote JWKS URLs require
  credential-free HTTPS.
- The HS256 migration path requires an independent secret containing at least 32
  bytes. Refresh and access HMAC secrets may not be the same.
- Access tokens are limited to 24 hours, refresh tokens to 31 days, and agent
  tokens to one hour. Compact JWT and signed-payload sizes are bounded.
- Stateful verification requires the token fingerprint to match the current
  Redis session and rejects revoked or quarantined sessions.
- Refresh rotation uses a per-session lock plus atomic compare-and-set. Replay or
  a lost rotation race revokes the refresh family.
- Redis stores SHA-256 token fingerprints rather than newly issued raw bearer
  tokens. Read-only migration support remains for older access-session records.
- Compound refresh and lock keys use collision-resistant identifiers, and
  persisted sessions must match the Redis hash field from which they were read.
- Authorization claim collections and values are bounded at issuance and again
  after signature verification.

### OAuth identity

- State is 256 random bits, expires within five minutes, has a strict shape, and
  is atomically read and deleted before token exchange. Custom state stores must
  implement the same one-time `take()` guarantee.
- Link mode must be explicit and is rejected before state creation unless an
  authenticated user ID is present.
- A link callback can modify only the authenticated user recorded in state.
  Provider-supplied email is never used to choose the link target.
- Redis identity creation atomically distinguishes `created`,
  `existing-provider`, and `existing-email`. An email collision never authorizes
  token issuance.
- Provider linking uses optimistic compare-and-set with bounded retries and
  verifies the resulting link before success. Identity transaction keys share a
  Redis Cluster hash slot.
- Identity indexes are cross-checked against resolved records. Adapter-returned
  users are bounded and validated before any account decision or token
  issuance.
- Automatic verified-email linking is disabled by default. If an application
  explicitly enables it, policy and email-verification values must be actual
  booleans and the adapter must persist and verify the link before tokens are
  issued.
- OAuth provider requests time out and decompressed JSON responses are capped at
  64 KiB before strict response-shape validation.

### Network and HTTP controls

- Client IP resolution starts at `socket.remoteAddress`; it never trusts
  Express's already-processed `req.ip`.
- `X-Forwarded-For` is ignored unless `trustedProxyCidrs` is configured. The
  chain is walked right-to-left and stops at the first untrusted hop. Malformed,
  excessively long, or excessively deep chains fail closed.
- IPv4, IPv6, IPv4-mapped IPv6, and CIDR entries are canonicalized. Loopback is
  not implicitly allowlisted.
- Exact IP allowlist membership and TTL are checked atomically. CIDR TTL cleanup
  is batched instead of issuing one Redis request per entry.
- Rate-limit keys are bounded SHA-256 digests. OTP limiting applies both an
  IP bucket and a normalized, bounded email bucket.
- Default CSP is enforcing and contains no `unsafe-inline` or placeholder
  origins. HSTS, frame denial, MIME sniffing protection, and a no-referrer policy
  are enabled.

### State isolation and audit

- SDK Redis keys are isolated by an explicit prefix or a stable prefix derived
  from issuer and audience. Caller-controlled identity index components are
  hashed.
- Audit metadata is detached, bounded, recursively cloned, and deeply frozen.
  One sink cannot mutate authorization state or the event delivered to another
  sink.
- Audit envelope identifiers are bounded and control-character free. Stored
  risk records, principals, counters, actions, and fingerprints are validated
  before they influence quarantine decisions.
- Best-effort audit delivery contains synchronous and asynchronous sink
  failures. Strict mode can deliberately fail the security operation.

## Residual Risks and Operator Responsibilities

1. Bearer credentials remain usable by a thief until expiry, revocation, or
   quarantine. The SDK does not implement proof-of-possession or TLS channel
   binding.
2. Cookie authentication is disabled by default and has no built-in CSRF token
   mechanism. Applications enabling it must enforce `Secure`, `HttpOnly`,
   suitable `SameSite`, origin checks, and CSRF validation.
3. Redis is security-critical. Use authenticated encrypted connections,
   network isolation, least-privilege credentials, persistence, tested failover,
   monitoring, protected backups, and a topology compatible with the Lua
   operations used here.
4. IP controls are defense in depth, not identity proof. NAT, mobile networks,
   IPv6 privacy addresses, botnets, and IP rotation limit their effectiveness.
5. The application must authenticate workloads before calling agent issuance.
   Use mTLS, cloud workload identity, signed client assertions, or an equivalent
   credential exchange.
6. Offline JWKS verification cannot observe Redis revocation. Services that need
   immediate revocation require a trusted online session/introspection boundary.
7. Custom OAuth identity and state adapters are part of the trusted computing
   base and must preserve uniqueness, atomicity, one-time consumption, and
   authenticated-link invariants.
8. The SDK does not replace TLS termination, secret-manager access controls,
   host/container hardening, application input validation, CORS policy, XSS
   prevention, durable audit storage, incident response, or supply-chain
   controls.
9. Fail-closed Redis behavior protects authorization but can reduce
   availability. Capacity planning and failure-mode testing are required.
10. CI intentionally uses `ioredis-mock` and starts no Redis service; operators must separately qualify
    their exact Redis version, cluster/failover topology, and persistence
    settings before production.

## Verification Expectations

Every security fix should retain a regression test for its abuse case. Release
gates should include type checking, unit and mocked-Redis integration tests,
build verification, a lockfile-based dependency audit, secret scanning, static
analysis, and independent review of high-risk changes. Production qualification
should add real-topology Redis tests outside CI, penetration testing, deployment
configuration review, and recovery exercises.
