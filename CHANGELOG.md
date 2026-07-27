# Changelog

## Unreleased

### Added
- Human `requireRole()`, `requirePermission()`, `requireScope()`, and tenant-aware authorization middleware.
- Versioned structured audit events with application-owned sinks and configurable best-effort or strict delivery.
- Stateful session-risk signals for refresh replay, concurrent refresh use, IP/device changes, and suspicious agent activity.
- Automatic, TTL-bound human and agent session quarantine with an explicit release API.
- Stable, configurable Redis key namespaces derived from issuer and audience by
  default.
- Explicit trusted-proxy CIDRs and right-to-left forwarding-chain validation.
- Configurable enforcing Helmet policy through `security.helmetOptions`.

### Changed
- Reorganized the root README into a concise entry point with each detailed topic in a dedicated document under `docs/`.
- HMAC secrets now require 32-4096 bytes of material. Access, refresh, and agent
  token lifetimes have explicit upper bounds.
- OAuth state stores must implement atomic `take()`, and identity adapters now
  return explicit creation outcomes and resolve users by ID.
- IP allowlist entries are canonicalized, loopback requires an explicit entry,
  and exact/CIDR expiry cleanup is enforced without N+1 Redis checks.
- SDK modules no longer call `dotenv.config()` at import time; environment
  loading belongs to the host application.
- Removed obsolete deep-import in-memory identity/password stores and their
  duplicate resolver; the hardened identity adapter is now the single OAuth
  account-resolution path.
- Removed stateless `jwtSecret` fallbacks from internal admin and incognito
  helpers. The instance always supplies purpose-bound, session-aware
  verification functions.
- CI remains Redis-service-free and exercises Redis behavior with
  `ioredis-mock`.
- Package exports are restricted to the reviewed root API; public identity,
  token, session, and refresh types are exported from that entry point.

### Security
- `incognito` now enforces active Redis session and quarantine state for authenticated users.
- Access and refresh bearer tokens are represented by SHA-256 fingerprints in Redis, with read migration support for existing raw records.
- Legacy HS256 verification now enforces issuer and audience.
- Token issuance and rotation roll back session state when a dependent security operation fails.
- OAuth state is consumed before token exchange and Redis uses atomic `GETDEL` where available.
- Closed an OAuth identity-create race that could issue tokens for an existing
  same-email account.
- Closed a link-mode account-confusion path that could return the existing
  provider owner's login instead of rejecting the link.
- OAuth state fallback consumption now uses an atomic Lua transaction; the
  nonatomic `get()`/`del()` fallback was removed.
- Redis OAuth identity creation and linking now use atomic, cluster-slot-safe
  transactions with post-link verification.
- Forwarding headers cannot affect allowlist, rate-limit, or risk context unless
  the socket peer belongs to an explicit trusted proxy network.
- Audit metadata is detached, bounded, recursively cloned, and deeply frozen,
  preventing a sink from mutating authorization requirements.
- Default CSP is enforcing and removes `unsafe-inline`, report-only behavior,
  and placeholder domains.
- OTP rate limiting uses bounded, hashed identifiers and both IP and normalized
  email buckets.
- Dependency lockfile updated to patched versions; `npm audit
  --package-lock-only --audit-level=low` reports zero vulnerabilities.
- Refresh and lock keys use collision-resistant compound identifiers, and
  refresh-family deletion uses bounded batches.
- OAuth provider JSON is bounded while streaming; state, identity records,
  provider counts, and adapter index integrity are validated before token
  issuance.
- Stored session/risk records and audit envelopes receive strict runtime
  validation. Authorization claims are bounded at issuance and verification.
- Identity, delegation, and registry policy decisions require exact boolean
  values instead of truthy coercion.
- Published JWKS fields use a public allowlist, local verification rejects
  private/oversized key sets, and remote JWKS URLs require credential-free
  HTTPS.

### Upgrade notes

- Existing Redis sessions use earlier key names and will be treated as logged
  out unless they are deliberately migrated. Set `redisKeyPrefix` explicitly
  before rollout when coordinating a migration.
- Tokens without an exact `tokenUse` claim are rejected.
- `trustProxyHeaders: true` without `trustedProxyCidrs` now fails startup.
- Google link routes must pass `"link"` explicitly to `redirect()`; route-path
  substring inference was removed.
- Numeric token lifetimes are relative seconds. Access tokens are limited to one
  day, refresh tokens to 31 days, and agent tokens to one hour.
- Internal package deep imports are no longer supported. Import runtime APIs and
  public types from `authenik8-core`.
- Refresh and lock Redis key shapes changed; existing refresh credentials are
  intentionally invalidated during this security upgrade.

## [2.0.0] - 2026-07-15
### Added
- JOSE-based ES256 signing with explicit `kid`, issuer, audience, expiry, and token-purpose validation.
- Configurable key rings for safe verification during signing-key rotation.
- Public-only JWKS export, `generateSigningJwk()` key generation, and local/remote public-key verification through `verifyAccessTokenWithJwks()`.
- Public, Redis-backed `auth.requireAuth` middleware that enforces session revocation.
- Per-user refresh-family indexes so user-wide revocation also removes refresh sessions whose access-token records have expired.
- Optional agent/service identities with exact scopes, actor-chain claims, delegated-user tokens, Redis-backed M2M sessions, registry-aware verification, and agent/session revocation.
- Fail-closed delegation policies and separate agent middleware so human and machine token classes cannot be confused.

### Changed
- `verifyToken()` and `guestToken()` are asynchronous because verification and signing use Web Crypto.
- Refresh and guest tokens now use JOSE and include purpose-bound claims.
- `jwtSecret` is deprecated and retained only as an HS256 migration path.

### Fixed
- Invalid RS256 signing with a shared string secret.
- OAuth state and distributed-lock Redis operations that had drifted to incompatible hash commands.

## [0.1.2] - 2026-03-22
### Fixed
- Patched a vulnerability allowing reuse of old refresh tokens.
- Refresh token rotation now uses Redis locks to prevent concurrent refresh exploits.
- Concurrent refresh requests are handled safely, ensuring only one succeeds.
