# Changelog

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
