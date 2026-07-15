  ### Assets to protect

  - Access and refresh-token signing keys
  - User and admin sessions
  - Agent identities, grants, actor chains, and M2M sessions
  - Refresh tokens stored in Redis
  - OAuth identities and account-linking records
  - Admin authorization
  - Redis availability and integrity

  ### Expected attackers

   Attacker                           Capabilities
  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
   Unauthenticated remote attacker    Sends malformed tokens, OAuth callbacks, headers, IP values, and high request volumes
  ─────────────────────────────────  ───────────────────────────────────────────────────────────────────────────────────────
   Authenticated malicious user       Manipulates JWT claims or attempts admin escalation
  ─────────────────────────────────  ───────────────────────────────────────────────────────────────────────────────────────
   Token thief                        Replays stolen access or refresh tokens
  ─────────────────────────────────  ───────────────────────────────────────────────────────────────────────────────────────
   OAuth attacker                     Guesses/replays state or attempts account-linking takeover
  ─────────────────────────────────  ───────────────────────────────────────────────────────────────────────────────────────
   Proxy-spoofing attacker            Supplies forged X-Forwarded-For headers
  ─────────────────────────────────  ───────────────────────────────────────────────────────────────────────────────────────
   Concurrent attacker                Races refresh and identity-creation operations
  ─────────────────────────────────  ───────────────────────────────────────────────────────────────────────────────────────
   Compromised or malicious agent     Attempts scope escalation, delegation abuse, token replay, or continued use after revocation

  ### Trust boundaries

  Untrusted client
      │ HTTP tokens, cookies, headers, OAuth parameters
      ▼
  Application + Authenik8
      ├── JWT signing keys          trusted
      ├── Redis session state      trusted and security-critical
      ├── Application agent registry and delegation policy trusted authorization inputs
      └── Google/GitHub responses  trusted only after verification

  Redis is effectively part of the trusted computing base. Compromising its OAuth indexes, refresh records, or sessions can cause account takeover, forced
  logout, or denial of service.

  ### Threats currently addressed

  - JWT tampering, algorithm confusion, cross-service reuse, and token-purpose confusion through JOSE verification constrained to ES256, `kid`, issuer, audience,
    expiry, and `tokenUse`.
  - Safe signing-key rotation through key rings and public-only JWKS export.
  - Stolen/revoked access sessions by requiring the JWT to exactly match Redis session state.
  - Refresh-token replay by comparing against the currently stored per-session token and revoking the refresh family on mismatch.
  - Complete user-wide revocation through a Redis refresh-family index, even after access-session records expire.
  - Concurrent refresh using Redis locking and atomic compare-and-set rotation.
  - Admin escalation through exact role === "admin" checks plus session validation.
  - OAuth CSRF using 256-bit state stored for five minutes. (src/oauth/providers/google.ts:26)
  - Unsafe automatic OAuth linking is disabled. (src/oauth/brain/identityPolicy.ts:1)
  - Proxy-header spoofing is resisted by not trusting forwarded headers by default. (src/security/ipService.ts:143)
  - Request flooding receives Redis-backed rate limiting.
  - Human/agent token confusion is prevented with distinct `tokenUse` values and middleware.
  - Agent scope escalation is rejected through exact subset checks against the live application registry.
  - Agent and M2M token replay after revocation is rejected through exact Redis session-token matching and whole-agent revocation markers.
  - Delegated-agent authority is bound to an active human session and an explicit application policy; user-session revocation invalidates the delegation.
  - Actor ambiguity is reduced through validated `sub`, `act`, and ordered `actorChain` claims.

  ### Important gaps

  1. Cookie authentication has no built-in CSRF protection. It is disabled by default, but applications enabling it must implement SameSite/Secure/HttpOnly
     cookies and CSRF validation.

  2. OAuth state consumption is not atomic. State is read before external token exchange and deleted afterward, allowing concurrent callbacks to observe the
     same state. Provider authorization codes reduce the impact but do not eliminate the race.

  3. Trusted proxy mode blindly accepts the first forwarded IP. It is safe only when a trusted reverse proxy strips client-supplied forwarding headers.
  4. IP rate limiting does not prevent IP rotation. The README’s claim that this threat is addressed is stronger than the implementation supports.
  5. Bearer-token theft remains effective until expiry or revocation. Session storage enables revocation but does not bind tokens to a device, TLS channel, or
     proof-of-possession key.

  6. Application-level threats remain outside the SDK: TLS termination, secret storage and rotation, XSS, CORS, request validation, password security,
     authorization beyond the admin role, audit-log persistence, dependency compromise, and host/Redis hardening.

  7. Authenik8 does not authenticate a workload before `issueToken()` is called. The application must verify mTLS, a cloud workload identity, a signed client
     assertion, or another credential and must never expose token issuance without that exchange.

  8. Agent tokens remain bearer credentials. Public JWKS verification proves signature and claims but cannot observe Redis revocation; offline services need a
     trusted introspection/session boundary for immediate revocation.
