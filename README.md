# Authenik8-core [Beta]



[![Pipeline status](https://gitlab.com/COD434/authenik8-core/badges/main/pipeline.svg)](https://gitlab.com/COD434/authenik8-core/-/pipelines)
[![Coverage](https://gitlab.com/COD434/authenik8-core/badges/main/coverage.svg)](https://gitlab.com/COD434/authenik8-core/-/pipelines)
[![NPM Version](https://img.shields.io/npm/v/authenik8-core.svg)](https://www.npmjs.com/package/authenik8-core)

Most JWT authentication systems break under real-world attacks.
Authenik8-core is built to handle them.

***
## What Authenik8-core Does
Authenik8-core adds a security layer on top of JWT:

 •Refresh token rotation with replay protection (jti-based)

 •Stateful session control using Redis

 •Built-in security middleware (rate limiting, IP control)

 •Unified authentication + security logic

 •Scoped identities for AI agents, workers, bots, and M2M callers

## Example: Replay Attack Prevention
```
TypeScript
// First request → valid
await auth.refreshToken(token);

// Reusing same token → blocked
await auth.refreshToken(token); // rejected
```
***

## Getting started

Generate and persist an ES256 private JWK once. Do not generate a new key every time the process starts.

```ts
import {
  createAuthenik8,
  generateSigningJwk,
  verifyAccessTokenWithJwks,
} from "authenik8-core";

const privateJwk = await generateSigningJwk("2026-07-primary");
// Store privateJwk in your secret manager before constructing the engine.

const auth = await createAuthenik8({
  jwt: {
    keys: [privateJwk],
    activeKid: "2026-07-primary",
    issuer: "https://api.example.com",
    audience: "example-api",
  },
  refreshSecret: process.env.REFRESH_SECRET!,
});

app.get("/.well-known/jwks.json", (_req, res) => res.json(auth.getJwks()));
app.get("/protected", auth.requireAuth, (_req, res) => res.sendStatus(204));

const tokens = await auth.issueTokens({
  userId: "user_1",
  email: "test@example.com",
});
const payload = await auth.verifyToken(tokens.accessToken);

// A separate service can verify with public keys only (or pass a JWKS URL).
const publicPayload = await verifyAccessTokenWithJwks(
  tokens.accessToken,
  auth.getJwks(),
  { issuer: "https://api.example.com", audience: "example-api" },
);
```

`jwtSecret` remains available as a deprecated JOSE/HS256 migration path. It does not provide a public JWKS and should not be used for new applications.

## Key rotation

1. Generate and securely persist a new key with a unique `kid`.
2. Put the new private JWK and previous verification keys in `jwt.keys`.
3. Set `activeKid` to the new key. New tokens now carry the new `kid`.
4. Keep old public keys until every token they signed has expired, then remove them.

`auth.getJwks()` strips private key material and returns every configured public verification key. Verification enforces ES256, `kid`, issuer, audience, expiry, and token purpose.

## Agent and service identity

Agent identity is optional and fails closed. The application supplies the source
of truth for registered agents and their maximum scopes:

```ts
const auth = await createAuthenik8({
  jwt,
  refreshSecret,
  redis,
  agent: {
    resolveAgent: async (agentId) => agentRepository.findActive(agentId),
    authorizeDelegation: async ({ user, agent, requestedScopes }) =>
      user.role === "admin" &&
      agent.agentId === "build-worker" &&
      requestedScopes.every((scope) => scope === "tasks:read"),
  },
});
```

Mint M2M tokens only after a trusted workload-authentication exchange such as
mTLS, cloud workload identity, or a signed client assertion:

```ts
const machine = await auth.agent!.issueToken({
  agentId: "build-worker",
  scopes: ["tasks:read"],
  label: "production queue worker",
});

app.post(
  "/internal/tasks",
  auth.agent!.requireScopes("tasks:write"),
  handler,
);
```

`issueToken()` is a privileged SDK primitive and must not be exposed as an
unauthenticated HTTP endpoint. Agent tokens use a distinct `tokenUse`, carry an
exact scope set and `actorChain`, and are stored under
`agent-sessions:<agentId>`. Human middleware rejects agent tokens.

Delegated tokens require an active human access-token session and an explicit
`authorizeDelegation` decision:

```ts
const delegated = await auth.agent!.issueDelegatedToken({
  agentId: "build-worker",
  userAccessToken,
  scopes: ["tasks:read"],
});
```

They identify the human subject and agent actor through `sub`, `act`, and
`actorChain` claims. Revoking the originating human session invalidates the
delegation. Removing an agent or scope from `resolveAgent` invalidates existing
tokens during verification.

```ts
await auth.agent!.revokeSession(agentId, sessionId);
await auth.agent!.revokeAgent(agentId);
await auth.agent!.activateAgent(agentId);
```

Public JWKS verification establishes signature validity but cannot observe
Redis session revocation. Security-sensitive agent routes should use the
session-aware SDK middleware or a trusted introspection boundary.
***

## Why Authenik8-core?


JWT makes authentication look simple…
…but introduces hidden problems:

 Refresh token reuse (replay attacks)
 Stateless logout issues
 Broken token rotation
 Scattered security logic

Authenik8 solves this with:

 Refresh token rotation (with uniqueness via jti)
 Stateful session control (Redis)
 Built-in security (rate limit, IP whitelist, helmet)
 Clean, unified API

 ***
## Secure Refresh Flow
```
 // first use → valid
await auth.refreshToken(token);

// reuse same token → rejected
await auth.refreshToken(token); // ❌ throws
```
***

## API Overview
```
const auth = await createAuthenik8(config);

// auth
await auth.signToken(payload);
await auth.verifyToken(token);
auth.getJwks();

// refresh
auth.refreshToken(refreshToken);
auth.generateRefreshToken(payload);

// Redis-backed sessions
await auth.listSessions(userId);
await auth.revokeSession(userId, sessionId);
await auth.revokeAllSessions(userId);

// optional agent identity
await auth.agent?.issueToken({ agentId, scopes });
await auth.agent?.issueDelegatedToken({ agentId, userAccessToken, scopes });
auth.agent?.requireAgent;
auth.agent?.requireScopes("tasks:write");
await auth.agent?.revokeAgent(agentId);

// security
auth.rateLimit;
auth.ipWhitelist;
auth.helmet;

// middleware
auth.requireAuth;
auth.requireAdmin;
```
***
## Architecture

```
┌───────────────┐
                │    Client     │
                │ (Web / Mobile)│
                └───────┬───────┘
                        │
                        ▼
            ┌─────────────────────┐
            │   API / Backend     │
            └─────────┬───────────┘
                      │
                      ▼
            ┌─────────────────────┐
            │   Authenik8-core    │
            │─────────────────────│
            │  JWT Service        │
            │  - Sign / Verify    │
            │                     │
            │  Refresh Service    │
            │  - Rotation         │
            │  - Replay Detection │
            │                     │
            │  Security Module    │
            │  - Rate Limiting    │
            │  - IP Controls      │
            │  - Middleware       │
            └─────────┬───────────┘
                      │
                      ▼
            ┌─────────────────────┐
            │       Redis         │
            │─────────────────────│
            │  Session Store      │
            │  Token State        │
            │  Revocation Data    │
            └─────────────────────┘

```
***

## Important

Authenik8-core uses stateful JWT authentication.
This means:
Requires Redis (or compatible store)
Provides stronger security and control than stateless JWT

## Add your files

```
cd existing_repo
git remote add origin https://gitlab.com/COD434/authenik8-core.git
git branch -M main
git push -uf origin main
```

***
## Built with Real Testing

Authenik8-core includes integration-tested flows for:

Token rotation
Replay attack prevention
Secure refresh logic

***
### Threats Addressed

- Refresh token replay attacks
- Concurrent token refresh abuse
- Stateless session vulnerabilities
- Basic rate limit bypass (IP rotation)

***
## How It Works Internally
Authenik8-core is designed around stateful JWT authentication to address real-world attack scenarios.
## Refresh Token Rotation

Each refresh token includes a unique identifier (jti).
Flow:

Token is issued with a jti

jti is stored in Redis
On refresh:

Token is validated
jti is checked against Redis

If valid:

Old token is invalidated
New token is issued with a new jti

## Replay Attack Detection

If a refresh token is reused:

The jti no longer exists or is marked as used
The request is rejected immediately
This prevents:

Token replay attacks
Concurrent refresh abuse

## Stateful Session Control
Unlike traditional JWT systems:
Sessions are tracked in Redis
Tokens can be revoked
Logout is fully enforced

## Security Layer
Authenik8-core includes built-in middleware for:
Rate limiting
IP-based controls
Secure headers (Helmet)
These operate alongside authentication to provide: 👉 a unified security layer

## Why Stateful Matters
Stateless JWT:
Cannot revoke tokens easily
Cannot detect reuse
Cannot track behavior
Authenik8-core:
Tracks token lifecycle
Detects anomalies
Enables real control over sessions
***


## Use Cases

SaaS backends
APIs with authentication
Secure admin systems
Systems requiring session control

***

## Final Thought

JWT alone is not an authentication system.
Authenik8-core makes it one.
***
