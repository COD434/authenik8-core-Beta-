# Authenik8-core

JWT rotation without uniqueness is fake security — Authenik8 fixes that.
Authenik8 is a modular authentication and security SDK for Node.js.
It combines:

 JWT authentication
 Secure refresh token rotation
 Redis-backed session control
 Built-in security middleware

***

## Getting started
```
import { createAuthenik8 } from "authenik8";

const auth = await createAuthenik8({
  jwtSecret: "ACCESS_SECRET",
  refreshSecret: "REFRESH_SECRET"
});

// generate tokens
const refreshToken = await auth.generateRefreshToken({
  userId: "user_1",
  email: "test@test.com"
});

// refresh tokens
const result = await auth.refresh(refreshToken);
```
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
await auth.refresh(token);

// reuse same token → rejected
await auth.refresh(token); // ❌ throws
```
***

## API Overview
```
const auth = await createAuthenik8(config);

// auth
auth.signToken(payload);
auth.verifyToken(token);

// refresh
auth.refresh(refreshToken);
auth.generateRefreshToken(payload);

// security
auth.rateLimit;
auth.ipWhitelist;
auth.helmet;

// middleware
auth.requireAdmin;
```
***
## Architecture


Client
  │
  ▼
Authenik8
  ├── JWTService
  ├── RefreshService (rotation)
  ├── SecurityModule
  ▼
Redis

***

## Important

Authenik8-core uses stateful JWT authentication.
This means:
Requires Redis (or compatible store)
Provides better control over sessions and security

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

## Use Cases

SaaS backends
APIs with authentication
Secure admin systems
Systems requiring session control

***

## Final Thought

JWT alone is not an authentication system.
Authenik8 makes it one.
***
