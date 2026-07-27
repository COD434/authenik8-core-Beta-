# API Overview

```ts
const auth = await createAuthenik8(config);

// Access tokens and keys
await auth.signToken(payload);
await auth.verifyToken(token);
await auth.verifyActiveToken(token);
auth.getJwks();

// Refresh tokens
await auth.refreshToken(refreshToken);
await auth.generateRefreshToken(payload);

// Redis-backed sessions
await auth.listSessions(userId);
await auth.revokeSession(userId, sessionId);
await auth.revokeAllSessions(userId);

// Optional agent identity
await auth.agent?.issueToken({ agentId, scopes });
await auth.agent?.issueDelegatedToken({
  agentId,
  userAccessToken,
  scopes,
});
auth.agent?.requireAgent;
auth.agent?.requireScopes("tasks:write");
await auth.agent?.revokeAgent(agentId);

// Security
auth.rateLimit;
auth.ipWhitelist;
auth.helmet;
await auth.addIP("203.0.113.10", 3600);
await auth.removeIP("203.0.113.10");
await auth.listIPs();

// Human middleware
auth.requireAuth;
auth.requireAdmin;
auth.requireRole("admin", "support");
auth.requirePermission("users:read");
auth.requireScope("profile:read");
auth.requireTenant();

// Risk state
await auth.risk.getState(principal);
await auth.risk.release(principal);
```

`verifyToken()` is signature-only. Use `verifyActiveToken()` for state-aware
verification.

[Back to the documentation index](../README.md#documentation)
