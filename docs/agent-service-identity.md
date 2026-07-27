# Agent and Service Identity

Agent identity is optional and fails closed. The application supplies the
source of truth for registered agents and their maximum scopes:

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

[Back to the documentation index](../README.md#documentation)
