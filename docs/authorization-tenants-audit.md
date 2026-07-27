# Authorization, Tenants, and Audit Events

Authorization middleware authenticates first, uses exact claim matching, and
fails closed when a configured tenant cannot be resolved or is not granted:

```ts
const auth = await createAuthenik8({
  jwt,
  refreshSecret,
  redis,
  authorization: {
    resolveTenant: (req) => req.params.tenantId,
  },
  audit: {
    delivery: "best-effort",
    sinks: [
      {
        write: async (event) => securityEventRepository.append(event),
      },
    ],
  },
});

app.get(
  "/tenants/:tenantId/invoices",
  auth.requireRole("billing-admin", "owner"),
  auth.requirePermission("invoice:read"),
  handler,
);

const tokens = await auth.issueTokens(
  {
    userId: "user_1",
    email: "user@example.com",
    roles: ["billing-admin"],
    permissions: ["invoice:read"],
    scopes: ["profile:read"],
    tenantIds: ["tenant_1"],
  },
  { ip: request.ip, device: request.headers["user-agent"] },
);
```

Roles use any-of matching. Required permissions and scopes use all-of matching.
Checks build a set of granted claims and then inspect each required claim,
avoiding pairwise comparisons.

The SDK owns the versioned audit-event envelope. Applications own durable
console, file, queue, SIEM, or webhook sinks. Best-effort delivery protects
authentication availability; strict delivery rolls back issuance when a sink
cannot accept the event.

[Back to the documentation index](../README.md#documentation)
