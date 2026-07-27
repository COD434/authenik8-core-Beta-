# Session Risk and Quarantine

Refresh replay quarantines and revokes the affected family immediately.
Concurrent refresh and suspicious-agent signals use bounded time-window
thresholds. IP and device changes are audited by default and can be configured
to quarantine:

```ts
const auth = await createAuthenik8({
  jwt,
  refreshSecret,
  redis,
  risk: {
    signalWindowSeconds: 300,
    quarantineSeconds: 900,
    concurrentRefreshThreshold: 2,
    suspiciousAgentThreshold: 5,
    ipChangeAction: "quarantine",
    deviceChangeAction: "audit",
  },
});

const principal = {
  kind: "human" as const,
  id: userId,
  sessionId,
};

await auth.risk.getState(principal);
await auth.risk.release(principal);
```

The risk service depends on a small store interface. The default adapter uses
Redis-compatible commands, while CI uses `ioredis-mock`.

[Back to the documentation index](../README.md#documentation)
