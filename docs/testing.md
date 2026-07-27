# Testing

Authenik8-core includes automated coverage for:

- Token issuance and verification.
- Refresh-token rotation and replay prevention.
- Concurrent refresh behavior.
- Session persistence and revocation.
- Authorization and tenant isolation.
- Audit delivery behavior.
- Session-risk quarantine.
- Agent and delegated identity.
- OAuth same-email creation races and provider-owner link confusion.
- One-time OAuth state under concurrent consumption.
- Forwarded-header spoofing and trusted multi-hop proxy resolution.
- Exact and CIDR allowlist expiration, including IPv4 and IPv6.
- Deep audit-event immutability and synchronous sink failure isolation.
- Secret, token-lifetime, JWT-size, and Redis-key namespace bounds.
- Compound-key collision resistance and persisted index/record integrity.
- OAuth response-size, state-shape, identity-count, and runtime type bounds.
- Malformed risk state, audit envelope, authorization claim, and rate-limit
  failure handling.

CI intentionally uses `ioredis-mock`, including for the concurrent refresh
integration scenario. The pipeline starts no Redis service. Production deployments should separately validate their
chosen Redis topology, persistence, failover, and operational controls.

The release dependency gate is:

```sh
npm audit --package-lock-only --audit-level=low
```

See the dated [security audit](security-audit.md) for scope, remediation, and
residual risks.

[Back to the documentation index](../README.md#documentation)
