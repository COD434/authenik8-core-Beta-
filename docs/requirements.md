# Requirements

Authenik8-core uses stateful JWT authentication. A Redis-compatible store is
therefore required for session tracking, refresh rotation, revocation, and
quarantine.

Stateful verification provides stronger control than signature-only JWT
verification, but Redis becomes security-critical infrastructure. Deploy it
with authentication, encryption, restricted network access, persistence, and
monitoring appropriate to the application.

Cryptographic and configuration requirements:

- Prefer ES256 JWKs stored in a secret manager or HSM-backed key service.
- The refresh HMAC secret must contain 32-4096 bytes of cryptographically random
  material and must be independent of the deprecated access HMAC secret.
- Access-token lifetime is 60 seconds to 24 hours; refresh lifetime is 60
  seconds to 31 days; agent-token lifetime is 60 seconds to one hour.
- Keep issuer and audience stable. They also form the default Redis isolation
  domain. Set `redisKeyPrefix` explicitly when multiple deployments share Redis
  or when planning a key migration.
- Load environment variables in the host process before importing or
  constructing the SDK. Authenik8-core does not invoke dotenv.
- Configure `trustedProxyCidrs` only for networks under your control.

CI uses `ioredis-mock` by design and does not start a Redis service. A
production readiness process must still test
the selected real Redis version and topology outside CI, including Lua support,
cluster hash-slot behavior, failover, persistence, latency, and recovery.

[Back to the documentation index](../README.md#documentation)
