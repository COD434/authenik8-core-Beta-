# What Authenik8-core Does

Authenik8-core adds a stateful security layer around JWT authentication:

- Refresh-token rotation with replay protection.
- Redis-backed session control and revocation.
- Role, permission, scope, and tenant authorization.
- Structured security audit events.
- Session-risk detection and quarantine.
- Rate limiting, IP controls, and secure headers.
- Scoped identities for AI agents, workers, bots, and M2M callers.

Only SHA-256 token fingerprints are stored in session and refresh records, so a
read-only Redis exposure does not reveal usable bearer tokens from those
records.

[Back to the documentation index](../README.md#documentation)
