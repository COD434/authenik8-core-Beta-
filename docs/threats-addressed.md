# Threats Addressed

Authenik8-core directly mitigates:

- Refresh-token replay.
- Concurrent refresh abuse.
- Use of revoked or quarantined sessions.
- Cross-tenant and missing-claim authorization failures.
- Human and machine token-class confusion.
- OAuth state reuse.
- OAuth same-email account-creation races and provider-link account confusion.
- Spoofed forwarding headers from untrusted socket peers or proxy hops.
- Expired exact and CIDR allowlist entries.
- Audit-sink mutation of nested authorization metadata.
- Redis-key collisions between SDK deployments.
- Ambiguous compound refresh/lock keys within a deployment.
- Corrupted or inconsistent OAuth indexes, session records, and risk records.
- Oversized OAuth provider JSON and authorization claim collections.
- Truthy-string coercion in high-impact identity and delegation policies.
- Bearer-token exposure through raw session records.

See the [threat model](../THREAT_MODEL.md) for trust boundaries, residual risks,
and application responsibilities.

[Back to the documentation index](../README.md#documentation)
