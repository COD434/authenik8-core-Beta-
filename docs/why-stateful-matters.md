# Why Stateful Authentication Matters

Signature-only JWT authentication cannot immediately revoke a valid token,
detect refresh-token reuse, or enforce server-side session quarantine.

Authenik8-core retains signed JWTs while tracking their lifecycle in Redis. This
enables immediate revocation, replay detection, session inventory, and risk
controls. The tradeoff is a runtime dependency on secure, available Redis
infrastructure.

[Back to the documentation index](../README.md#documentation)
