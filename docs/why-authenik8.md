# Why Authenik8-core?

JWT makes authentication look simple but introduces hidden operational and
security problems:

- Refresh-token reuse and replay attacks.
- Stateless logout and revocation gaps.
- Broken or incomplete token rotation.
- Security logic scattered across routes and services.

Authenik8-core addresses these with refresh-token rotation, Redis-backed session
control, authorization middleware, risk quarantine, audit events, and a unified
API.

[Back to the documentation index](../README.md#documentation)
