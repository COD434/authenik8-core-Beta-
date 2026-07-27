# Stateful Session Control

Sessions are represented in Redis, allowing the SDK to:

- Revoke an individual session.
- Revoke every session for a user.
- Reject access tokens after logout.
- Track refresh families independently of access-token expiry.
- Enforce automatic or manual quarantine.
- List active sessions.

Public JWKS verification remains useful for signature-only boundaries, but it
cannot observe this Redis state. Sensitive routes should use
`verifyActiveToken()` or `requireAuth`.

[Back to the documentation index](../README.md#documentation)
