# Replay-Attack Detection

When a previously rotated refresh token is reused, its fingerprint no longer
matches the current family record.

The SDK then:

1. Rejects the request.
2. Revokes the affected refresh family.
3. Reports a replay-risk signal.
4. Quarantines the affected session.
5. Emits a structured audit event.

This blocks both token replay and concurrent attempts to rotate the same family.

[Back to the documentation index](../README.md#documentation)
