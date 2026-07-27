# Secure Refresh Flow

The initial refresh validates the token and atomically rotates its family
record:

```ts
await auth.refreshToken(token);
```

The previous token no longer matches the stored fingerprint:

```ts
await auth.refreshToken(token); // Throws.
```

Replay causes the family to be revoked and the affected session to be
quarantined.

[Read the internal rotation flow](./refresh-token-rotation.md)

[Back to the documentation index](../README.md#documentation)
