# Example: Replay Attack Prevention

The first refresh succeeds and rotates the token. Reusing the previous token is
rejected:

```ts
await auth.refreshToken(token);
await auth.refreshToken(token); // Throws.
```

Replay detection also revokes and quarantines the affected refresh family.

[Learn how replay detection works](./replay-attack-detection.md)

[Back to the documentation index](../README.md#documentation)
