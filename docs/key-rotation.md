# Key Rotation

1. Generate and securely persist a new key with a unique `kid`.
2. Put the new private JWK and previous verification keys in `jwt.keys`.
3. Set `activeKid` to the new key. New tokens now carry the new `kid`.
4. Keep old public keys until every token they signed has expired, then remove
   them.

`auth.getJwks()` strips private key material and returns every configured public
verification key. Verification enforces ES256, `kid`, issuer, audience, expiry,
and token purpose.

[Back to the documentation index](../README.md#documentation)
