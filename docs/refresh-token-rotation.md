# Refresh-Token Rotation

Each refresh token includes a unique identifier (`jti`). Redis stores a SHA-256
fingerprint of the current token for its refresh family.

During refresh:

1. The token signature, purpose, issuer, audience, and expiry are validated.
2. The supplied token fingerprint is compared with the current family record.
3. A Redis lock and compare-and-set transition allow only one rotation.
4. The old token is invalidated and a new token is issued with a new `jti`.
5. If a dependent security operation fails, the affected family is rolled back
   or revoked rather than leaving partially issued credentials.

[Back to the documentation index](../README.md#documentation)
