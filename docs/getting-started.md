# Getting Started

Generate and persist an ES256 private JWK once. Do not generate a new key every
time the process starts.

```ts
import {
  createAuthenik8,
  generateSigningJwk,
  verifyAccessTokenWithJwks,
} from "authenik8-core";

const privateJwk = await generateSigningJwk("2026-07-primary");
// Store privateJwk in your secret manager before constructing the engine.

const auth = await createAuthenik8({
  jwt: {
    keys: [privateJwk],
    activeKid: "2026-07-primary",
    issuer: "https://api.example.com",
    audience: "example-api",
  },
  refreshSecret: process.env.REFRESH_SECRET!,
  redisKeyPrefix: "example-api:production",
});

app.get("/.well-known/jwks.json", (_req, res) => res.json(auth.getJwks()));
app.get("/protected", auth.requireAuth, (_req, res) => res.sendStatus(204));

const tokens = await auth.issueTokens({
  userId: "user_1",
  email: "test@example.com",
});
const payload = await auth.verifyToken(tokens.accessToken);

// A separate service can verify with public keys only (or pass a JWKS URL).
const publicPayload = await verifyAccessTokenWithJwks(
  tokens.accessToken,
  auth.getJwks(),
  { issuer: "https://api.example.com", audience: "example-api" },
);
```

`verifyToken()` verifies signature and claims only. Use
`verifyActiveToken()` or `requireAuth` whenever Redis revocation and
quarantine must be enforced.

`jwtSecret` remains available as a deprecated JOSE/HS256 migration path. It
does not provide a public JWKS and should not be used for new applications.
If it is temporarily required, both it and `refreshSecret` need at least 32
bytes of independent random material.

The host application must load its environment before construction (for
example with a runtime `--env-file` option or an application-owned dotenv
bootstrap). Importing Authenik8-core never changes `process.env`.

[Back to the documentation index](../README.md#documentation)
