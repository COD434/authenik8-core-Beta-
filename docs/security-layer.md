# Security Layer

Authenik8-core includes:

- Rate-limiting middleware.
- IP allow and deny controls.
- Secure HTTP headers through Helmet.
- Human authorization middleware.
- Tenant isolation.
- Structured audit events.
- Session-risk signals and quarantine.

These controls share authenticated identity and session context while remaining
separate services, limiting coupling between policy, persistence, and delivery.

Forwarding headers are ignored by default. If the application is behind a
reverse proxy, authorize only its networks:

```ts
const auth = await createAuthenik8({
  jwt,
  refreshSecret,
  redisKeyPrefix: "orders-api:production",
  trustedProxyCidrs: ["10.20.0.0/16", "2001:db8:100::/48"],
  security: {
    rateLimitPoints: 100,
    rateLimitDuration: 60,
    rateLimitBlock: 300,
  },
});
```

`trustProxyHeaders: true` without `trustedProxyCidrs` is rejected. The direct
socket peer must be trusted, and resolution stops at the first untrusted hop.
Configure the same policy at Express and the edge proxy; the proxy must replace,
not append to, client-supplied forwarding headers at the trust boundary.

IP allowlist entries accept canonical IPv4, IPv6, or CIDR values and expire
after seven days by default:

```ts
await auth.addIP("203.0.113.10", 3600);
await auth.addIP("2001:db8:abcd::/48");
```

Loopback is not automatically allowed. Add it explicitly if a local health or
administration path genuinely requires it.

The default Helmet CSP is enforcing and intentionally blocks inline scripts and
styles. Applications requiring nonces or additional origins should replace it
with a reviewed `security.helmetOptions` policy; do not restore
`'unsafe-inline'` as a convenience.

[Back to the documentation index](../README.md#documentation)
