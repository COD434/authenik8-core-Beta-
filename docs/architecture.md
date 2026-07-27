# Architecture

```text
┌─────────────────┐
│     Client      │
│  Web / Mobile   │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  API / Backend  │
└────────┬────────┘
         │
         ▼
┌────────────────────────────┐
│      Authenik8-core        │
├────────────────────────────┤
│ JWT signing/verification   │
│ Refresh rotation/replay    │
│ Authorization/tenancy      │
│ Audit and risk signals     │
│ Agent identity             │
│ Security middleware        │
└─────────────┬──────────────┘
              │
              ▼
┌────────────────────────────┐
│           Redis            │
├────────────────────────────┤
│ Session fingerprints       │
│ Refresh-family state       │
│ Revocation/quarantine      │
│ Rate and signal windows    │
└────────────────────────────┘
```

Audit sinks and identity registries are application-owned dependencies. The SDK
uses narrow interfaces for those dependencies so their storage and delivery
choices remain outside the authentication core.

[Back to the documentation index](../README.md#documentation)
