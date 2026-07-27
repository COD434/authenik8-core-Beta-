<div align="center">

![Authenik8-core logo](https://raw.githubusercontent.com/COD434/authenik8-core-Beta-/main/logo.svg)

# Authenik8-core [Beta]

[![Pipeline status](https://gitlab.com/COD434/authenik8-core/badges/main/pipeline.svg)](https://gitlab.com/COD434/authenik8-core/-/pipelines)
[![Coverage](https://gitlab.com/COD434/authenik8-core/badges/main/coverage.svg)](https://gitlab.com/COD434/authenik8-core/-/pipelines)
[![NPM Version](https://img.shields.io/npm/v/authenik8-core.svg)](https://www.npmjs.com/package/authenik8-core)

</div>

Authenik8-core is a stateful JWT authentication SDK with refresh-token replay
protection, Redis-backed revocation, authorization, audit events, risk
quarantine, and scoped agent identities.

Start with [Getting Started](docs/getting-started.md), then review the
[requirements](docs/requirements.md) and [threat model](THREAT_MODEL.md) before
deploying.

## Documentation

### Start Here

- [What Authenik8-core does](docs/what-authenik8-does.md)
- [Getting started](docs/getting-started.md)
- [Requirements](docs/requirements.md)
- [Why Authenik8-core?](docs/why-authenik8.md)
- [Use cases](docs/use-cases.md)
- [Final thought](docs/final-thought.md)

### Authentication and Sessions

- [Replay-attack prevention example](docs/replay-attack-prevention.md)
- [Secure refresh flow](docs/secure-refresh-flow.md)
- [Key rotation](docs/key-rotation.md)
- [Session risk and quarantine](docs/session-risk-quarantine.md)
- [Agent and service identity](docs/agent-service-identity.md)

### Authorization and API

- [Authorization, tenants, and audit events](docs/authorization-tenants-audit.md)
- [API overview](docs/api-overview.md)
- [Security layer](docs/security-layer.md)

### Design and Internals

- [Architecture](docs/architecture.md)
- [How it works internally](docs/how-it-works-internally.md)
- [Refresh-token rotation](docs/refresh-token-rotation.md)
- [Replay-attack detection](docs/replay-attack-detection.md)
- [Stateful session control](docs/stateful-session-control.md)
- [Why stateful authentication matters](docs/why-stateful-matters.md)

### Assurance and Project Information

- [Testing](docs/testing.md)
- [Security audit](docs/security-audit.md)
- [Threats addressed](docs/threats-addressed.md)
- [Full threat model](THREAT_MODEL.md)
- [Repository setup](docs/repository-setup.md)
- [Changelog](CHANGELOG.md)
