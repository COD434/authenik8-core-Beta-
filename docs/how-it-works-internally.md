# How It Works Internally

Authenik8-core combines signed JWT claims with Redis-backed lifecycle state.
Signature verification establishes token authenticity; state-aware verification
additionally enforces revocation, rotation, and quarantine.

Internal flows are documented separately:

- [Refresh-token rotation](./refresh-token-rotation.md)
- [Replay-attack detection](./replay-attack-detection.md)
- [Stateful session control](./stateful-session-control.md)
- [Security layer](./security-layer.md)
- [Why stateful authentication matters](./why-stateful-matters.md)

[Back to the documentation index](../README.md#documentation)
