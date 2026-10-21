# ADR-0014. The Ktor engines see the transport only through `Http3Endpoint`

Date: 2026-10-08. Status: accepted (adopted while building the Ktor engines as an implementation ruling; approved by the owner when they were merged into `main` 2026-10-08).

## Context

The layer rule (ADR-0005) forbids the Ktor engine modules from importing `kuicksilver-quic` directly, but the engines' configuration
exposes `QuicConfig`, `QuicEndpointConfig`, `TrustConfig` and `ConnectionAdmission`. If an engine opened
`QuicEndpoint` itself and wrapped connections in `Http3Connection`, the layer rule of ADR-0005 would be broken, and the logic "ALPN h3,
H3_DATAGRAM settings from the transport, closing connections with a foreign ALPN" would be duplicated in two engines.

## Decision

- `kuicksilver-http3` publishes the `Http3Endpoint` facade (`bind`, `connect`, `accept`, `close`): it holds the `QuicEndpoint`,
  checks ALPN `h3`, sets `SETTINGS_H3_DATAGRAM` from `QuicConfig.maxDatagramFrameSize` and hands out ready
  `Http3Connection`s.
- `kuicksilver-ktor-server` and `kuicksilver-ktor-client` declare dependencies only on `kuicksilver-http3` and
  `kuicksilver-ktor-network` (checked by `checkLayerDependencies`; test configurations are not checked); the QUIC/TLS
  configuration types arrive transitively through `api`.

## Consequences

- The transport can change without touching the engines as long as `Http3Endpoint` is stable.
- QUIC settings that are not in `QuicConfig`/`QuicEndpointConfig` (for example, UDP buffer sizes) cannot be declared by an engine —
  the QUIC layer has to add them first (ruling of 2026-10-08: `udpReceiveBufferSize` is not declared).
- The engine tests (the vendored Ktor contract) may depend on other engine modules only in test
  configurations.

## Rejected

- Importing `kuicksilver-quic` directly from the engines — breaks ADR-0005 and duplicates the h3 connection logic.
- A separate adapter module between the engines and http3 — an extra published artifact for the sake of one facade.
