# ADR-0008. 0-RTT is disabled in v1

Date: 2026-10-02. Status: superseded by [ADR-0015](0015-0rtt-implementation.md) in 0.2.0 (0-RTT opt-in); accepted 2026-10-02.

## Context

0-RTT data can be replayed; protection requires the application's participation (idempotency, anti-replay on the server). OpenSSL 3.5 supports 0-RTT for third-party stacks (`SSL_set_quic_tls_early_data_enabled`).

## Decision

0-RTT is not implemented in v1: `early_data` is not enabled, incoming 0-RTT packets are dropped, the API has `EarlyDataState.Disabled` and room for future settings. The interop case `zerortt` is "not supported".

## Consequences

- No replay risk in v1; resumption takes one RTT longer.
- Enabling it after v1 does not change the public transport API.
