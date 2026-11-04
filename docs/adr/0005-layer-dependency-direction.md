# ADR-0005. Dependency direction `ktor → http3 → quic → tls → native`

Date: 2026-10-02. Status: accepted (approved by the owner 2026-10-02).

## Decision

Layers, each sees only the one directly below: `kuicksilver-ktor-client` / `kuicksilver-ktor-server` → `kuicksilver-http3` → `kuicksilver-quic` → `kuicksilver-tls` → `kuicksilver-native` (the Ktor engines additionally use `kuicksilver-ktor-network` for HTTP/1.1 over TLS; clarified 2026-10-08, when the Ktor engines were split: two engine modules instead of a single `kuicksilver-ktor`). Enforced by a dependency rule in Gradle.

Clarified 2026-11-04 (ADR-0017): `kuicksilver-http2` sits next to `kuicksilver-http3` and depends only on `kuicksilver-native` (for the API annotations), not on QUIC or TLS; the Ktor engines depend on `kuicksilver-http3`, `kuicksilver-http2` and `kuicksilver-ktor-network`.

## Consequences

- A raw QUIC consumer does not need HTTP/3 or Ktor; a TLS socket consumer does not need QUIC.
- `Socket.tls(...)` for `ktor-network` lives in a separate module `kuicksilver-ktor-network` that depends only on `kuicksilver-tls` and `ktor-network` (owner decision 2026-10-02).
