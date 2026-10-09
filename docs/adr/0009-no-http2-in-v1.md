# ADR-0009. No HTTP/2 in v1

Date: 2026-10-02. Status: accepted (approved by the owner 2026-10-02).

## Context

The client engine must have a fallback on networks with UDP blocked (3–5 %). HTTP/2 is a separate large protocol (HPACK, multiplexing, priorities), not needed for QUIC or the TLS socket.

## Decision

Client: HTTP/3 and HTTP/1.1 over `TlsConnection` (parsing by `ktor-http-cio`). Server: HTTP/1.1 on TCP and HTTP/3 on UDP on the same port number. HTTP/2 is not implemented; ALPN `h2` is not offered.

## Consequences

- There is a fallback, and v1 is smaller.
- Against servers without h3 the client works over h1.1 — acceptable for the first version.
