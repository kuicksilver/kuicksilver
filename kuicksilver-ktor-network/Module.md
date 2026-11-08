# Module kuicksilver-ktor-network

TLS for ktor-network sockets: `Socket.tls()` on the client and `Socket.tlsServer()` on the server, plus the WebSocket
permessage-deflate extension the Ktor engines use. Guide: `docs/guide/tls.md`.

# Package io.kuicksilver.ktor.network

`Socket.tls()`, `Socket.tlsServer()` and the `TlsSocket` they return.

# Package io.kuicksilver.ktor.network.websocket

The WebSocket permessage-deflate extension (RFC 7692) for Ktor: `PerMessageDeflate` and its negotiated parameters.
