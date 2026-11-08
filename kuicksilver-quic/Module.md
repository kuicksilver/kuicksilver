# Module kuicksilver-quic

QUIC v1 and v2 (RFC 9000, 9001, 9002, 9369) for Kotlin Multiplatform: endpoints, connections, streams, datagrams
(RFC 9221), connection migration and path MTU discovery, as a coroutine API over a sans-IO core. Guide:
`docs/guide/quic.md`.

# Package io.kuicksilver.quic

`QuicEndpoint.bind`, `QuicConnection`, `QuicStream`, the configuration builders (`quicConfig { }`,
`quicClientConfig`, `quicServerConfig`, `quicEndpointConfig`), connection events and statistics, `QuicException`, and the
sans-IO level (`ConnectionCore`, `EndpointCore`) for callers with their own event loop.

# Package io.kuicksilver.quic.qlog

qlog sinks: `DirectoryQlogSink` writes one trace file per connection, `AsyncQlogSink` moves the writing off the endpoint
loop.
