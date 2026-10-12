# Architecture Decision Records

One decision per file, numbered. Format: context, decision, consequences, alternatives rejected. Status values: proposed, accepted, superseded.

Documents and identifiers are in English.

| № | Title | Status |
|---|---|---|
| [0001](0001-thin-native-layer.md) | A thin native layer, everything else in Kotlin | accepted |
| [0002](0002-openssl-first-backend.md) | OpenSSL 3.5 is the first TLS backend, BoringSSL the fallback, the transport depends on the `QuicCrypto` interface | accepted |
| [0003](0003-ksl-single-c-shim.md) | One narrow C shim `ksl` with a shared header for JNI and cinterop | accepted |
| [0004](0004-sans-io-core.md) | The QUIC core is sans-IO | accepted |
| [0005](0005-layer-dependency-direction.md) | Dependency direction `ktor → http3 → quic → tls → native` | accepted |
| [0006](0006-datagram-io-interface.md) | UDP behind the `DatagramIo` interface: portable and accelerated implementations | accepted |
| [0007](0007-symbol-prefixing.md) | Symbol isolation: a version script for JNI, OpenSSL symbol prefixing for Kotlin/Native | accepted |
| [0008](0008-no-0rtt-in-v1.md) | 0-RTT is disabled in v1 | accepted |
| [0009](0009-no-http2-in-v1.md) | No HTTP/2 in v1 | accepted |
| [0010](0010-apache-2-license.md) | Apache-2.0 license | accepted |
| [0011](0011-trust-config-rules.md) | Trust rules: the name can be replaced but not disabled; the pin is always checked | accepted |
| [0012](0012-certificate-verify-pause.md) | Certificate verification with a handshake pause (`SSL_set_retry_verify`), without upcalls from C | accepted |
| [0013](0013-0rtt-anti-replay-design.md) | Anti-replay design for 0-RTT: ticket freshness in `ksl`, a single-use window per loop, idempotency decided by the application | proposed (design only; implementation after v1, 0-RTT stays disabled in v1 per ADR-0008) |
| [0014](0014-ktor-engines-via-http3-endpoint.md) | The Ktor engines see the transport only through `Http3Endpoint` | accepted |
| [0015](0015-0rtt-implementation.md) | 0-RTT in 0.2.0: ksl ABI 6 early data, a per-server replay register keyed by ticket, configuration-bound tickets, HTTP/3 gating | accepted |
