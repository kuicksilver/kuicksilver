# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
# Which configuration classes tools/check/config-table.sh checks against which section of docs/guide/configuration.md.
# <heading of the section> | <source file> | <class, Outer.Inner> | var (public var in the body) | ctor (public val of the constructor)
QuicConfig | kuicksilver-quic/src/commonMain/kotlin/io/kuicksilver/quic/QuicConfig.kt | QuicConfig.Builder | var
QuicClientConfig and QuicServerConfig | kuicksilver-quic/src/commonMain/kotlin/io/kuicksilver/quic/QuicEndpointConfig.kt | QuicClientConfig.Builder | var
QuicClientConfig and QuicServerConfig | kuicksilver-quic/src/commonMain/kotlin/io/kuicksilver/quic/QuicEndpointConfig.kt | QuicServerConfig.Builder | var
QuicEndpointConfig | kuicksilver-quic/src/commonMain/kotlin/io/kuicksilver/quic/QuicEndpointConfig.kt | QuicEndpointConfig.Builder | var
TlsConfig | kuicksilver-tls/src/commonMain/kotlin/io/kuicksilver/tls/TlsConfig.kt | TlsConfig.Builder | var
SessionTicketConfig | kuicksilver-tls/src/commonMain/kotlin/io/kuicksilver/tls/TlsConfig.kt | SessionTicketConfig | ctor
Http3Settings | kuicksilver-http3/src/commonMain/kotlin/io/kuicksilver/http3/Http3Settings.kt | Http3Settings.Builder | var
CapsuleConfig | kuicksilver-http3/src/commonMain/kotlin/io/kuicksilver/http3/Capsules.kt | CapsuleConfig.Builder | var
Http2Settings | kuicksilver-http2/src/commonMain/kotlin/io/kuicksilver/http2/Http2Settings.kt | Http2Settings | ctor
Ktor client engine | kuicksilver-ktor-client/src/commonMain/kotlin/io/kuicksilver/ktor/client/KuicksilverEngineConfig.kt | KuicksilverEngineConfig | var
HTTP/2 client options | kuicksilver-ktor-client/src/commonMain/kotlin/io/kuicksilver/ktor/client/KuicksilverEngineConfig.kt | Http2ClientConfig | var
HTTP/3 client options | kuicksilver-ktor-client/src/commonMain/kotlin/io/kuicksilver/ktor/client/KuicksilverEngineConfig.kt | Http3ClientConfig | var
Ktor server engine | kuicksilver-ktor-server/src/commonMain/kotlin/io/kuicksilver/ktor/server/KuicksilverApplicationEngine.kt | KuicksilverApplicationEngine.Configuration | var
TLS connector | kuicksilver-ktor-server/src/commonMain/kotlin/io/kuicksilver/ktor/server/KuicksilverTlsConnector.kt | KuicksilverTlsConnector.Builder | var
