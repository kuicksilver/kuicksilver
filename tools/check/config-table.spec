# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
# Which configuration classes tools/check/config-table.sh checks against which section of docs/guide/configuration.md.
# <heading of the section> | <source file> | <class, Outer.Inner> | var (options in the body) | ctor (public val of the
# constructor) | <the DSL path from a #root to the class, dot-separated; - for a class built by its constructor>
# The heading of a block's section is its DSL path (ADR-0026).

# The roots of the DSL paths: `#root <name> | <class> | <file>`.
#root engine | KuicksilverEngineConfig | kuicksilver-ktor-client/src/commonMain/kotlin/io/kuicksilver/ktor/client/KuicksilverEngineConfig.kt
#root configure | KuicksilverApplicationEngine.Configuration | kuicksilver-ktor-server/src/commonMain/kotlin/io/kuicksilver/ktor/server/KuicksilverApplicationEngine.kt
#root quicConfig | QuicConfig.Builder | kuicksilver-quic/src/commonMain/kotlin/io/kuicksilver/quic/QuicConfig.kt
#root quicEndpointConfig | QuicEndpointConfig.Builder | kuicksilver-quic/src/commonMain/kotlin/io/kuicksilver/quic/QuicEndpointConfig.kt
#root quicClientConfig | QuicClientConfig.Builder | kuicksilver-quic/src/commonMain/kotlin/io/kuicksilver/quic/QuicEndpointConfig.kt
#root quicServerConfig | QuicServerConfig.Builder | kuicksilver-quic/src/commonMain/kotlin/io/kuicksilver/quic/QuicEndpointConfig.kt
#root tlsConfig | TlsConfig.Builder | kuicksilver-tls/src/commonMain/kotlin/io/kuicksilver/tls/TlsConfig.kt
#root http3Settings | Http3Settings.Builder | kuicksilver-http3/src/commonMain/kotlin/io/kuicksilver/http3/Http3Settings.kt
#root capsuleConfig | CapsuleConfig.Builder | kuicksilver-http3/src/commonMain/kotlin/io/kuicksilver/http3/Capsules.kt
#root http2Settings | Http2Settings.Builder | kuicksilver-http2/src/commonMain/kotlin/io/kuicksilver/http2/Http2Settings.kt

# Ktor client
`engine { }` | kuicksilver-ktor-client/src/commonMain/kotlin/io/kuicksilver/ktor/client/KuicksilverEngineConfig.kt | KuicksilverEngineConfig | var | engine
`engine { tls { } }` | kuicksilver-ktor-client/src/commonMain/kotlin/io/kuicksilver/ktor/client/KuicksilverEngineConfig.kt | ClientTlsConfig | var | engine.tls
`engine { tls { ech { } } }` | kuicksilver-ktor-client/src/commonMain/kotlin/io/kuicksilver/ktor/client/Ech.kt | EchClientConfig | var | engine.tls.ech
`engine { http3 { } }` | kuicksilver-ktor-client/src/commonMain/kotlin/io/kuicksilver/ktor/client/KuicksilverEngineConfig.kt | Http3ClientConfig | var | engine.http3
`engine { http3 { earlyData { } } }` | kuicksilver-ktor-client/src/commonMain/kotlin/io/kuicksilver/ktor/client/KuicksilverEngineConfig.kt | ClientEarlyDataConfig | var | engine.http3.earlyData
`engine { http3 { stall { } } }` | kuicksilver-ktor-client/src/commonMain/kotlin/io/kuicksilver/ktor/client/KuicksilverEngineConfig.kt | StallConfig | var | engine.http3.stall
`engine { http3 { webTransport { } } }` | kuicksilver-ktor-client/src/commonMain/kotlin/io/kuicksilver/ktor/client/KuicksilverEngineConfig.kt | ClientWebTransportConfig | var | engine.http3.webTransport
`engine { http3 { expert { } } }` | kuicksilver-ktor-client/src/commonMain/kotlin/io/kuicksilver/ktor/client/KuicksilverEngineConfig.kt | Http3ClientExpert | var | engine.http3.expert
`engine { http2 { } }` | kuicksilver-ktor-client/src/commonMain/kotlin/io/kuicksilver/ktor/client/KuicksilverEngineConfig.kt | Http2ClientConfig | var | engine.http2
`engine { http1 { } }` | kuicksilver-ktor-client/src/commonMain/kotlin/io/kuicksilver/ktor/client/KuicksilverEngineConfig.kt | Http1ClientConfig | var | engine.http1
`engine { pool { } }` | kuicksilver-ktor-client/src/commonMain/kotlin/io/kuicksilver/ktor/client/KuicksilverEngineConfig.kt | PoolConfig | var | engine.pool
`engine { network { } }` | kuicksilver-ktor-client/src/commonMain/kotlin/io/kuicksilver/ktor/client/KuicksilverEngineConfig.kt | ClientNetworkConfig | var | engine.network
`engine { proxies { } }` | kuicksilver-ktor-client/src/commonMain/kotlin/io/kuicksilver/ktor/client/KuicksilverEngineConfig.kt | ProxiesConfig | var | engine.proxies
`engine { webSockets { } }` | kuicksilver-ktor-client/src/commonMain/kotlin/io/kuicksilver/ktor/client/KuicksilverEngineConfig.kt | ClientWebSocketsConfig | var | engine.webSockets
`engine { observability { } }` | kuicksilver-ktor-client/src/commonMain/kotlin/io/kuicksilver/ktor/client/KuicksilverEngineConfig.kt | ClientObservability | var | engine.observability

# Ktor server
`configure { }` | kuicksilver-ktor-server/src/commonMain/kotlin/io/kuicksilver/ktor/server/KuicksilverApplicationEngine.kt | KuicksilverApplicationEngine.Configuration | var | configure
`configure { tls { } }` | kuicksilver-ktor-server/src/commonMain/kotlin/io/kuicksilver/ktor/server/KuicksilverServerConfig.kt | ServerTlsConfig | var | configure.tls
`configure { tlsConnector { } }` | kuicksilver-ktor-server/src/commonMain/kotlin/io/kuicksilver/ktor/server/KuicksilverTlsConnector.kt | KuicksilverTlsConnector.Builder | var | configure.tlsConnector
`configure { plainConnector { } }` | kuicksilver-ktor-server/src/commonMain/kotlin/io/kuicksilver/ktor/server/KuicksilverPlainConnector.kt | KuicksilverPlainConnector.Builder | var | configure.plainConnector
`configure { tlsConnector { proxyProtocol { } } }` | kuicksilver-ktor-server/src/commonMain/kotlin/io/kuicksilver/ktor/server/ProxyProtocol.kt | ProxyProtocolConfig.Builder | var | configure.tlsConnector.proxyProtocol
`configure { http1 { } }` | kuicksilver-ktor-server/src/commonMain/kotlin/io/kuicksilver/ktor/server/KuicksilverServerConfig.kt | Http1ServerConfig | var | configure.http1
`configure { http2 { } }` | kuicksilver-ktor-server/src/commonMain/kotlin/io/kuicksilver/ktor/server/KuicksilverServerConfig.kt | Http2ServerConfig | var | configure.http2
`configure { http3 { } }` | kuicksilver-ktor-server/src/commonMain/kotlin/io/kuicksilver/ktor/server/KuicksilverServerConfig.kt | Http3ServerConfig | var | configure.http3
`configure { http3 { earlyData { } } }` | kuicksilver-ktor-server/src/commonMain/kotlin/io/kuicksilver/ktor/server/KuicksilverServerConfig.kt | ServerEarlyDataConfig | var | configure.http3.earlyData
`configure { http3 { webTransport { } } }` | kuicksilver-ktor-server/src/commonMain/kotlin/io/kuicksilver/ktor/server/KuicksilverServerConfig.kt | ServerWebTransportConfig | var | configure.http3.webTransport
`configure { http3 { endpoint { } } }` | kuicksilver-ktor-server/src/commonMain/kotlin/io/kuicksilver/ktor/server/KuicksilverServerConfig.kt | ServerEndpointConfig | var | configure.http3.endpoint
`configure { http3 { endpoint { expert { } } } }` | kuicksilver-ktor-server/src/commonMain/kotlin/io/kuicksilver/ktor/server/KuicksilverServerConfig.kt | ServerEndpointExpert | var | configure.http3.endpoint.expert
`configure { webSockets { } }` | kuicksilver-ktor-server/src/commonMain/kotlin/io/kuicksilver/ktor/server/KuicksilverServerConfig.kt | ServerWebSocketsConfig | var | configure.webSockets
`configure { tcp { } }` | kuicksilver-ktor-server/src/commonMain/kotlin/io/kuicksilver/ktor/server/KuicksilverServerConfig.kt | TcpLimitsConfig | var | configure.tcp
`configure { observability { } }` | kuicksilver-ktor-server/src/commonMain/kotlin/io/kuicksilver/ktor/server/KuicksilverServerConfig.kt | ServerObservability | var | configure.observability

# HOCON keys of EngineMain, and the old keys it refuses
HOCON keys | kuicksilver-ktor-server/src/commonMain/kotlin/io/kuicksilver/ktor/server/EngineMain.kt | KNOWN_KEYS | keys
`application.conf` keys | kuicksilver-ktor-server/src/commonMain/kotlin/io/kuicksilver/ktor/server/EngineMain.kt | RENAMED_KEYS | renamed

# Low level
`quicConfig { }` | kuicksilver-quic/src/commonMain/kotlin/io/kuicksilver/quic/QuicConfig.kt | QuicConfig.Builder | var | quicConfig
`quicConfig { flowControl { } }` | kuicksilver-quic/src/commonMain/kotlin/io/kuicksilver/quic/QuicConfig.kt | QuicConfig.Builder.FlowControl | var | quicConfig.flowControl
`quicConfig { pathMtu { } }` | kuicksilver-quic/src/commonMain/kotlin/io/kuicksilver/quic/QuicConfig.kt | QuicConfig.Builder.PathMtu | var | quicConfig.pathMtu
`quicConfig { datagrams { } }` | kuicksilver-quic/src/commonMain/kotlin/io/kuicksilver/quic/QuicConfig.kt | QuicConfig.Builder.Datagrams | var | quicConfig.datagrams
`quicConfig { migration { } }` | kuicksilver-quic/src/commonMain/kotlin/io/kuicksilver/quic/QuicConfig.kt | QuicConfig.Builder.Migration | var | quicConfig.migration
`quicConfig { expert { } }` | kuicksilver-quic/src/commonMain/kotlin/io/kuicksilver/quic/QuicConfig.kt | QuicConfig.Builder.Expert | var | quicConfig.expert
`quicClientConfig(tls) { }` and `quicServerConfig(tls) { }` | kuicksilver-quic/src/commonMain/kotlin/io/kuicksilver/quic/QuicEndpointConfig.kt | QuicClientConfig.Builder | var | quicClientConfig
`quicClientConfig(tls) { }` and `quicServerConfig(tls) { }` | kuicksilver-quic/src/commonMain/kotlin/io/kuicksilver/quic/QuicEndpointConfig.kt | QuicServerConfig.Builder | var | quicServerConfig
`quicEndpointConfig { }` | kuicksilver-quic/src/commonMain/kotlin/io/kuicksilver/quic/QuicEndpointConfig.kt | QuicEndpointConfig.Builder | var | quicEndpointConfig
`quicEndpointConfig { observability { } }` | kuicksilver-quic/src/commonMain/kotlin/io/kuicksilver/quic/QuicEndpointConfig.kt | QuicEndpointConfig.Builder.Observability | var | quicEndpointConfig.observability
`quicEndpointConfig { runtime { } }` | kuicksilver-quic/src/commonMain/kotlin/io/kuicksilver/quic/QuicEndpointConfig.kt | QuicEndpointConfig.Builder.Runtime | var | quicEndpointConfig.runtime
`quicEndpointConfig { expert { } }` | kuicksilver-quic/src/commonMain/kotlin/io/kuicksilver/quic/QuicEndpointConfig.kt | QuicEndpointConfig.Builder.Expert | var | quicEndpointConfig.expert
`tlsConfig(role) { }` | kuicksilver-tls/src/commonMain/kotlin/io/kuicksilver/tls/TlsConfig.kt | TlsConfig.Builder | var | tlsConfig
`tlsConfig(role) { ech { } }` | kuicksilver-tls/src/commonMain/kotlin/io/kuicksilver/tls/TlsConfig.kt | TlsConfig.Builder.Ech | var | tlsConfig.ech
`tlsConfig(role) { expert { } }` | kuicksilver-tls/src/commonMain/kotlin/io/kuicksilver/tls/TlsConfig.kt | TlsConfig.Builder.Expert | var | tlsConfig.expert
`SessionTicketConfig(…)` | kuicksilver-tls/src/commonMain/kotlin/io/kuicksilver/tls/TlsConfig.kt | SessionTicketConfig | ctor | -
`http3Settings { }` | kuicksilver-http3/src/commonMain/kotlin/io/kuicksilver/http3/Http3Settings.kt | Http3Settings.Builder | var | http3Settings
`http3Settings { qpack { } }` | kuicksilver-http3/src/commonMain/kotlin/io/kuicksilver/http3/Http3Settings.kt | Http3Settings.Builder.Qpack | var | http3Settings.qpack
`http3Settings { webTransport { } }` | kuicksilver-http3/src/commonMain/kotlin/io/kuicksilver/http3/Http3Settings.kt | Http3Settings.Builder.WebTransport | var | http3Settings.webTransport
`http3Settings { expert { } }` | kuicksilver-http3/src/commonMain/kotlin/io/kuicksilver/http3/Http3Settings.kt | Http3Settings.Builder.Expert | var | http3Settings.expert
`capsuleConfig { }` | kuicksilver-http3/src/commonMain/kotlin/io/kuicksilver/http3/Capsules.kt | CapsuleConfig.Builder | var | capsuleConfig
`UdpProxyConfig(…)` | kuicksilver-http3/src/commonMain/kotlin/io/kuicksilver/http3/ConnectUdp.kt | UdpProxyConfig | ctor | -
`http2Settings { }` | kuicksilver-http2/src/commonMain/kotlin/io/kuicksilver/http2/Http2Settings.kt | Http2Settings.Builder | var | http2Settings
`http2Settings { floodLimits { } }` | kuicksilver-http2/src/commonMain/kotlin/io/kuicksilver/http2/Http2Settings.kt | Http2Settings.Builder.FloodLimits | var | http2Settings.floodLimits

# The first-screen tables (sections whose heading starts with this): DSL paths, stable options only, at most 10 per root.
First screen | - | - | first-screen

# Rows of options the classes inherit or take as plain constructor parameters:
#allow `engine { }` | proxy
#allow `configure { }` | shutdownGracePeriod, shutdownTimeout
#allow `SessionTicketConfig(…)` | keys
#allow `quicClientConfig(tls) { }` and `quicServerConfig(tls) { }` | tls

# P9: options experimental by their own annotation inside a stable block (design section 6), each with its reason.
#field-experimental ClientTlsConfig.keyExchangeGroups | its type KeyExchangeGroups is experimental
#field-experimental ClientTlsConfig.revocation | its type RevocationPolicy is experimental
#field-experimental Http3ClientConfig.migration | its type Http3ConnectionMigration is experimental
#field-experimental Http2ClientConfig.priorKnowledge | h2c, a separately enabled feature (ADR-0018)
#field-experimental PoolConfig.coalescing | connection coalescing, a separately enabled feature (ADR-0018)
#field-experimental ClientNetworkConfig.dns | its type Dns is experimental (ADR-0020)
#field-experimental ClientNetworkConfig.httpsRecords | its type HttpsRecordSource is experimental
#field-experimental ClientNetworkConfig.httpsRecordWait | only used with httpsRecords, whose type is experimental
#field-experimental ClientObservability.eventListener | its type KuicksilverEventListener is experimental
#field-experimental ClientObservability.connectionListener | its type ConnectionListener is experimental
#field-experimental ServerTlsConfig.keyExchangeGroups | its type KeyExchangeGroups is experimental
#field-experimental ServerTlsConfig.ocspStapling | its type OcspStapling is experimental
#field-experimental ServerTlsConfig.ocspStaplingFile | sets ocspStapling, whose type OcspStapling is experimental
#field-experimental ServerTlsConfig.echKeys | its type EchServerKeys is experimental
#field-experimental KuicksilverPlainConnector.Builder.h2c | h2c, a separately enabled feature (ADR-0018)
#field-experimental Http2ServerConfig.repeatOffenderPenalty | a new defence whose threshold is still being tuned (ADR-0017)
#field-experimental Http3ServerConfig.connectUdp | CONNECT-UDP, a separately enabled feature (ADR-0024)
#field-experimental ServerEndpointConfig.loadBalancer | its type QuicLbConfig is experimental
#field-experimental ServerObservability.connectionListener | its type ConnectionListener is experimental
#field-experimental ServerObservability.eventListener | its type KuicksilverServerEventListener is experimental
#field-experimental QuicClientConfig.Builder.earlyData | 0-RTT, a separately enabled feature (ADR-0015)
#field-experimental QuicClientConfig.Builder.tokenStore | its type QuicTokenStore is experimental
#field-experimental QuicServerConfig.Builder.acceptEarlyData | 0-RTT, a separately enabled feature (ADR-0015)
#field-experimental QuicServerConfig.Builder.earlyDataContext | 0-RTT, a separately enabled feature (ADR-0015)
#field-experimental QuicServerConfig.Builder.newTokenLifetime | NEW_TOKEN address validation, new in 0.3.0
#field-experimental QuicServerConfig.Builder.newTokenReplayCapacity | NEW_TOKEN address validation, new in 0.3.0
#field-experimental QuicServerConfig.Builder.preferredAddress | its type PreferredAddress is experimental
#field-experimental QuicEndpointConfig.Builder.loadBalancer | its type QuicLbConfig is experimental
#field-experimental QuicEndpointConfig.Builder.Observability.connectionListener | its type ConnectionListener is experimental
#field-experimental QuicEndpointConfig.Builder.Runtime.io | its type DatagramIo is a port and test hook
#field-experimental QuicEndpointConfig.Builder.Runtime.crypto | its type QuicCrypto is a port and test hook
#field-experimental TlsConfig.Builder.revocation | its type RevocationPolicy is experimental
#field-experimental TlsConfig.Builder.ocspStapling | its type OcspStapling is experimental
#field-experimental TlsConfig.Builder.keyExchangeGroups | its type KeyExchangeGroups is experimental
#field-experimental Http3Settings.Builder.earlyData | 0-RTT, a separately enabled feature (ADR-0015)

# Mapping tests (design 7.2.1): every option name of a module's spec'd classes appears in one of them.
#mapped kuicksilver-ktor-client | kuicksilver-ktor-client/src/commonTest/kotlin/io/kuicksilver/ktor/client/ClientConfigMappingTest.kt
#mapped kuicksilver-ktor-server | kuicksilver-ktor-server/src/commonTest/kotlin/io/kuicksilver/ktor/server/ServerConfigMappingTest.kt
#mapped kuicksilver-quic | kuicksilver-quic/src/commonTest/kotlin/io/kuicksilver/quic/ConfigGroupsTest.kt
#mapped kuicksilver-http3 | kuicksilver-http3/src/commonTest/kotlin/io/kuicksilver/http3/Http3SettingsGroupsTest.kt
#mapped kuicksilver-http2 | kuicksilver-http2/src/commonTest/kotlin/io/kuicksilver/http2/Http2SettingsBuilderTest.kt
#unmapped TlsConfig.Builder | the builder is the TlsConfig: its options are read back by name (TlsConfig keeps public readers, P10) and tested where each one acts
#unmapped TlsConfig.Builder.Ech | read back as TlsConfig.echConfigList, echGrease and echKeys and tested where ECH acts (EchTest)
#unmapped TlsConfig.Builder.Expert | read back as TlsConfig.genericAlerts and alpnFallback and tested where each acts
#unmapped SessionTicketConfig | a constructor-configured value: its parameters are its properties
#unmapped UdpProxyConfig | a constructor-configured value: its parameters are its properties
#unmapped CapsuleConfig.Builder | flat and unchanged by the 0.3.0 layout; tested where each option acts (CapsuleTest)
