// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(ExperimentalKuicksilverApi::class)

package io.kuicksilver.guide.client

// guide:ktor:client-imports
import io.ktor.client.HttpClient
import io.ktor.client.engine.ProxyBuilder
import io.ktor.client.engine.http
import io.ktor.client.plugins.HttpTimeout
import io.ktor.client.plugins.api.createClientPlugin
import io.ktor.client.plugins.websocket.WebSockets
import io.ktor.client.request.HttpRequestData
import io.ktor.client.request.get
import io.ktor.client.request.prepareGet
import io.ktor.client.statement.bodyAsChannel
import io.ktor.client.statement.bodyAsText
import io.ktor.http.HttpProtocolVersion
import io.ktor.utils.io.discard
import io.ktor.utils.io.readBuffer
import io.ktor.utils.io.writeFully
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.http2.Http2Settings
import io.kuicksilver.http2.http2Settings
import io.kuicksilver.http3.UdpProxyTemplate
import io.kuicksilver.ktor.client.ConnectFailure
import io.kuicksilver.ktor.client.ConnectUdpProxy
import io.kuicksilver.ktor.client.Dns
import io.kuicksilver.ktor.client.FileAltSvcStore
import io.kuicksilver.ktor.client.HostPort
import io.kuicksilver.ktor.client.Http3ConnectionMigration
import io.kuicksilver.ktor.client.Http3Discovery
import io.kuicksilver.ktor.client.HttpsRecordSource
import io.kuicksilver.ktor.client.IpAddress
import io.kuicksilver.ktor.client.Kuicksilver
import io.kuicksilver.ktor.client.KuicksilverEventListener
import io.kuicksilver.ktor.client.ProtocolReason
import io.kuicksilver.ktor.client.ProxyCredentials
import io.kuicksilver.ktor.client.ProxyResolver
import io.kuicksilver.ktor.client.ProxyResolvers
import io.kuicksilver.ktor.client.QuicConnectionSnapshot
import io.kuicksilver.ktor.client.ResolvedProxy
import io.kuicksilver.ktor.client.TcpConnectionSnapshot
import io.kuicksilver.ktor.client.Transport
import io.kuicksilver.ktor.client.closeHttp3Connections
import io.kuicksilver.ktor.client.kuicksilverDiagnostics
import io.kuicksilver.ktor.client.priority
import io.kuicksilver.ktor.client.updatePriority
import io.kuicksilver.ktor.client.webTransport
import io.kuicksilver.ktor.network.websocket.PerMessageDeflate
import io.kuicksilver.quic.KuicksilverLogger
import io.kuicksilver.quic.LogLevel
import io.kuicksilver.quic.qlog.AsyncQlogSink
import io.kuicksilver.quic.qlog.DirectoryQlogSink
import io.kuicksilver.tls.Certificate
import io.kuicksilver.tls.EchConfigList
import io.kuicksilver.tls.SpkiSha256
import io.kuicksilver.tls.TlsIdentity
import io.kuicksilver.tls.TrustConfig
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.io.readString
import java.io.File
import kotlin.time.Duration
import kotlin.time.Duration.Companion.minutes
import kotlin.time.Duration.Companion.seconds

/**
 * The import block docs/guide/ktor.md shows for its client samples (`guide:ktor:client-imports`), in a package of its own so
 * that every import is a real one: [everyClientImport] uses each, so a name that moves breaks this file.
 */
suspend fun everyClientImport(
    url: String,
    identity: TlsIdentity,
    caPem: String,
) {
    val allowed: StateFlow<Boolean> = MutableStateFlow(true)
    val client =
        HttpClient(Kuicksilver) {
            engine {
                tls { this.identity = identity }
                tls {
                    trust =
                        TrustConfig.Pinned(
                            setOf(SpkiSha256.parse("sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")),
                            base = TrustConfig.AnchoredCa(Certificate.parsePem(caPem)),
                        )
                }
                proxy = ProxyBuilder.http("http://proxy.corp.test:3128")
                proxies { credentials = ProxyCredentials("user", "password") }
                proxies { resolver = ProxyResolver { ResolvedProxy.http("proxy.corp.test", 3128, ProxyCredentials("user", "password")) } }
                pool { idleTimeout = 5.minutes }
                pool { maxConnectionLifetime = null }
                observability { logger = KuicksilverLogger.stderr(LogLevel.Info) }
                http2 {
                    settings { initialStreamWindow = 1 shl 20 }
                }
                http3 {
                    discovery = Http3Discovery.Auto
                    this.allowed = { allowed.value }
                }
                observability { qlog = AsyncQlogSink(DirectoryQlogSink("qlog")) }
                observability {
                    eventListener =
                        object : KuicksilverEventListener() {
                            override fun protocolSelected(
                                request: HttpRequestData,
                                protocol: HttpProtocolVersion,
                                reason: ProtocolReason,
                            ) {}

                            override fun connectFailed(
                                request: HttpRequestData,
                                failure: ConnectFailure,
                            ) {
                                println(failure.transport == Transport.Tcp)
                            }
                        }
                }
            }
            install(HttpTimeout) { connectTimeoutMillis = 5.seconds.inWholeMilliseconds }
            install(WebSockets) { extensions { install(PerMessageDeflate) } }
            install(createClientPlugin("ProtocolLog") { onResponse { println(it.kuicksilverDiagnostics?.fallback) } })
            install(
                createClientPlugin("ConnectionLog") {
                    onResponse {
                        val c = it.kuicksilverDiagnostics?.connection
                        println((c as? QuicConnectionSnapshot)?.smoothedRtt ?: (c as? TcpConnectionSnapshot)?.alpn)
                    }
                },
            )
        }
    println(client.get(url) { priority(urgency = 1) }.bodyAsText())
    client.prepareGet(url).execute { response ->
        response.updatePriority(urgency = 2, incremental = true)
        response.bodyAsChannel().discard()
    }
    val session = client.webTransport(url, protocols = listOf("echo-v1"))
    val stream = session.openBidi()
    stream.output.writeFully("ping".encodeToByteArray())
    println(stream.input.readBuffer().readString())
    client.closeHttp3Connections()
    HttpClient(Kuicksilver) {
        engine {
            http3 {
                hints = setOf(HostPort("api.example.com", 443))
                altSvcStore = FileAltSvcStore(File("alt-svc"))
                migration = Http3ConnectionMigration { _, _ -> error("the JVM has no network source of its own") }
            }
            network {
                dns = Dns { name -> if (name == "api.example.test") listOf(IpAddress.parse("192.0.2.10")) else Dns.System.lookup(name) }
                httpsRecords = HttpsRecordSource.System
            }
            tls { ech { configLists = mapOf("example.com" to EchConfigList.parseBase64(caPem)) } }
            proxies { resolver = ProxyResolvers.None }
        }
    }.close()
    HttpClient(Kuicksilver) { engine { proxies { connectUdp = ConnectUdpProxy(UdpProxyTemplate.wellKnown("masque.example")) } } }.close()
}
