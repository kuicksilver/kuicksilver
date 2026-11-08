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
import io.kuicksilver.ktor.client.Http3DiscoveryMode
import io.kuicksilver.ktor.client.Kuicksilver
import io.kuicksilver.ktor.client.KuicksilverEventListener
import io.kuicksilver.ktor.client.ProtocolReason
import io.kuicksilver.ktor.client.ProxyCredentials
import io.kuicksilver.ktor.client.ProxyResolver
import io.kuicksilver.ktor.client.ResolvedProxy
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
import io.kuicksilver.tls.SpkiSha256
import io.kuicksilver.tls.TlsIdentity
import io.kuicksilver.tls.TrustConfig
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.io.readString
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
                this.identity = identity
                trust =
                    TrustConfig.Pinned(
                        setOf(SpkiSha256.parse("sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")),
                        base = TrustConfig.AnchoredCa(Certificate.parsePem(caPem)),
                    )
                proxy = ProxyBuilder.http("http://proxy.corp.test:3128")
                proxyCredentials = ProxyCredentials("user", "password")
                proxyResolver = ProxyResolver { ResolvedProxy.http("proxy.corp.test", 3128, ProxyCredentials("user", "password")) }
                idleTimeout = 5.minutes
                maxConnectionLifetime = Duration.INFINITE
                logger = KuicksilverLogger.stderr(LogLevel.Info)
                http2 { settings = Http2Settings(initialStreamWindow = 1 shl 20) }
                http3 {
                    discovery = Http3DiscoveryMode.Auto
                    http3Allowed = { allowed.value }
                    qlog = AsyncQlogSink(DirectoryQlogSink("qlog"))
                }
                eventListener =
                    object : KuicksilverEventListener() {
                        override fun protocolSelected(
                            request: HttpRequestData,
                            protocol: HttpProtocolVersion,
                            reason: ProtocolReason,
                        ) {}
                    }
            }
            install(HttpTimeout) { connectTimeoutMillis = 5.seconds.inWholeMilliseconds }
            install(WebSockets) { extensions { install(PerMessageDeflate) } }
            install(createClientPlugin("ProtocolLog") { onResponse { println(it.kuicksilverDiagnostics?.fallback) } })
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
}
