// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.engineinterop

import io.ktor.client.HttpClient
import io.ktor.client.HttpClientConfig
import io.ktor.client.engine.cio.CIO
import io.ktor.client.engine.java.Java
import io.ktor.client.engine.okhttp.OkHttp
import io.ktor.client.plugins.HttpTimeout
import io.ktor.client.plugins.websocket.WebSockets
import io.ktor.websocket.WebSocketDeflateExtension
import io.kuicksilver.ktor.client.Http3DiscoveryMode
import io.kuicksilver.ktor.client.Kuicksilver
import io.kuicksilver.ktor.network.websocket.PerMessageDeflate
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import kotlin.time.Duration
import kotlin.time.Duration.Companion.seconds

/** The Ktor client engines of the bench and what each one can do. */
internal enum class ClientEngine(
    val label: String,
    /** It speaks HTTP/2 (over TLS, by ALPN). */
    val http2: Boolean,
    /** It negotiates WebSocket extensions (Ktor's WebSocketExtensionsCapability). */
    val wsExtensions: Boolean,
) {
    Kuicksilver("Kuicksilver", http2 = true, wsExtensions = true),
    Cio("Ktor CIO", http2 = false, wsExtensions = true),
    OkHttp("Ktor OkHttp", http2 = true, wsExtensions = false),
    Java("Ktor Java", http2 = true, wsExtensions = false),
}

/**
 * A Ktor client of [engine] that trusts the test CA ([otherCa]: an unrelated CA only). [http2] off keeps it on HTTP/1.1
 * (ALPN `http/1.1` only), [h3Only] puts Kuicksilver's client on HTTP/3 alone. [deflate] offers permessage-deflate:
 * PerMessageDeflate on ours, Ktor's WebSocketDeflateExtension on CIO.
 */
internal fun ktorClient(
    engine: ClientEngine,
    http2: Boolean = true,
    h3Only: Boolean = false,
    otherCa: Boolean = false,
    deflate: Boolean = false,
    quicIdleTimeout: Duration? = null,
    qlog: io.kuicksilver.quic.QlogSink? = null,
    block: HttpClientConfig<*>.() -> Unit = {},
): HttpClient {
    val common: HttpClientConfig<*>.() -> Unit = {
        expectSuccess = false
        install(HttpTimeout)
        install(WebSockets) {
            // Ktor's OkHttp engine refuses any maxFrameSize (OkHttp has its own limits)
            if (engine != ClientEngine.OkHttp) maxFrameSize = 4L shl 20
            if (deflate) {
                extensions {
                    if (engine == ClientEngine.Kuicksilver) install(PerMessageDeflate) else install(WebSocketDeflateExtension)
                }
            }
        }
        block()
    }
    return when (engine) {
        ClientEngine.Kuicksilver -> {
            HttpClient(Kuicksilver) {
                engine {
                    trust = if (otherCa) Pki.otherTrust else Pki.trust
                    http3 { discovery = if (h3Only) Http3DiscoveryMode.H3Only else Http3DiscoveryMode.H1Only }
                    http2 { enabled = http2 }
                    quicIdleTimeout?.let { t -> quic = io.kuicksilver.quic.quicConfig { maxIdleTimeout = t } }
                    qlog?.let { http3 { this.qlog = it } }
                }
                common()
            }
        }

        ClientEngine.Cio -> {
            HttpClient(CIO) {
                engine { https { trustManager = Pki.trustManager(otherCa) } }
                common()
            }
        }

        ClientEngine.OkHttp -> {
            HttpClient(OkHttp) {
                engine {
                    config {
                        sslSocketFactory(Pki.clientContext(otherCa).socketFactory, Pki.trustManager(otherCa))
                        protocols(
                            if (http2) listOf(okhttp3.Protocol.HTTP_2, okhttp3.Protocol.HTTP_1_1) else listOf(okhttp3.Protocol.HTTP_1_1),
                        )
                    }
                }
                common()
            }
        }

        ClientEngine.Java -> {
            HttpClient(Java) {
                engine {
                    config {
                        sslContext(Pki.clientContext(otherCa))
                        version(if (http2) java.net.http.HttpClient.Version.HTTP_2 else java.net.http.HttpClient.Version.HTTP_1_1)
                    }
                }
                common()
            }
        }
    }
}

/** A test body with a deadline: a hang fails the test instead of the build. */
internal fun interopTest(
    timeout: Duration = 60.seconds,
    block: suspend () -> Unit,
) = runBlocking { withTimeout(timeout) { block() } }

/** Every qlog record of our client's QUIC connections, in memory, for tests that assert which frames went out. */
internal class RecordingQlog : io.kuicksilver.quic.QlogSink {
    private val records = java.util.concurrent.ConcurrentLinkedQueue<String>()

    override fun open(
        odcidHex: String,
        role: io.kuicksilver.tls.TlsRole,
    ): io.kuicksilver.quic.QlogTrace =
        object : io.kuicksilver.quic.QlogTrace {
            override fun write(record: String) {
                records += record
            }

            override fun close() = Unit
        }

    /** The frame types of every packet sent so far. */
    fun sentFrames(): Set<String> =
        records
            .filter { "\"transport:packet_sent\"" in it }
            .flatMap { r -> Regex("\"frame_type\":\"([a-z_]+)\"").findAll(r).map { it.groupValues[1] } }
            .toSet()
}
