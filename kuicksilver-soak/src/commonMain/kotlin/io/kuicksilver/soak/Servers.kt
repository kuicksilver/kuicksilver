// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.soak

import io.ktor.http.ContentType
import io.ktor.network.sockets.InetSocketAddress
import io.ktor.server.engine.EmbeddedServer
import io.ktor.server.engine.embeddedServer
import io.ktor.server.request.receiveChannel
import io.ktor.server.response.respondBytes
import io.ktor.server.response.respondBytesWriter
import io.ktor.server.response.respondText
import io.ktor.server.routing.get
import io.ktor.server.routing.post
import io.ktor.server.routing.routing
import io.ktor.utils.io.ByteReadChannel
import io.ktor.utils.io.discard
import io.ktor.utils.io.readUTF8Line
import io.ktor.utils.io.writeFully
import io.ktor.utils.io.writeStringUtf8
import io.kuicksilver.ktor.server.Kuicksilver
import io.kuicksilver.ktor.server.KuicksilverApplicationEngine
import io.kuicksilver.quic.QuicConnection
import io.kuicksilver.quic.QuicEndpoint
import io.kuicksilver.quic.QuicServerConfig
import io.kuicksilver.quic.QuicStream
import io.kuicksilver.quic.quicConfig
import io.kuicksilver.quic.quicEndpointConfig
import io.kuicksilver.tls.Certificate
import io.kuicksilver.tls.TlsConfig
import io.kuicksilver.tls.TlsIdentity
import io.kuicksilver.tls.TlsRole
import io.kuicksilver.tls.TrustConfig
import io.kuicksilver.tls.tlsConfig
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch

/** The test PKI: one server identity (SANs server.test and 127.0.0.1) and the CA that clients trust. */
internal object SoakPki {
    val trust: TrustConfig by lazy { TrustConfig.AnchoredCa(listOf(Certificate(TestCerts.testCa))) }

    fun identity(): TlsIdentity = TlsIdentity.fromDer(listOf(TestCerts.server), TestCerts.serverKey.copyOf())

    fun serverTls(alpn: String): TlsConfig =
        tlsConfig(TlsRole.Server) {
            this.alpn = listOf(alpn)
            identity = identity()
        }

    fun clientTls(alpn: String): TlsConfig =
        tlsConfig(TlsRole.Client) {
            this.alpn = listOf(alpn)
            serverName = "server.test"
            trust = SoakPki.trust
        }
}

/** Raw QUIC application protocol of the soak: one command line per bidirectional stream. */
internal object RawProtocol {
    const val ALPN: String = "kuicksilver-soak"
    const val CHUNK: Int = 16 * 1024
    val pattern: ByteArray = ByteArray(CHUNK) { (it * 31 + 7).toByte() }

    /** `GET n`: the server sends n bytes; `PUT n`: the client sends n bytes and the server answers `ok`; `CLOSE`: the server closes the connection. */
    suspend fun serve(
        c: QuicConnection,
        s: QuicStream,
    ) {
        try {
            val line = s.input.readUTF8Line(64) ?: return
            val parts = line.split(' ')
            when (parts[0]) {
                "GET" -> {
                    var left = parts[1].toLong()
                    while (left > 0) {
                        val n = minOf(left, CHUNK.toLong()).toInt()
                        s.output.writeFully(pattern, 0, n)
                        left -= n
                    }
                    s.output.flushAndClose()
                }

                "PUT" -> {
                    val got = s.input.discard()
                    s.output.writeStringUtf8("ok $got\n")
                    s.output.flushAndClose()
                }

                "CLOSE" -> {
                    c.close(0, "asked to close")
                }

                else -> {
                    s.reset(1)
                }
            }
        } catch (e: CancellationException) {
            throw e
        } catch (_: Throwable) {
            runCatching { s.reset(2) } // an aborted exchange: both directions end here too
        }
    }
}

/** A raw QUIC server on 127.0.0.1: accepts every connection (slowly when [acceptEvery] is set, so its queue fills) and serves [RawProtocol]. */
internal class RawServer private constructor(
    val endpoint: QuicEndpoint,
    val job: Job,
) {
    val port: Int get() = endpoint.localAddress.port

    suspend fun close() {
        job.cancel()
        endpoint.closeAndJoin()
    }

    companion object {
        suspend fun start(
            scope: CoroutineScope,
            acceptQueue: Int = 128,
            acceptEvery: kotlin.time.Duration? = null,
        ): RawServer {
            val ep =
                QuicEndpoint.bind(
                    InetSocketAddress("127.0.0.1", 0),
                    quicEndpointConfig {
                        server = QuicServerConfig.Builder(SoakPki.serverTls(RawProtocol.ALPN)).apply { earlyData = true }.build()
                        this.acceptQueue = acceptQueue
                    },
                )
            val job =
                scope.launch {
                    while (true) {
                        val c =
                            try {
                                ep.accept()
                            } catch (e: CancellationException) {
                                throw e
                            } catch (_: Throwable) {
                                break
                            }
                        launch { connection(c) }
                        acceptEvery?.let { delay(it) }
                    }
                }
            return RawServer(ep, job)
        }

        private suspend fun connection(c: QuicConnection) {
            try {
                coroutineScope {
                    while (true) {
                        val s = c.acceptStream()
                        launch { RawProtocol.serve(c, s) }
                    }
                }
            } catch (e: CancellationException) {
                c.close()
                throw e
            } catch (_: Throwable) {
                // the connection ended: its streams' handlers ended with it
            } finally {
                c.close()
            }
        }
    }
}

internal typealias SoakHttpServer = EmbeddedServer<KuicksilverApplicationEngine, KuicksilverApplicationEngine.Configuration>

/** The Ktor server: HTTP/1.1 over TLS and HTTP/3 on one port of 127.0.0.1. */
internal object HttpServer {
    suspend fun start(): Pair<SoakHttpServer, Int> {
        val server =
            embeddedServer(Kuicksilver, configure = {
                tlsConnector(SoakPki.identity()) {
                    host = "127.0.0.1"
                    port = 0
                }
                SoakQlog.sink?.let { sink -> quic = quicConfig { qlog = sink } }
            }) {
                routing {
                    get("/bytes/{n}") {
                        val n = call.parameters["n"]!!.toInt()
                        call.respondBytes(ByteArray(n) { RawProtocol.pattern[it % RawProtocol.CHUNK] }, ContentType.Application.OctetStream)
                    }
                    // a long body written in chunks: clients abort it midway
                    get("/stream/{n}") {
                        val n = call.parameters["n"]!!.toLong()
                        call.respondBytesWriter(ContentType.Application.OctetStream) {
                            var left = n
                            while (left > 0) {
                                val k = minOf(left, RawProtocol.CHUNK.toLong()).toInt()
                                writeFully(RawProtocol.pattern, 0, k)
                                flush()
                                left -= k
                            }
                        }
                    }
                    post("/upload") {
                        val ch: ByteReadChannel = call.receiveChannel()
                        call.respondText("ok ${ch.discard()}")
                    }
                }
            }
        server.startSuspend(false)
        return server to
            server.engine
                .resolvedConnectors()
                .first()
                .port
    }
}
