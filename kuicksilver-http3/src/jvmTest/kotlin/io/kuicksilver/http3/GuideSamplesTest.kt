// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(ExperimentalKuicksilverApi::class)

package io.kuicksilver.http3

import io.ktor.network.sockets.InetSocketAddress
import io.ktor.utils.io.copyTo
import io.ktor.utils.io.readBuffer
import io.ktor.utils.io.writeFully
import io.ktor.utils.io.writeStringUtf8
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.native.KslLoader
import io.kuicksilver.quic.QuicEndpointConfig
import io.kuicksilver.quic.QuicServerConfig
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.toList
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import kotlinx.io.readString
import java.io.File
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds

/** The code blocks of docs/guide/http3.md, kept compiling and running (block markers `guide:http3:*`). */
class GuideSamplesTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    private val serverTls = H3Fixtures.server()
    private val clientTls = H3Fixtures.client()

    @Test fun guideHasEveryMarker() {
        val guide =
            generateSequence(File("").absoluteFile) {
                it.parentFile
            }.map { File(it, "docs/guide/http3.md") }.first { it.exists() }.readText()
        for (m in listOf(
            "qpack",
            "endpoints",
            "client-request",
            "serve",
            "connect (server)",
            "connect (client)",
            "capsules (server)",
            "capsules (client)",
            "webtransport (server)",
            "webtransport (client)",
            "webtransport-echo (server)",
            "webtransport-echo (client)",
        )) {
            assertTrue("guide:http3:$m" in guide, "marker $m")
        }
    }

    @Test fun endpointsRequestAndServeSamples() =
        runBlocking {
            withTimeout(30.seconds) {
                // guide:http3:endpoints (port 0 instead of 443)
                val server =
                    Http3Endpoint.bind(
                        InetSocketAddress("127.0.0.1", 0),
                        QuicEndpointConfig
                            .Builder()
                            .apply {
                                this.server =
                                    QuicServerConfig
                                        .Builder(
                                            serverTls, // alpn = listOf("h3")
                                        ).build()
                            }.build(),
                    )
                val client = Http3Endpoint.bind(InetSocketAddress("127.0.0.1", 0))
                val serverAddress = server.localAddress
                val serving =
                    launch {
                        // guide:http3:serve (one request)
                        val connection = server.accept()
                        while (true) {
                            val request = connection.acceptRequest()
                            launch {
                                val writer = request.respond(200, Http3Headers.of("content-type" to "text/plain"))
                                writer.output.writeStringUtf8("hello")
                                writer.finish()
                            }
                            break // the guide serves forever; one request is enough here
                        }
                    }
                val connection = client.connect(serverAddress, clientTls /* alpn = listOf("h3") */)
                // guide:http3:client-request
                val response = connection.request(http3Request("GET", "example.com", "/"))
                println(response.status)
                val body = response.body
                assertEquals("hello", body.readAllBytes().decodeToString())
                serving.join()
                connection.close()
                client.close()
                server.close()
            }
        }

    @Test fun qpackAndConnectSamples() =
        runBlocking {
            withTimeout(30.seconds) {
                val q = QuicPair.open()
                val (quicConnection, serverQuic) = q.connect()
                // guide:http3:qpack
                val settings = http3Settings { enableQpackDynamicTable() } // advertise 4096 bytes / 16 blocked streams
                val serverConnection =
                    Http3Connection.server(
                        serverQuic,
                        http3Settings {
                            enableQpackDynamicTable()
                            enableConnectProtocol =
                                true
                        },
                    )
                val client = Http3Connection.client(quicConnection, settings)
                val echoed = CompletableDeferred<Int>()
                val serving =
                    launch {
                        val connection = serverConnection
                        // guide:http3:connect (server)
                        val request = connection.acceptRequest()
                        if (request.protocol == "echo") {
                            val stream = request.acceptConnect() // :status 200
                            launch { echoed.complete(stream.datagrams.first().size) }
                            stream.input.copyTo(stream.output)
                        } else {
                            request.respond(501).finish()
                        }
                    }
                // guide:http3:connect (client)
                val stream = client.connect(http3Request("CONNECT", "example.com", "/chat"), protocol = "echo")
                stream.trySendDatagram(byteArrayOf(1, 2, 3))
                val collector = launch { stream.datagrams.collect { println(it.size) } }
                assertEquals(3, echoed.await())
                stream.output.flushAndClose()
                serving.join() // the server's echo ends before the connections close under it
                collector.cancel()
                client.close()
                serverConnection.close()
                q.close()
            }
        }

    @Test fun capsulesSample() =
        runBlocking {
            withTimeout(30.seconds) {
                val q = QuicPair.open()
                val (quicConnection, serverQuic) = q.connect()
                val serverConnection = Http3Connection.server(serverQuic, http3Settings { enableConnectProtocol = true })
                val client = Http3Connection.client(quicConnection)
                val serving =
                    launch {
                        val request = serverConnection.acceptRequest()
                        // guide:http3:capsules (server)
                        val config = capsuleConfig { knownTypes = setOf(0x2843) } // the capsule types the protocol defines
                        val tunnel = request.acceptConnect().useCapsuleProtocol(config)
                        tunnel.capsules.collect { tunnel.send(it) } // echo each capsule until the client's FIN
                        tunnel.close() // the queued capsules, then FIN
                    }
                // guide:http3:capsules (client)
                val config = capsuleConfig { knownTypes = setOf(0x2843) }
                val capsules = client.connect(http3Request("CONNECT", "example.com", "/chat"), protocol = "echo").useCapsuleProtocol(config)
                capsules.send(Capsule(0x2843, "hello".encodeToByteArray()))
                capsules.close()
                val echoed = capsules.capsules.toList()
                assertEquals(listOf("hello"), echoed.map { it.value.decodeToString() })
                serving.join()
                client.close()
                serverConnection.close()
                q.close()
            }
        }

    @OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)
    @Test
    fun webTransportSamples() =
        runBlocking {
            withTimeout(30.seconds) {
                val q = QuicPair.open()
                val (quicConnection, serverQuic) = q.connect()
                val wt =
                    http3Settings {
                        enableConnectProtocol = true
                        webTransport = true
                    }
                val serverConnection = Http3Connection.server(serverQuic, wt)
                val client = Http3Connection.client(quicConnection, wt)
                val serving =
                    launch {
                        val connection = serverConnection
                        // guide:http3:webtransport (server)
                        val request = connection.acceptRequest()
                        if (request.isWebTransport && request.headers["origin"] == "https://app.example") {
                            val session = request.acceptWebTransport(protocol = request.availableProtocols.firstOrNull())
                            assertEquals("chat-v1", session.protocol)
                        } else {
                            request.respond(403).finish()
                        }
                    }
                // guide:http3:webtransport (client)
                val request = http3Request("CONNECT", "example.com", "/wt") { headers = Http3Headers.of("origin" to "https://app.example") }
                val session = client.webTransport(request, protocols = listOf("chat-v1"))
                println(session.protocol)
                assertEquals("chat-v1", session.protocol)
                serving.join()
                client.close()
                serverConnection.close()
                q.close()
            }
        }

    @OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)
    @Test
    fun webTransportEchoSample() =
        runBlocking {
            withTimeout(30.seconds) {
                val q = QuicPair.open()
                val (quicConnection, serverQuic) = q.connect()
                val wt =
                    http3Settings {
                        enableConnectProtocol = true
                        webTransport = true
                    }
                val serverConnection = Http3Connection.server(serverQuic, wt)
                val client = Http3Connection.client(quicConnection, wt)
                val reason = CompletableDeferred<String>()
                val serving =
                    launch {
                        val session = serverConnection.acceptRequest().acceptWebTransport()
                        // guide:http3:webtransport-echo (server)
                        val stream = session.acceptBidi()
                        stream.input.copyTo(stream.output)
                        stream.output.flushAndClose()
                        session.sendDatagram(session.receiveDatagram())
                        println(session.closed.await().reason)
                        reason.complete(session.closed.await().reason)
                    }
                val session = client.webTransport(http3Request("CONNECT", "example.com", "/wt"))
                // guide:http3:webtransport-echo (client)
                val stream = session.openBidi()
                stream.output.writeFully("ping".encodeToByteArray())
                stream.output.flushAndClose()
                println(stream.input.readBuffer().readString())
                session.trySendDatagram(byteArrayOf(1, 2, 3))
                println(session.receiveDatagram().size)
                session.close(0, "done")
                assertEquals("done", reason.await())
                serving.join()
                client.close()
                serverConnection.close()
                q.close()
            }
        }
}
