// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.http3

import io.ktor.network.sockets.InetSocketAddress
import io.ktor.utils.io.copyTo
import io.ktor.utils.io.writeStringUtf8
import io.kuicksilver.native.KslLoader
import io.kuicksilver.quic.QuicEndpointConfig
import io.kuicksilver.quic.QuicServerConfig
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
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
        for (m in listOf("qpack", "endpoints", "client-request", "serve", "connect (server)", "connect (client)")) {
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
                val response = connection.request(Http3Request("GET", authority = "example.com", path = "/"))
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
                val stream = client.connect(Http3Request("CONNECT", authority = "example.com", path = "/chat"), protocol = "echo")
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
}
