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
import io.kuicksilver.quic.PacketTooBigSender
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

    /** `guide:http3:connect-udp`: a proxy, a UDP tunnel through it and HTTP/3 through a tunnel, all on in-memory UDP. */
    @OptIn(io.kuicksilver.annotations.DelicateKuicksilverApi::class)
    @Test
    fun connectUdpSamples() =
        runBlocking {
            withTimeout(30.seconds) {
                val q = QuicPair.open(df = true) // Don't Fragment, so the proxy's path grows above 1200 bytes
                val (quicConnection, serverQuic) = q.connect()
                val net = q.net
                val echoAt = InetSocketAddress("192.0.2.10", 443)
                val echoIo = net.open(echoAt)
                val echo =
                    launch {
                        while (true) {
                            val (bytes, from) = echoIo.inbox.receive()
                            net.deliver(echoAt, from, bytes.reversedArray())
                        }
                    }
                val webAt = InetSocketAddress("192.0.2.20", 443)
                val web =
                    Http3Endpoint.bind(
                        webAt,
                        QuicEndpointConfig
                            .Builder()
                            .apply {
                                server = QuicServerConfig.Builder(H3Fixtures.server()).build()
                                runtime { io = { net.open(webAt) } }
                            }.build(),
                    )
                val webServing =
                    launch {
                        val r = web.accept().acceptRequest()
                        r.respond(200).apply { output.writeStringUtf8("through the tunnel") }.finish()
                    }
                var port = 40_000
                val serving =
                    launch {
                        val connection = Http3Connection.server(serverQuic, http3Settings { enableConnectProtocol = true })
                        val proxy =
                            UdpProxy(
                                UdpProxyConfig(
                                    targetFilter = UdpTargetFilter.AllowAll, // in-memory targets in TEST-NET-1
                                    resolver = { listOf(byteArrayOf(192.toByte(), 0, 2, 20)) },
                                    socketFactory = { net.open(InetSocketAddress("10.0.0.2", ++port)) },
                                ),
                            ).also {
                                // tests send no ICMP: as root the real probe would let a Packet Too Big go to TEST-NET addresses
                                it.impl.probeForTest = { PacketTooBigSender.Probe(false, "tests send no ICMP") }
                            }
                        while (true) {
                            // guide:http3:connect-udp (proxy)
                            val request = connection.acceptRequest()
                            if (ConnectUdp.isConnectUdp(request)) proxy.serve(request) else request.respond(404).finish()
                        }
                    }
                val connection = Http3Connection.client(quicConnection)
                // guide:http3:connect-udp (client)
                val template = UdpProxyTemplate.parse("https://proxy.example/.well-known/masque/udp/{target_host}/{target_port}/")
                val tunnel = connection.connectUdp(template, "192.0.2.10", 443)
                tunnel.send("hello".encodeToByteArray())
                val reply = tunnel.payloads.first()
                tunnel.close()
                assertEquals("olleh", reply.decodeToString())

                val tls = H3Fixtures.client()
                run {
                    // guide:http3:connect-udp (proxied QUIC)
                    val tunnel = connection.connectUdp(template, "example.com", 443)
                    val inner =
                        Http3Endpoint.bind(
                            InetSocketAddress("127.0.0.1", 0),
                            QuicEndpointConfig
                                .Builder()
                                .apply {
                                    runtime { io = { tunnel.asDatagramIo() } }
                                }.build(),
                        )
                    val h3 = inner.connect(tunnel.remoteAddress, tls)
                    val response = h3.request(http3Request("GET", "example.com", "/"))
                    assertEquals("through the tunnel", response.body.readAllBytes().decodeToString())
                    h3.close()
                    inner.close()
                }
                webServing.join()
                serving.cancel()
                echo.cancel()
                echoIo.close()
                web.close()
                connection.close()
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
                // reset_stream_at on both sides, as Http3Endpoint turns it on with webTransport (draft-17 section 3.1)
                val q = QuicPair.open(H3Fixtures.quic)
                val (quicConnection, serverQuic) = q.connect(H3Fixtures.quic)
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
                // reset_stream_at on both sides, as Http3Endpoint turns it on with webTransport (draft-17 section 3.1)
                val q = QuicPair.open(H3Fixtures.quic)
                val (quicConnection, serverQuic) = q.connect(H3Fixtures.quic)
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
