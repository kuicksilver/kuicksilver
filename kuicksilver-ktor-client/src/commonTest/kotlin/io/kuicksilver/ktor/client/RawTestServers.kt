// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.client

import io.ktor.network.selector.SelectorManager
import io.ktor.network.sockets.BoundDatagramSocket
import io.ktor.network.sockets.InetSocketAddress
import io.ktor.network.sockets.ServerSocket
import io.ktor.network.sockets.aSocket
import io.ktor.network.sockets.openReadChannel
import io.ktor.network.sockets.openWriteChannel
import io.ktor.utils.io.ByteReadChannel
import io.ktor.utils.io.ByteWriteChannel
import io.ktor.utils.io.LineEnding
import io.ktor.utils.io.readAvailable
import io.ktor.utils.io.readByteArray
import io.ktor.utils.io.readLine
import io.ktor.utils.io.writeStringUtf8
import io.kuicksilver.http3.Http3Endpoint
import io.kuicksilver.http3.Http3Headers
import io.kuicksilver.ktor.network.tlsServer
import io.kuicksilver.quic.QuicEndpointConfig
import io.kuicksilver.quic.QuicServerConfig
import io.kuicksilver.tls.TlsRole
import io.kuicksilver.tls.tlsConfig
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.launch

/** Reads a request head and its Content-Length body; returns the request line ("" at end of stream). */
internal suspend fun readRequest(input: ByteReadChannel): String {
    val line = input.readLine(LineEnding.Lenient) ?: return ""
    var length = 0
    while (true) {
        val h = input.readLine(LineEnding.Lenient) ?: break
        if (h.isEmpty()) break
        if (h.startsWith("Content-Length:", ignoreCase = true)) length = h.substringAfter(':').trim().toInt()
    }
    if (length > 0) input.readByteArray(length)
    return line
}

/**
 * A TLS (HTTP/1.1) listener on 127.0.0.1 that runs [handler] once per accepted connection with its index, then closes it;
 * with [silentUdp] the UDP port of the same number is bound too and never answers (QUIC blocked): the UDP side binds a
 * free port first and TCP takes that number ([bindOnSamePort]; a free TCP port says nothing about its UDP twin). With
 * [listener] (not closed here) it serves on that socket instead of binding one. Connections are accepted once
 * [acceptAfter] completed (they wait in the backlog until then). [block] gets the port.
 */
internal suspend fun tlsH1WithSilentUdp(
    silentUdp: Boolean = true,
    listener: ServerSocket? = null,
    acceptAfter: kotlinx.coroutines.Deferred<Unit>? = null,
    handler: suspend CoroutineScope.(index: Int, input: ByteReadChannel, output: ByteWriteChannel) -> Unit,
    block: suspend (Int) -> Unit,
) {
    require(listener == null || !silentUdp) { "a given listener comes with its own UDP side" }
    val tls =
        tlsConfig(TlsRole.Server) {
            identity = ClientFixtures.identity()
            alpn = listOf("http/1.1")
        }
    val selector = SelectorManager(Dispatchers.Default)
    var udp: BoundDatagramSocket? = null
    val tcp: ServerSocket
    try {
        tcp =
            when {
                listener != null -> {
                    listener
                }

                silentUdp -> {
                    bindOnSamePort(
                        first = {
                            aSocket(selector).udp().bind(InetSocketAddress("127.0.0.1", 0)).let {
                                it to
                                    (it.localAddress as InetSocketAddress).port
                            }
                        },
                        release = { it.close() },
                    ) { p -> aSocket(selector).tcp().bind("127.0.0.1", p) }.let { (u, t, _) ->
                        udp = u
                        t
                    }
                }

                else -> {
                    aSocket(selector).tcp().bind("127.0.0.1", 0)
                }
            }
    } catch (e: Throwable) {
        selector.close()
        throw e
    }
    val bound = (tcp.localAddress as InetSocketAddress).port
    try {
        coroutineScope {
            val server =
                launch {
                    acceptAfter?.await()
                    var index = 0
                    while (true) {
                        val raw = tcp.accept()
                        val i = index++
                        launch {
                            runCatching {
                                raw.tlsServer(tls).use { s -> handler(i, s.openReadChannel(), s.openWriteChannel(autoFlush = true)) }
                            }
                            raw.close()
                        }
                    }
                }
            block(bound)
            server.cancel()
        }
    } finally {
        udp?.close()
        if (listener == null) tcp.close()
        selector.close()
    }
}

/**
 * An HTTP/3 server on 127.0.0.1:[port] (0: a free UDP port) that answers every request 200 "h3" with [headers]; with
 * [earlyData] it accepts 0-RTT. Nothing listens on the TCP port of the same number.
 */
@OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)
internal suspend fun CoroutineScope.h3Origin(
    headers: List<Pair<String, String>> = emptyList(),
    earlyData: Boolean = false,
    port: Int = 0,
): Http3Endpoint {
    val tls =
        tlsConfig(TlsRole.Server) {
            alpn = listOf(Http3Endpoint.H3)
            identity = ClientFixtures.identity()
        }
    val ep =
        Http3Endpoint.bind(
            InetSocketAddress("127.0.0.1", port),
            QuicEndpointConfig
                .Builder()
                .apply {
                    server = QuicServerConfig.Builder(tls).apply { this.earlyData = earlyData }.build()
                }.build(),
        )
    launch {
        runCatching {
            while (true) {
                val conn = ep.accept()
                launch {
                    runCatching {
                        while (true) {
                            val r = conn.acceptRequest()
                            launch {
                                runCatching {
                                    r.body.discardAll()
                                    val w = r.respond(200, Http3Headers(headers))
                                    w.output.writeStringUtf8("h3")
                                    w.finish()
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    return ep
}

private suspend fun ByteReadChannel.discardAll() {
    val b = ByteArray(4096)
    while (readAvailable(b, 0, b.size) >= 0) Unit
}

/** Control of a [udpRelay]. */
internal class UdpRelay(
    /** With `tcpTwin`: a TCP listener on 127.0.0.1 at the relay's port number, bound with it and accepting nothing yet. */
    val tcp: ServerSocket?,
) {
    /** While true every datagram is dropped, both ways: QUIC is blocked on the path. */
    @kotlin.concurrent.Volatile var blocked: Boolean = false

    /** Completed by the first datagram from the client dropped while [blocked]. */
    val dropped: kotlinx.coroutines.CompletableDeferred<Unit> = kotlinx.coroutines.CompletableDeferred()
}

/**
 * A UDP relay from a free port of 127.0.0.1 to 127.0.0.1:[target] (for one client address at a time); [block] gets its port
 * and its [UdpRelay] switch. Without [tcpTwin] nothing of ours listens on the TCP port of the same number; with it that
 * port is bound together with the relay's ([bindOnSamePort]) and handed over as [UdpRelay.tcp], for a test that serves
 * HTTP/1.1 on the relay's port later: binding TCP on that number only then failed with "Address already in use" whenever
 * another process held it.
 */
internal suspend fun udpRelay(
    target: Int,
    tcpTwin: Boolean = false,
    block: suspend (port: Int, relay: UdpRelay) -> Unit,
) {
    val selector = SelectorManager(Dispatchers.Default)
    val (front, tcp) =
        try {
            if (tcpTwin) {
                bindOnSamePort(
                    first = {
                        aSocket(selector).udp().bind(InetSocketAddress("127.0.0.1", 0)).let {
                            it to
                                (it.localAddress as InetSocketAddress).port
                        }
                    },
                    release = { it.close() },
                ) { p -> aSocket(selector).tcp().bind("127.0.0.1", p) }.let { (u, t, _) -> u to t }
            } else {
                aSocket(selector).udp().bind(InetSocketAddress("127.0.0.1", 0)) to null
            }
        } catch (e: Throwable) {
            selector.close()
            throw e
        }
    val back =
        try {
            aSocket(selector).udp().bind(InetSocketAddress("127.0.0.1", 0))
        } catch (e: Throwable) {
            front.close()
            tcp?.close()
            selector.close()
            throw e
        }
    val relay = UdpRelay(tcp)
    val to = InetSocketAddress("127.0.0.1", target)
    var client: io.ktor.network.sockets.SocketAddress? = null
    try {
        coroutineScope {
            val up =
                launch {
                    while (true) {
                        val d = front.receive()
                        if (relay.blocked) {
                            d.packet.close()
                            relay.dropped.complete(Unit)
                            continue
                        }
                        client = d.address
                        back.send(
                            io.ktor.network.sockets
                                .Datagram(d.packet, to),
                        )
                    }
                }
            val down =
                launch {
                    while (true) {
                        val d = back.receive()
                        val c = client
                        if (relay.blocked || c == null) {
                            d.packet.close()
                            continue
                        }
                        front.send(
                            io.ktor.network.sockets
                                .Datagram(d.packet, c),
                        )
                    }
                }
            block((front.localAddress as InetSocketAddress).port, relay)
            up.cancel()
            down.cancel()
        }
    } finally {
        front.close()
        back.close()
        tcp?.close()
        selector.close()
    }
}
