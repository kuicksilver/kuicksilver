// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.soak

import io.ktor.http.ContentType
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.http.content.OutgoingContent
import io.ktor.server.engine.embeddedServer
import io.ktor.server.response.header
import io.ktor.server.response.respond
import io.ktor.server.routing.get
import io.ktor.server.routing.routing
import io.ktor.utils.io.ByteWriteChannel
import io.ktor.utils.io.writeFully
import io.kuicksilver.ktor.server.Kuicksilver
import kotlinx.coroutines.awaitCancellation
import kotlinx.coroutines.runBlocking
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.net.SocketAddress
import java.net.StandardSocketOptions
import java.nio.ByteBuffer
import java.nio.channels.DatagramChannel
import java.nio.channels.SelectionKey
import java.nio.channels.Selector
import java.util.concurrent.atomic.AtomicBoolean
import kotlin.concurrent.thread

/**
 * The server and clients of `tools/bench/why-quic.sh` (docs/why-quic.md), run inside one container whose loopback carries
 * the emulated network (`tc netem`):
 *   why-quic server <port> <relay port> <control port>
 *   why-quic client --client kuicksilver|okhttp --protocol h1|h2|h3|h3-0rtt --scenario <name> [options]   (WhyQuicClients.kt)
 *   why-quic header                                                                                      (the CSV header)
 */
public fun main(args: Array<String>) {
    when (args.firstOrNull()) {
        "server" -> {
            whyQuicServer(args[1].toInt(), args[2].toInt(), args[3].toInt())
        }

        "client" -> {
            whyQuicClient(args.drop(1))
        }

        "header" -> {
            println(WHY_QUIC_HEADER)
        }

        else -> {
            System.err.println("usage: why-quic server <port> <relay port> <control port> | client <options> | header")
            kotlin.system.exitProcess(2)
        }
    }
}

/** One row per measured run; `tools/bench/why-quic.sh` checks it against docs/benchmarks/why-quic.csv. */
internal const val WHY_QUIC_HEADER = "scenario,client,protocol,rtt_ms,loss_pct,rep,ok,seconds,bytes,requests,client_cpu_s"

/** Bytes a relayed flow carries towards the client before an armed rebind (half of the 50 MiB download). */
internal const val REBIND_AFTER: Long = 25L shl 20

private val loopback: InetAddress = InetAddress.getLoopbackAddress()

/**
 * The Ktor engine on [port] (TCP: HTTP/1.1 and HTTP/2 over TLS 1.3; UDP: HTTP/3 with 0-RTT), the test PKI's identity
 * (`server.test`). `GET /bytes/<n>` answers n bytes (`Range: bytes=<from>-` gives 206 and the rest from there). The
 * [RebindRelay] listens on [relayPort] and [controlPort].
 */
internal fun whyQuicServer(
    port: Int,
    relayPort: Int,
    controlPort: Int,
) {
    RebindRelay(relayPort, port, controlPort, REBIND_AFTER).start()
    val chunk = ByteArray(64 * 1024) { (it * 31).toByte() }
    runBlocking {
        val server =
            embeddedServer(Kuicksilver, configure = {
                tlsConnector(SoakPki.identity()) {
                    host = "127.0.0.1"
                    this.port = port
                }
                http2 = true
                http3 = true
                quicEarlyData = true
            }) {
                routing {
                    get("/bytes/{n}") {
                        val n = call.parameters["n"]!!.toLong()
                        val from =
                            call.request.headers[HttpHeaders.Range]
                                ?.let { Regex("bytes=(\\d+)-").matchEntire(it) }
                                ?.groupValues
                                ?.get(1)
                                ?.toLong()
                                ?.coerceAtMost(n) ?: 0L
                        if (from > 0) call.response.header(HttpHeaders.ContentRange, "bytes $from-${n - 1}/$n")
                        call.respond(
                            object : OutgoingContent.WriteChannelContent() {
                                override val contentLength: Long = n - from
                                override val contentType: ContentType = ContentType.Application.OctetStream
                                override val status: HttpStatusCode = if (from > 0) HttpStatusCode.PartialContent else HttpStatusCode.OK

                                override suspend fun writeTo(channel: ByteWriteChannel) {
                                    var left = n - from
                                    while (left > 0) {
                                        val k = minOf(left, chunk.size.toLong()).toInt()
                                        channel.writeFully(chunk, 0, k)
                                        left -= k
                                    }
                                }
                            },
                        )
                    }
                }
            }
        server.startSuspend(false)
        println("why-quic server listening on $port")
        awaitCancellation()
    }
}

/**
 * A NAT in front of the server on [listenPort] (UDP and TCP), forwarding to [serverPort] from a port of its own per client
 * flow. A line `arm` on [controlPort] arms the next new flow: once it has carried [after] bytes towards the client, the
 * NAT forgets its mapping. A UDP flow then leaves from a new port (the server sees a NAT rebinding, RFC 9000 section 9.3;
 * the old port's socket is closed); a TCP flow is reset on both sides, as the server answers
 * a segment from the new port with RST.
 */
internal class RebindRelay(
    private val listenPort: Int,
    private val serverPort: Int,
    private val controlPort: Int,
    private val after: Long,
) {
    private val armed = AtomicBoolean(false)

    fun start() {
        val control = ServerSocket(controlPort, 50, loopback)
        val tcp = ServerSocket(listenPort, 50, loopback)
        val udp = DatagramChannel.open().bind(InetSocketAddress(loopback, listenPort))
        thread(isDaemon = true, name = "relay-control") {
            while (true) {
                control.accept().use { s ->
                    val line = s.getInputStream().bufferedReader().readLine()
                    if (line == "arm") armed.set(true)
                    s.getOutputStream().write("ok\n".toByteArray())
                }
            }
        }
        thread(isDaemon = true, name = "relay-tcp") { while (true) tcpFlow(tcp.accept(), armed.getAndSet(false)) }
        thread(isDaemon = true, name = "relay-udp") { udpLoop(udp) }
    }

    private class Flow(
        val client: SocketAddress,
        var armed: Boolean,
    ) {
        lateinit var up: DatagramChannel
        var down = 0L
        var lastSeen = System.nanoTime()

        fun open(selector: Selector) {
            up = DatagramChannel.open().bind(InetSocketAddress(loopback, 0))
            up.setOption(StandardSocketOptions.SO_RCVBUF, 4 shl 20)
            up.setOption(StandardSocketOptions.SO_SNDBUF, 4 shl 20)
            up.configureBlocking(false)
            up.register(selector, SelectionKey.OP_READ, this)
        }

        /** A new upstream port; the old socket is closed, so what the server still sends to it is lost. */
        fun rebind(selector: Selector) {
            val old = up
            open(selector)
            old.close()
        }

        fun close() = up.close()
    }

    private fun udpLoop(front: DatagramChannel) {
        val selector = Selector.open()
        front.setOption(StandardSocketOptions.SO_RCVBUF, 4 shl 20)
        front.setOption(StandardSocketOptions.SO_SNDBUF, 4 shl 20)
        front.configureBlocking(false)
        front.register(selector, SelectionKey.OP_READ, null)
        val server = InetSocketAddress(loopback, serverPort)
        val flows = HashMap<SocketAddress, Flow>()
        val buf = ByteBuffer.allocateDirect(65_536)
        var pruned = System.nanoTime()
        while (true) {
            selector.select(1_000)
            val now = System.nanoTime()
            if (now - pruned > 10_000_000_000L) {
                // flows of finished clients: a minute without a datagram either way
                pruned = now
                flows.values.removeAll { f -> (now - f.lastSeen > 60_000_000_000L).also { if (it) f.close() } }
            }
            val keys = selector.selectedKeys().iterator()
            while (keys.hasNext()) {
                val key = keys.next()
                keys.remove()
                if (!key.isValid) continue // a flow pruned above
                val ch = key.channel() as DatagramChannel
                val flow = key.attachment() as Flow?
                while (true) {
                    buf.clear()
                    val from = ch.receive(buf) ?: break
                    buf.flip()
                    if (flow == null) {
                        val f = flows.getOrPut(from) { Flow(from, armed.getAndSet(false)).also { it.open(selector) } }
                        f.lastSeen = now
                        f.up.send(buf, server)
                    } else if (ch === flow.up) {
                        flow.lastSeen = now
                        flow.down += buf.remaining()
                        front.send(buf, flow.client)
                        if (flow.armed && flow.down >= after) {
                            flow.armed = false
                            flow.rebind(selector)
                            break // ch was the old socket, closed now
                        }
                    }
                }
            }
        }
    }

    private fun tcpFlow(
        client: Socket,
        armedHere: Boolean,
    ) {
        thread(isDaemon = true, name = "relay-tcp-flow") {
            val server = Socket()
            try {
                server.connect(InetSocketAddress(loopback, serverPort))
            } catch (_: IOException) {
                client.close()
                return@thread
            }
            client.tcpNoDelay = true
            server.tcpNoDelay = true

            fun reset() {
                for (s in listOf(client, server)) {
                    runCatching {
                        s.setSoLinger(true, 0)
                        s.close()
                    }
                }
            }
            thread(isDaemon = true, name = "relay-tcp-up") {
                if (pump(client.getInputStream(), server.getOutputStream(), Long.MAX_VALUE) == null) runCatching { server.shutdownOutput() }
            }
            val cut = pump(server.getInputStream(), client.getOutputStream(), if (armedHere) after else Long.MAX_VALUE)
            // the cut, or a side that failed: both reset; the server's end of the response: half-close towards the client
            if (cut == null) {
                runCatching { client.shutdownOutput() }
                client.close() // the server ended its side: the flow is over
                server.close()
            } else {
                reset()
            }
        }
    }

    /** Copies until EOF (null), an I/O error (false) or [limit] bytes (true). */
    private fun pump(
        from: InputStream,
        to: OutputStream,
        limit: Long,
    ): Boolean? {
        val b = ByteArray(65_536)
        var n = 0L
        try {
            var k = from.read(b)
            while (k >= 0) {
                to.write(b, 0, k)
                n += k
                if (n >= limit) return true
                k = from.read(b)
            }
            return null
        } catch (_: IOException) {
            return false
        }
    }
}
