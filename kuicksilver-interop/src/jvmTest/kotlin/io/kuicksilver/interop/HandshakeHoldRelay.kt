// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.interop

import kotlinx.coroutines.CompletableDeferred
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.SocketAddress
import java.net.SocketException
import kotlin.concurrent.thread

/**
 * A UDP relay on loopback between one client and a server at [serverPort] that, from the second connection the client
 * opens on, holds the server's datagrams back until [release]: on loopback the server answers a ClientHello within a
 * millisecond, so whether a client's 0-RTT requests leave before it has the 1-RTT keys otherwise depends on scheduling
 * (the `zerortt` test failed 1 run in 6). A connection is new when its client Initial carries a destination connection ID
 * the relay has seen neither from the client nor as a server's source connection ID (a client's later Initials carry the
 * server's ID). [answerSettled] completes once the server has answered that connection and the answer is either held or
 * was let through and processed by the client (it sent a 1-RTT packet, so it has the 1-RTT keys).
 * Held datagrams go out at [release] or after [maxHold] at the latest, so a broken client cannot hang a test.
 */
internal class HandshakeHoldRelay(
    private val serverPort: Int,
    private val maxHoldMillis: Long = 10_000,
) : AutoCloseable {
    private val loopback = InetAddress.getByName("127.0.0.1")
    private val socket = DatagramSocket(InetSocketAddress(loopback, 0))
    val port: Int get() = socket.localPort
    private val server = InetSocketAddress(loopback, serverPort)

    @Volatile private var client: SocketAddress? = null
    private val seenIds = HashSet<String>()
    private var connections = 0
    private val held = ArrayList<ByteArray>()
    private var holding = false
    private var released = false
    private var holdStarted = 0L

    /** The server answered the held connection, and its answer is held or the client has processed it. */
    val answerSettled = CompletableDeferred<Unit>()
    private var answered = false

    private val pump =
        thread(name = "hold-relay", isDaemon = true) {
            val buf = ByteArray(65_536)
            try {
                while (true) {
                    val p = DatagramPacket(buf, buf.size)
                    socket.receive(p)
                    val data = p.data.copyOfRange(0, p.length)
                    if (p.socketAddress == server) fromServer(data) else fromClient(p.socketAddress, data)
                }
            } catch (_: SocketException) {
                // closed
            }
        }

    private fun fromClient(
        from: SocketAddress,
        data: ByteArray,
    ) {
        client = from
        synchronized(this) {
            if (answered && data.isNotEmpty() && data[0].toInt() and 0x80 == 0) answerSettled.complete(Unit) // a 1-RTT packet
            val dcid = initialDcid(data)
            if (dcid != null && seenIds.add(dcid) && ++connections == 2) {
                holding = true
                holdStarted = System.nanoTime()
            }
        }
        socket.send(DatagramPacket(data, data.size, server))
    }

    private fun fromServer(data: ByteArray) {
        val out: List<ByteArray>
        synchronized(this) {
            longHeaderScid(data)?.let { seenIds.add(it) }
            if (holding) answered = true
            if (holding && !released && (System.nanoTime() - holdStarted) / 1_000_000 < maxHoldMillis) {
                held += data
                answerSettled.complete(Unit)
                return
            }
            out = held.toList() + listOf(data)
            held.clear()
        }
        val to = client ?: return
        for (d in out) socket.send(DatagramPacket(d, d.size, to))
    }

    /** Lets the held datagrams and everything after them through. */
    fun release() {
        val out: List<ByteArray>
        synchronized(this) {
            released = true
            out = held.toList()
            held.clear()
        }
        val to = client ?: return
        for (d in out) socket.send(DatagramPacket(d, d.size, to))
    }

    override fun close() {
        socket.close()
        pump.join(1_000)
    }

    private companion object {
        fun hex(
            b: ByteArray,
            from: Int,
            n: Int,
        ) = (from until from + n).joinToString("") { "%02x".format(b[it]) }

        /** The destination connection ID of a datagram whose first packet is a QUIC v1/v2 Initial, else null. */
        fun initialDcid(b: ByteArray): String? {
            if (b.size < 7 || b[0].toInt() and 0x80 == 0) return null
            val version = ((b[1].toInt() and 0xff) shl 24) or ((b[2].toInt() and 0xff) shl 16) or ((b[3].toInt() and 0xff) shl 8) or (b[4].toInt() and 0xff)
            val type = (b[0].toInt() shr 4) and 3
            val initial = if (version == 0x6b3343cf) 1 else 0 // QUIC v2 (RFC 9369) numbers the long-header types differently
            if (type != initial) return null
            val len = b[5].toInt() and 0xff
            return if (6 + len <= b.size) hex(b, 6, len) else null
        }

        /** The source connection ID of a long-header packet, else null. */
        fun longHeaderScid(b: ByteArray): String? {
            if (b.size < 7 || b[0].toInt() and 0x80 == 0) return null
            val dlen = b[5].toInt() and 0xff
            if (6 + dlen >= b.size) return null
            val slen = b[6 + dlen].toInt() and 0xff
            return if (7 + dlen + slen <= b.size) hex(b, 7 + dlen, slen) else null
        }
    }
}
