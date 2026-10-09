// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.fuzz

import io.ktor.network.sockets.InetSocketAddress
import io.kuicksilver.annotations.DelicateKuicksilverApi
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.native.KslLoader
import io.kuicksilver.native.PacketBuffer
import io.kuicksilver.quic.ConnectionCore
import io.kuicksilver.quic.ConnectionEvent
import io.kuicksilver.quic.ConnectionState
import io.kuicksilver.quic.CoreFixtures
import io.kuicksilver.quic.Ecn
import io.kuicksilver.quic.EndpointCore
import io.kuicksilver.quic.NullCryptoProvider
import io.kuicksilver.quic.PacketBatch
import io.kuicksilver.quic.QuicConfig
import io.kuicksilver.quic.QuicEndpointConfig
import io.kuicksilver.quic.QuicException
import io.kuicksilver.quic.QuicServerConfig
import io.kuicksilver.quic.TimeMark
import io.kuicksilver.quic.wire.QuicWireException
import kotlin.random.Random
import kotlin.time.Duration.Companion.milliseconds

/**
 * Input framing shared by the fuzz targets and the seed generator (`tools/fuzz/gen-seeds.sh`): a sequence of
 * datagrams, each prefixed with a 2-byte big-endian length; a short or overlong prefix takes the rest of the input.
 */
internal object Framing {
    fun split(
        data: ByteArray,
        from: Int = 0,
    ): List<ByteArray> {
        val out = ArrayList<ByteArray>()
        var p = from
        while (p < data.size) {
            if (data.size - p < 2) {
                out += data.copyOfRange(p, data.size)
                break
            }
            val n = ((data[p].toInt() and 0xff) shl 8) or (data[p + 1].toInt() and 0xff)
            p += 2
            val end = minOf(data.size, p + n)
            out += data.copyOfRange(p, end)
            p = end
        }
        return out
    }

    fun join(datagrams: List<ByteArray>): ByteArray {
        val out = java.io.ByteArrayOutputStream()
        for (d in datagrams) {
            require(d.size <= 0xffff)
            out.write(d.size ushr 8)
            out.write(d.size and 0xff)
            out.write(d)
        }
        return out.toByteArray()
    }
}

/** Runs a codec under the fuzzing contract: a [QuicWireException] is a valid rejection, anything else is a finding. */
internal inline fun wireContract(block: () -> Unit) {
    try {
        block()
    } catch (_: QuicWireException) {
    }
}

internal val fuzzServerAddr: InetSocketAddress = CoreFixtures.serverAddr
internal val fuzzClientAddr: InetSocketAddress = CoreFixtures.clientAddr

/**
 * Drives sans-IO cores with NullCryptoProvider under virtual time. Any exception thrown by a core escapes and fails
 * the target; a connection that is closing or closed must have reported [ConnectionEvent.Closed]; a connection the
 * endpoint closed with [QuicException.ConnectionLost.Internal] (its isolation of a crash) fails it too.
 */
@OptIn(ExperimentalKuicksilverApi::class, DelicateKuicksilverApi::class)
internal class CoreDriver : AutoCloseable {
    init {
        KslLoader.ensureLoaded()
    }

    var now = TimeMark(1_000_000_000L)
    private val batch = PacketBatch(16)
    private val closedSeen = HashSet<ConnectionCore>()

    fun serverEndpoint(): EndpointCore =
        EndpointCore(
            QuicEndpointConfig
                .Builder()
                .apply {
                    server = QuicServerConfig.Builder(CoreFixtures.server()).build()
                    crypto = NullCryptoProvider
                }.build(),
            Random(5),
        )

    /** The client of `CorePair(seed = 1)`, so datagrams captured from that pair are addressed to it. */
    fun client(): ConnectionCore =
        ConnectionCore.client(QuicConfig.Default, CoreFixtures.client(), NullCryptoProvider, fuzzServerAddr, Random(2), now)

    fun deliver(
        core: ConnectionCore,
        bytes: ByteArray,
        from: InetSocketAddress,
    ) {
        withBuffer(bytes) { b, n -> core.handleDatagram(b, n, from, Ecn.NotEct, now) }
    }

    fun deliver(
        ep: EndpointCore,
        bytes: ByteArray,
        from: InetSocketAddress,
    ) {
        withBuffer(bytes) { b, n -> ep.handleDatagram(b, n, from, Ecn.NotEct, now) }
        ep.processPending(now)
    }

    private inline fun withBuffer(
        bytes: ByteArray,
        block: (PacketBuffer, Int) -> Unit,
    ) {
        val b = PacketBuffer.allocate(maxOf(1, bytes.size))
        b.copyFrom(bytes, 0, 0, bytes.size)
        try {
            block(b, bytes.size)
        } finally {
            b.close()
        }
    }

    /** Events, sending and due timers for one connection; returns the datagrams it sent. */
    fun service(core: ConnectionCore): List<ByteArray> {
        drain(core)
        batch.clear()
        val n = core.poll(batch, now)
        val sent =
            List(n) {
                val l = batch.length(it)
                ByteArray(l).also { a -> batch.buffer(it).copyTo(a, 0, 0, l) }
            }
        core.nextTimeout()?.let { if (it <= now) core.onTimeout(now) }
        drain(core)
        return sent
    }

    fun service(ep: EndpointCore) {
        batch.clear()
        ep.pollStateless(batch)
        while (ep.nextAccepted() != null) { /* the application takes every connection */ }
        for (c in ep.connections().toList()) service(c)
    }

    /** Lets virtual time pass so loss, ack and idle timers fire. */
    fun tick(ms: Long = 30) {
        now += ms.milliseconds
    }

    private fun drain(core: ConnectionCore) {
        while (true) {
            val e = core.nextEvent() ?: break
            if (e is ConnectionEvent.Closed) {
                closedSeen += core
                (e.reason as? QuicException.ConnectionLost.Internal)?.let {
                    throw IllegalStateException(
                        "a connection crashed: ${it.message}",
                        it.cause ?: it,
                    )
                }
            }
        }
        if (core.state == ConnectionState.Closing || core.state == ConnectionState.Draining || core.state == ConnectionState.Closed) {
            check(core in closedSeen) { "connection reached ${core.state} without a Closed event" }
        }
    }

    override fun close() {
        batch.close()
    }
}
