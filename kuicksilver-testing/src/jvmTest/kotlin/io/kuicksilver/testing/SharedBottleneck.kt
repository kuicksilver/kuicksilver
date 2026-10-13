// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.testing

import io.ktor.network.sockets.InetSocketAddress
import io.kuicksilver.annotations.DelicateKuicksilverApi
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.native.PacketBuffer
import io.kuicksilver.native.toByteArray
import io.kuicksilver.quic.ConnectionCore
import io.kuicksilver.quic.ConnectionEvent
import io.kuicksilver.quic.EndpointCore
import io.kuicksilver.quic.IoCapabilities
import io.kuicksilver.quic.NullCryptoProvider
import io.kuicksilver.quic.PacketBatch
import io.kuicksilver.quic.PathId
import io.kuicksilver.quic.QuicClientConfig
import io.kuicksilver.quic.QuicConfig
import io.kuicksilver.quic.QuicEndpointConfig
import io.kuicksilver.quic.QuicServerConfig
import io.kuicksilver.quic.StreamPriority
import io.kuicksilver.quic.TimeMark
import io.kuicksilver.tls.TlsIdentity
import kotlinx.coroutines.runBlocking
import kotlin.random.Random
import kotlin.time.Duration
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.nanoseconds

/**
 * Several bulk uploads over one bottleneck under virtual time: every flow has its own client and server endpoint, the data
 * direction is one shared [SimLink] ([data], usually bandwidth-limited with a finite buffer), the ACK direction another ([acks]).
 * Each flow writes as fast as its stream accepts from [Flow.start] on; the server reads everything. Goodput is what the servers
 * read inside a measurement window; the bottleneck's queueing delay is sampled per data datagram.
 */
@OptIn(ExperimentalKuicksilverApi::class, DelicateKuicksilverApi::class)
internal class SharedBottleneck(
    seed: Long,
    data: LinkParams,
    acks: LinkParams = LinkParams(delay = data.delay),
    /** What both endpoints' sockets can do (ECN, DF for PMTUD); null: the portable socket (no ECN, the MTU stays 1200). */
    private val caps: IoCapabilities? = null,
) {
    var now: TimeMark = TimeMark(1_000_000_000L)
        private set

    /** The data direction (the bottleneck) and the ACK direction, for scenarios that change them mid-run. */
    val c2s = SimLink(data, Random(seed * 31 + 1), "c2s")
    val s2c = SimLink(acks, Random(seed * 31 + 2), "s2c")
    private val batch = PacketBatch(32)
    private val identity = TlsIdentity.fromDer(listOf(TestCerts.server), TestCerts.serverKey.copyOf())
    private val tls = SimScenario.nullTls(identity)
    private val seedBase = seed
    val flows = ArrayList<Flow>()
    private val chunk = ByteArray(16384)
    private val sink = ByteArray(65536)

    // queueing delay of the data datagrams inside the measurement window
    private var measuring = false
    private var queueDelaySum = 0L
    private var queueDelayCount = 0L
    var maxQueueDelay: Duration = Duration.ZERO
        private set

    // the queueing delay integrated over time (what a packet arriving at a random instant would wait), inside the window
    private var queueAreaNanos2 = 0.0
    private var markedAt = now

    val tailDrops: Long get() = c2s.tailDropped

    inner class Flow(
        val index: Int,
        quic: QuicConfig,
        val start: TimeMark,
    ) {
        val clientAddr = InetSocketAddress("10.0.1.${index + 1}", 40000 + index)
        val serverAddr = InetSocketAddress("10.0.2.${index + 1}", 443)
        val clientEp =
            EndpointCore(QuicEndpointConfig.Builder().apply { crypto = NullCryptoProvider }.build(), Random(seedBase + 100 + index))
        val serverEp =
            EndpointCore(
                QuicEndpointConfig
                    .Builder()
                    .apply {
                        server = QuicServerConfig.Builder(tls.second).apply { this.quic = quic }.build()
                        crypto = NullCryptoProvider
                    }.build(),
                Random(seedBase + 200 + index),
            )
        private val quicConfig = quic
        var client: ConnectionCore? = null
        var server: ConnectionCore? = null
        var stream = -1L
        var read = 0L
        var readAtMark = 0L
        var lost: Long = 0
        var clientReady = false
        var serverReady = false

        /** The application has nothing to send while set (an on/off flow); the stream stays open. */
        var paused = false

        fun begin() {
            client =
                clientEp.connect(QuicClientConfig.Builder(tls.first).apply { this.quic = quicConfig }.build(), serverAddr, now).also { c ->
                    caps?.let { c.setPathCapabilities(PathId.Initial, it) }
                }
        }
    }

    fun addFlow(
        quic: QuicConfig,
        startAfter: Duration = Duration.ZERO,
    ): Flow = Flow(flows.size, quic, now + startAfter).also { flows += it }

    /** Starts the measurement window: goodput and queueing delay count from here. */
    fun mark() {
        for (f in flows) f.readAtMark = f.read
        measuring = true
        queueAreaNanos2 = 0.0
        markedAt = now
        queueDelaySum = 0
        queueDelayCount = 0
        maxQueueDelay = Duration.ZERO
    }

    val meanQueueDelay: Duration get() = if (queueDelayCount == 0L) Duration.ZERO else (queueDelaySum / queueDelayCount).nanoseconds

    /** The bottleneck's queueing delay averaged over time since [mark] (idle time counts as an empty queue). */
    val timeMeanQueueDelay: Duration
        get() {
            val span = (now - markedAt).inWholeNanoseconds
            return if (span <= 0) Duration.ZERO else (queueAreaNanos2 / span).toLong().nanoseconds
        }

    /** Adds the area under the queueing delay from [a] to [b]: it falls with slope 1 until the link is idle. */
    private fun integrateQueue(
        a: TimeMark,
        b: TimeMark,
    ) {
        if (!measuring || b <= a) return
        val busy = c2s.busyUntil
        if (busy <= a) return
        val qa = (busy - a).inWholeNanoseconds.toDouble()
        queueAreaNanos2 +=
            if (busy >= b) {
                val qb = (busy - b).inWholeNanoseconds.toDouble()
                (qa + qb) / 2 * (b - a).inWholeNanoseconds
            } else {
                qa * qa / 2
            }
    }

    fun run(limit: Duration) {
        val end = now + limit
        while (now < end) {
            step()
            var next: TimeMark? = null

            fun consider(t: TimeMark?) {
                if (t != null && t > now && (next == null || t < next!!)) next = t
            }
            for (f in flows) {
                if (f.client == null) consider(f.start)
                consider(f.client?.nextTimeout())
                consider(f.server?.nextTimeout())
            }
            consider(c2s.nextArrival())
            consider(s2c.nextArrival())
            val n = next
            var to = if (n == null || n > now + 50.milliseconds) now + 50.milliseconds else n
            if (to > end) to = end
            integrateQueue(now, to)
            now = to
        }
    }

    private fun step() {
        for (f in flows) {
            if (f.client == null && now >= f.start) f.begin()
            f.client?.let { c -> c.nextTimeout()?.let { if (it <= now) c.onTimeout(now) } }
            f.server?.let { s -> s.nextTimeout()?.let { if (it <= now) s.onTimeout(now) } }
        }
        for (d in c2s.due(now)) {
            val f = flows[d.tag]
            deliver(f.serverEp, d, f.clientAddr)?.let { if (f.server == null) f.server = it }
        }
        for (f in flows) {
            val before = f.serverEp.connectionCount
            if (f.serverEp.processPending(now) > 0 && f.server == null && f.serverEp.connectionCount > before) {
                f.server =
                    f.serverEp
                        .connections()
                        .last()
                        .also { sv -> caps?.let { sv.setPathCapabilities(PathId.Initial, it) } }
            }
        }
        for (d in s2c.due(now)) {
            val f = flows[d.tag]
            deliver(f.clientEp, d, f.serverAddr)
            f.clientEp.processPending(now)
        }
        for (f in flows) {
            val c = f.client ?: continue
            if (drain(c)) f.clientReady = true
            f.server?.let { if (drain(it)) f.serverReady = true }
            if (f.clientReady && f.serverReady) {
                if (f.stream < 0) f.stream = c.openStream(true, StreamPriority.Default)
                if (f.stream >= 0 && !f.paused) {
                    while (c.writeStream(f.stream, chunk, 0, chunk.size, false) > 0) {}
                }
            }
            f.server?.let { s ->
                if (f.stream >= 0) {
                    while (true) {
                        val n = s.readStream(f.stream, sink, 0, sink.size)
                        if (n <= 0) break
                        f.read += n
                    }
                }
            }
            poll(c, c2s, f.index, data = true)
            f.server?.let { poll(it, s2c, f.index, data = false) }
            f.lost = c.stats.lostPackets
        }
    }

    /** Handles the events of [core]; true when the handshake completed among them. */
    private fun drain(core: ConnectionCore): Boolean {
        var done = false
        while (true) {
            val e = core.nextEvent() ?: break
            if (e is ConnectionEvent.VerifyRequested) core.resumeVerify(runBlocking { e.session.verifyPeer(e.chain) })
            if (e is ConnectionEvent.HandshakeCompleted) done = true
        }
        return done
    }

    private fun deliver(
        ep: EndpointCore,
        d: InFlight,
        from: InetSocketAddress,
    ): ConnectionCore? {
        val b = PacketBuffer.allocate(d.bytes.size)
        try {
            b.copyFrom(d.bytes, 0, 0, d.bytes.size)
            return ep.handleDatagram(b, d.bytes.size, from, d.ecn, now)
        } finally {
            b.close()
        }
    }

    private fun poll(
        core: ConnectionCore,
        link: SimLink,
        tag: Int,
        data: Boolean,
    ) {
        batch.clear()
        val n = core.poll(batch, now)
        for (i in 0 until n) {
            link.send(batch.buffer(i).toByteArray(batch.length(i)), batch.ecn(i), now, tag)
            if (data && measuring) {
                val q = link.lastQueueDelay
                queueDelaySum += q.inWholeNanoseconds
                queueDelayCount++
                if (q > maxQueueDelay) maxQueueDelay = q
            }
        }
    }

    /** Goodput of [f] in bits per second since [mark], over [window]. */
    fun goodputBits(
        f: Flow,
        window: Duration,
    ): Long = (f.read - f.readAtMark) * 8 * 1000 / window.inWholeMilliseconds
}
