// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.client.h3

import io.kuicksilver.http3.Http3Connection
import io.kuicksilver.http3.Http3ErrorCode
import io.kuicksilver.ktor.client.QuicStalledException
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import kotlin.concurrent.atomics.AtomicReference
import kotlin.concurrent.atomics.ExperimentalAtomicApi
import kotlin.time.Duration
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds

/**
 * The thresholds of HTTP/3 stall detection (`http3 { stallDetection }`): [probeTimeouts] probe timeouts in a row
 * (RFC 9002 section 6.2) and at least [minSilence] without any packet from the peer.
 */
internal class StallSettings(
    val probeTimeouts: Int,
    val minSilence: Duration,
) {
    /** How often a watched connection's counters are read: an eighth of [minSilence], 25 ms..250 ms. */
    val pollInterval: Duration = (minSilence / 8).coerceIn(25.milliseconds, 250.milliseconds)

    /** The first liveness PING of a quiet watched connection goes after half of [minSilence] without a packet. */
    val firstPing: Duration = minSilence / 2
}

/** The longest gap between two liveness PINGs of a watched connection (Chromium's ping timeout, 15 s). */
internal val MAX_PING_INTERVAL = 15.seconds

/**
 * The stall of one HTTP/3 connection, shared by the requests it failed: what was seen, and which (origin, alternative)
 * pairs a request already marked broken for it (one mark per stall, however many requests it failed).
 */
@OptIn(ExperimentalAtomicApi::class)
internal class Stall(
    val silence: Duration,
    val probeTimeouts: Int,
    val handshakeComplete: Boolean,
) {
    private val marked = AtomicReference(emptySet<String>())

    /** True for the first caller with [key]: that caller marks the alternative broken. */
    fun claim(key: String): Boolean {
        while (true) {
            val now = marked.load()
            if (key in now) return false
            if (marked.compareAndSet(now, now + key)) return true
        }
    }

    /** A new exception for one request (its own stack), with [cause] what the request itself saw. */
    fun exception(cause: Throwable?): QuicStalledException = QuicStalledException(this, cause)
}

/**
 * Stall detection for one HTTP/3 connection (docs/guide/ktor.md, "Stalled HTTP/3 connections"): a path that stopped
 * carrying packets in both directions (a middlebox that cuts UDP flows) is found within seconds, not at the idle
 * timeout (RFC 9000 section 10.1, 30 s by default). It runs only while requests [watch] the connection; with none, it
 * waits without timers.
 *
 * The signal is the transport's: loss recovery arms a probe timeout (PTO, RFC 9002 section 6.2) whenever ack-eliciting
 * data is in flight, and [io.kuicksilver.quic.ConnectionStats.ptoCount] counts the PTOs in a row without an
 * acknowledgement. The connection is stalled when
 * - after the handshake: [StallSettings.probeTimeouts] PTOs in a row went unanswered and no packet at all arrived for
 *   [StallSettings.minSilence] since the first of them was seen. The PTO grows with the RTT and doubles at each expiry,
 *   so K PTOs are about (2^K - 1) PTOs of time (K = 3: 7 x (smoothed RTT + 4 x RTT variation + max_ack_delay)); the
 *   silence floor keeps a short blip on a low-RTT path from counting;
 * - before it (a request waiting on a 0-RTT connection): nothing at all came back from the server, not even an
 *   Initial, for [StallSettings.minSilence] since the request started watching, and at least one PTO expired. The
 *   handshake's PTOs start from the 333 ms initial RTT (RFC 9002 section 6.2.2), so K of them would take some 7 s.
 *
 * A slow server (long think time) acknowledges the request, and an idle long-lived exchange (a long poll, a server-sent
 * event stream between events) has nothing in flight: neither shows a PTO. So that a path cut while nothing is in flight
 * is found too, a watched connection that is quiet sends a PING (RFC 9000 section 10.1.2), first after half of
 * [StallSettings.minSilence] without a packet, then at twice the previous gap, up to [MAX_PING_INTERVAL] (Chromium sends
 * its pings only while streams are open, too): a live peer acknowledges it, a dead path turns it into PTOs.
 *
 * On a stall [onStall] runs once with the [Stall]; the listeners of the watching requests get it first (a response body
 * being read fails with [QuicStalledException]), then the connection is closed (H3_NO_ERROR, the reason naming the
 * stall), which fails everything else on it.
 */
@OptIn(ExperimentalAtomicApi::class)
internal class H3StallMonitor(
    private val conn: Http3Connection,
    private val settings: StallSettings,
    private val clock: () -> Long,
    /** With the stall and the keys (`origin|alternative`) of the requests that watched the connection then. */
    private val onStall: (Stall, Set<String>) -> Unit,
) {
    private val watchers = MutableStateFlow(0)
    private val keys = AtomicReference(emptyList<String>())
    private val listeners = AtomicReference(emptyList<(QuicStalledException) -> Unit>())

    /** The stall, once found. */
    @kotlin.concurrent.Volatile
    var stall: Stall? = null
        private set

    /** One request watching the connection; [end] once it is over (its response read or abandoned, or it failed). */
    inner class Watch(
        private val key: String,
    ) {
        private val ended = kotlin.concurrent.atomics.AtomicInt(0)
        private var listener: ((QuicStalledException) -> Unit)? = null

        val stall: Stall? get() = this@H3StallMonitor.stall

        /** [block] runs if the connection stalls while this watch lasts (twice at most, when both race; it must be idempotent). */
        fun onStall(block: (QuicStalledException) -> Unit) {
            listener = block
            listeners.update { it + block }
            this@H3StallMonitor.stall?.let { if (ended.load() == 0) block(it.exception(null)) }
        }

        fun end() {
            if (!ended.compareAndSet(0, 1)) return
            listener?.let { l -> listeners.update { it - l } }
            keys.update { it - key }
            watchers.update { it - 1 }
        }
    }

    /** A request for [key] (`origin|alternative`, what a stall marks broken) watches the connection from now on. */
    fun watch(key: String): Watch {
        keys.update { it + key }
        watchers.update { it + 1 }
        return Watch(key)
    }

    private inline fun <T> AtomicReference<T>.update(f: (T) -> T) {
        while (true) {
            val v = load()
            if (compareAndSet(v, f(v))) return
        }
    }

    /** Runs until the connection ends or stalls (then closes it); launched once per connection. */
    @OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)
    suspend fun run() {
        while (stall == null) {
            watchers.first { it > 0 }
            watchWhileWatched()
        }
    }

    @OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)
    private suspend fun watchWhileWatched() {
        val quic = conn.quic
        val start = clock()
        var received = quic.stats.packetsReceived
        var lastReceived = start // a packet, or the start of the watch: the request was sent then
        var ptoSeenAt = -1L // when the first unanswered PTO was seen, -1 while there is none
        var pingGap = settings.firstPing.inWholeMilliseconds
        var lastPing = -1L
        val minSilence = settings.minSilence.inWholeMilliseconds
        while (watchers.value > 0) {
            delay(settings.pollInterval)
            if (quic.closed.isCompleted) return
            val s = quic.stats
            val now = clock()
            if (s.packetsReceived != received) {
                received = s.packetsReceived
                lastReceived = now
                ptoSeenAt = -1L
                continue
            }
            if (s.ptoCount == 0) {
                ptoSeenAt = -1L
            } else if (ptoSeenAt < 0) {
                ptoSeenAt = now
            }
            val handshaken = quic.isHandshakeComplete
            val stalled =
                if (handshaken) {
                    s.ptoCount >= settings.probeTimeouts && ptoSeenAt >= 0 && now - ptoSeenAt >= minSilence
                } else {
                    // nothing at all from the server since the request started watching (RFC 9000 section 10.1 has no
                    // handshake equivalent: the handshake timeout bounds it, 10 s by default)
                    s.packetsReceived == 0L && s.ptoCount >= 1 && now - start >= minSilence
                }
            if (stalled) {
                val silence = (now - maxOf(lastReceived, start)).milliseconds
                declare(Stall(silence, s.ptoCount, handshaken))
                return
            }
            // a quiet watched connection: nothing in flight, so a dead path would show no PTO; a PING gives it one
            if (handshaken && s.ptoCount == 0 && s.bytesInFlight == 0L &&
                now - maxOf(lastReceived, lastPing) >= pingGap
            ) {
                if (quic.ping()) {
                    lastPing = now
                    pingGap = minOf(pingGap * 2, MAX_PING_INTERVAL.inWholeMilliseconds)
                }
            }
        }
    }

    private suspend fun declare(s: Stall) {
        stall = s
        try {
            onStall(s, keys.load().toSet())
        } catch (e: CancellationException) {
            throw e
        } catch (_: Throwable) {
            // the pool's bookkeeping; the connection is closed whatever it did
        }
        for (l in listeners.load()) runCatching { l(s.exception(null)) }
        withContext(NonCancellable) {
            runCatching { conn.close(Http3ErrorCode.NO_ERROR, "stalled: no packet for ${s.silence.inWholeMilliseconds} ms") }
        }
    }

    companion object {
        /** Starts [monitor] in [scope] until its connection ends; the job is cancelled when the QUIC connection ends. */
        fun launch(
            scope: CoroutineScope,
            monitor: H3StallMonitor,
            finally: () -> Unit,
        ): Job {
            val job =
                scope.launch {
                    try {
                        monitor.run()
                    } finally {
                        finally()
                    }
                }
            monitor.conn.quic.closed
                .invokeOnCompletion { job.cancel() }
            return job
        }
    }
}
