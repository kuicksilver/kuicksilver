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
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.isActive
import kotlinx.coroutines.job
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull
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
    /** How long non-repeatable work on a stalled connection may wait for the path to come back before it fails. */
    val abandonAfter: Duration,
) {
    /** How often a watched connection's counters are read: an eighth of [minSilence], 25 ms..250 ms. */
    val pollInterval: Duration = (minSilence / 8).coerceIn(25.milliseconds, 250.milliseconds)

    /** The first liveness PING of a quiet watched connection goes after half of [minSilence] without a packet. */
    val firstPing: Duration = minSilence / 2
}

/** The longest gap between two liveness PINGs of a watched connection; half the idle timeout in force when that is shorter. */
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
    /** Shared by the stalls of one connection: a connection that stalls, recovers and stalls again marks once. */
    private val marked: AtomicReference<Set<String>> = AtomicReference(emptySet()),
) {
    /** True for the first caller with [key] for this connection: that caller marks the alternative broken. */
    fun claim(key: String): Boolean {
        while (true) {
            val now = marked.load()
            if (key in now) return false
            if (marked.compareAndSet(now, now + key)) return true
        }
    }

    /** When it was declared ([H3StallMonitor]'s clock). */
    var at: Long = 0

    /** A new exception for one request (its own stack), with [cause] what the request itself saw. */
    fun exception(cause: Throwable?): QuicStalledException = QuicStalledException(this, cause)
}

/** Cancels a repeatable request's wait when its connection stalls: the request then goes over TCP. */
internal class StallAbort(
    val stall: Stall,
) : CancellationException("HTTP/3 connection stalled")

/**
 * Stall detection for one HTTP/3 connection (docs/guide/ktor.md, "Stalled HTTP/3 connections"): a path that stopped
 * carrying packets in both directions (a middlebox that cuts UDP flows) is found within seconds, not at the idle
 * timeout (RFC 9000 section 10.1, 30 s by default). It runs only while requests [watch] the connection; with none, it
 * waits without timers, and while the watched connection is quiet it sleeps until its next PING is due.
 *
 * The signal is the transport's: loss recovery arms a probe timeout (PTO, RFC 9002 section 6.2) whenever ack-eliciting
 * data is in flight, and [io.kuicksilver.quic.ConnectionStats.ptoCount] counts the PTOs in a row without an
 * acknowledgement. The connection is stalled when
 * - after the handshake: [StallSettings.probeTimeouts] PTOs in a row went unanswered and no packet at all arrived for
 *   [StallSettings.minSilence] since the first of them was seen. The PTO grows with the RTT and doubles at each expiry,
 *   so K PTOs are about (2^K - 1) PTOs of time (K = 3: 7 x (smoothed RTT + 4 x RTT variation + max_ack_delay)); the
 *   silence floor keeps a short blip on a low-RTT path from counting;
 * - before it (a request waiting on a 0-RTT connection): nothing at all came back from the server, not even an
 *   Initial, since the request started watching, for at least [StallSettings.minSilence] and two PTOs. The handshake's
 *   PTOs start from the 333 ms initial RTT (RFC 9002 section 6.2.2) and double, so two of them are about 3 s of a slow
 *   path's handshake.
 *
 * A slow server (long think time) acknowledges the request, and an idle long-lived exchange (a long poll, a server-sent
 * event stream between events) has nothing in flight: neither shows a PTO. So that a path cut while nothing is in flight
 * is found too, a watched connection that is quiet sends a PING (RFC 9000 section 10.1.2), first after half of
 * [StallSettings.minSilence] without a packet, then at twice the previous gap, up to [MAX_PING_INTERVAL] or half the
 * idle timeout in force, whichever is shorter (as `QuicConfig.keepAlive`): a live peer acknowledges it, a dead path turns
 * it into PTOs. While a request waits for its response this also keeps the connection open past the idle timeout, as
 * RFC 9114 section 5.1 expects of a client with responses outstanding.
 *
 * On a stall the connection is drained, not closed: [onStall] runs first (the pool hands the connection out no more and
 * the engine marks the alternative broken), then the waits of the repeatable requests ([Watch.abortable]) end with
 * [QuicStalledException] so that they go over TCP. Everything else — a request that may not be repeated, a response body
 * being read — goes on: a path that comes back (any packet) lets it finish. When the path stays silent for
 * [StallSettings.abandonAfter] after the stall, the bodies still being read fail with [QuicStalledException] and the
 * connection is closed (H3_NO_ERROR, the reason naming the stall), which fails the rest; the requests map that failure
 * to the stall ([Watch.stall]).
 */
@OptIn(ExperimentalAtomicApi::class)
internal class H3StallMonitor(
    private val conn: Http3Connection,
    private val settings: StallSettings,
    private val clock: () -> Long,
    /** With the stall and the keys (`origin|alternative`) of the requests that watched the connection then. */
    private val onStall: suspend (Stall, Set<String>) -> Unit,
    /** A watched exchange on a connection that never stalled received its whole response (`origin|alternative`). */
    private val onCompleted: (String) -> Unit = {},
    /** Logs at Warn: a failure of the monitor itself, which goes on. */
    private val warn: (String, Throwable?) -> Unit = { _, _ -> },
    /** Each wake-up of the watching loop (tests count them). */
    private val polled: () -> Unit = {},
) {
    private val watchers = MutableStateFlow(0)
    private val keys = AtomicReference(emptyList<String>())
    private val aborts = AtomicReference(emptyList<(Stall) -> Unit>())
    private val bodies = AtomicReference(emptyList<(QuicStalledException) -> Unit>())
    private val completedOnce = kotlin.concurrent.atomics.AtomicInt(0)
    private val marked = AtomicReference(emptySet<String>())

    /** The stall in force: declared and the path not back yet. */
    @kotlin.concurrent.Volatile
    var stall: Stall? = null
        private set

    /** The stall that outlasted [StallSettings.abandonAfter]: the connection was closed. */
    @kotlin.concurrent.Volatile
    var abandoned: Stall? = null
        private set

    @kotlin.concurrent.Volatile
    private var everStalled = false

    /** One request watching the connection; [end] once it no longer needs the network or is over. */
    inner class Watch(
        private val key: String,
    ) {
        private val ended = kotlin.concurrent.atomics.AtomicInt(0)
        private val body = AtomicReference<((QuicStalledException) -> Unit)?>(null)

        /** The stall the request's failure belongs to, if any: the one that closed the connection, or the one in force. */
        val stall: Stall? get() = abandoned ?: this@H3StallMonitor.stall

        /**
         * Runs [block], the wait of a request that may be repeated (or was not sent yet), until a stall: then it ends with
         * [QuicStalledException] (the block cancelled), so the request goes over TCP. A stall already in force ends it
         * before [block] starts.
         */
        suspend fun <T> abortable(block: suspend () -> T): T {
            this@H3StallMonitor.stall?.let { throw it.exception(null) }
            var abort: ((Stall) -> Unit)? = null
            try {
                return coroutineScope {
                    val job = coroutineContext.job
                    val a: (Stall) -> Unit = { s -> job.cancel(StallAbort(s)) }
                    abort = a
                    aborts.update { it + a }
                    this@H3StallMonitor.stall?.let(a) // declared between the check and the registration
                    block()
                }
            } catch (e: CancellationException) {
                val s = generateSequence<Throwable>(e) { it.cause }.filterIsInstance<StallAbort>().firstOrNull()
                if (s != null && currentCoroutineContext().isActive) throw s.stall.exception(null)
                throw e
            } finally {
                abort?.let { a -> aborts.update { it - a } }
            }
        }

        /** [block] runs if the connection is abandoned while this watch lasts (a response body being read fails then). */
        fun onAbandon(block: (QuicStalledException) -> Unit) {
            body.store(block)
            bodies.update { it + block }
            abandoned?.let { if (ended.load() == 0) block(it.exception(null)) }
        }

        /**
         * The request needs the network no more: its whole response arrived ([completed]: a watched exchange that ended
         * well), or the call is over. Idempotent.
         */
        fun end(completed: Boolean = false) {
            if (!ended.compareAndSet(0, 1)) return
            body.load()?.let { l -> bodies.update { it - l } }
            keys.update { it - key }
            watchers.update { it - 1 }
            if (completed && !everStalled && completedOnce.compareAndSet(0, 1)) runCatching { onCompleted(key) }
        }
    }

    /**
     * A request for [key] (`origin|alternative`, what a stall marks broken) watches the connection from now on. A
     * connection that stalled already takes no request: [QuicStalledException] (the request was not sent).
     */
    fun watch(key: String): Watch {
        (abandoned ?: stall)?.let { throw it.exception(null) }
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

    /**
     * Runs until the connection ends or is abandoned; launched once per connection. A failure of its own (reading the
     * counters, sending a PING) is logged and the watch goes on.
     */
    suspend fun run() {
        while (abandoned == null && !conn.quic.closed.isCompleted) {
            watchers.first { it > 0 }
            try {
                watchWhileWatched()
            } catch (e: CancellationException) {
                throw e
            } catch (e: Throwable) {
                warn("HTTP/3 stall detection failed on a connection; it goes on watching", e)
                delay(settings.pollInterval)
            }
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
        val poll = settings.pollInterval.inWholeMilliseconds
        var quiet = false // nothing in flight at the last look: sleep until the next PING is due
        while (true) {
            val w = watchers.value
            if (w == 0) break
            val due = maxOf(lastReceived, lastPing) + pingGap - clock()
            if (quiet && stall == null && due > poll) {
                // a new request (or one leaving) wakes the watch: it may have put data in flight
                withTimeoutOrNull(due) { watchers.first { it != w } }
            } else {
                delay(poll)
            }
            polled()
            if (quic.closed.isCompleted) return
            val s = quic.stats
            val now = clock()
            if (s.packetsReceived != received) {
                received = s.packetsReceived
                lastReceived = now
                ptoSeenAt = -1L
                quiet = false
                // the path came back: work that waited on the drained connection finishes on it
                if (stall != null) stall = null
                continue
            }
            if (s.ptoCount == 0) {
                ptoSeenAt = -1L
            } else if (ptoSeenAt < 0) {
                ptoSeenAt = now
            }
            val current = stall
            if (current != null) {
                if (now - current.at >= settings.abandonAfter.inWholeMilliseconds) {
                    abandon(current)
                    return
                }
                continue
            }
            val handshaken = quic.isHandshakeComplete
            val stalled =
                if (handshaken) {
                    s.ptoCount >= settings.probeTimeouts && ptoSeenAt >= 0 && now - ptoSeenAt >= minSilence
                } else {
                    // nothing at all from the server since the request started watching (RFC 9000 section 10.1 has no
                    // handshake equivalent: the handshake timeout bounds it, 10 s by default)
                    s.packetsReceived == 0L && s.ptoCount >= 2 && now - start >= minSilence
                }
            if (stalled) {
                declare(Stall((now - maxOf(lastReceived, start)).milliseconds, s.ptoCount, handshaken, marked).also { it.at = now })
                continue
            }
            quiet = handshaken && s.ptoCount == 0 && s.bytesInFlight == 0L
            // a quiet watched connection: nothing in flight, so a dead path would show no PTO; a PING gives it one
            if (quiet && now - maxOf(lastReceived, lastPing) >= pingGap) {
                if (quic.ping()) {
                    lastPing = now
                    quiet = false
                    // at most half the idle timeout in force, so the PINGs keep the connection open (RFC 9114 section 5.1)
                    val cap = minOf(MAX_PING_INTERVAL, s.idleTimeout / 2).inWholeMilliseconds.coerceAtLeast(poll)
                    pingGap = minOf(pingGap * 2, cap)
                }
            }
        }
        // the last watcher left a drained connection: nobody else will use it
        stall?.let { abandon(it) }
    }

    private suspend fun declare(s: Stall) {
        stall = s
        everStalled = true
        try {
            onStall(s, keys.load().toSet())
        } catch (e: CancellationException) {
            throw e
        } catch (e: Throwable) {
            warn("HTTP/3 stall bookkeeping failed", e)
        }
        for (a in aborts.load()) runCatching { a(s) }
    }

    private suspend fun abandon(s: Stall) {
        abandoned = s
        for (l in bodies.load()) runCatching { l(s.exception(null)) }
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
