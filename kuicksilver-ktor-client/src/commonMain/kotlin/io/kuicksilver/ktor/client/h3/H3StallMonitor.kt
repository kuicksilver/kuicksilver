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
 * The thresholds of HTTP/3 stall detection (`http3 { stall { enabled } }`): [probeTimeouts] probe timeouts in a row
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
 * Stall detection for one HTTP/3 connection (docs/guide/client-http3.md, "Stalled HTTP/3 connections"): a path that stopped
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
    /**
     * The connection ended without ever stalling, after it carried whole exchanges for these `origin|alternative` keys (a
     * stall's backoff walks down for each; one that later stalls never counts, however many exchanges it carried first).
     */
    private val onCompleted: (Set<String>) -> Unit = {},
    /** Logs at Warn: a failure of the monitor itself, which goes on. */
    private val warn: (String, Throwable?) -> Unit = { _, _ -> },
    /** Each wake-up of the watching loop (tests count them). */
    private val polled: () -> Unit = {},
    /** The watching loop started (+1) or ended (-1): no request watches the connection any more (tests). */
    private val looping: (Int) -> Unit = {},
    /** A liveness PING went out (tests). */
    private val pinged: () -> Unit = {},
) {
    private val watchers = MutableStateFlow(0)
    private val keys = AtomicReference(emptyList<String>())
    private val aborts = AtomicReference(emptyList<(Stall) -> Unit>())
    private val bodies = AtomicReference(emptyList<(QuicStalledException) -> Unit>())
    private val completedKeys = AtomicReference(emptySet<String>())
    private val marked = AtomicReference(emptySet<String>())

    /** The stall in force: declared and the path not back yet. */
    @kotlin.concurrent.Volatile
    var stall: Stall? = null
        private set(value) {
            field = value
            stalledState.value = value != null
        }

    /** Whether a stall is in force ([stall] non-null), for the socket timeout to stand still meanwhile. */
    private val stalledState = MutableStateFlow(false)

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
         * True while a stall is in force: the request's socket timeout stands still then (`stall { abandonAfter }` decides
         * when the request fails, as StallConfig promises) and starts over once the path is back.
         */
        val stalled: kotlinx.coroutines.flow.StateFlow<Boolean> get() = stalledState

        /**
         * Runs [block], the wait of a request that may be repeated (or was not sent yet), until a stall: then it ends with
         * [QuicStalledException] (the block cancelled), so the request goes over TCP. A stall already in force ends it
         * before [block] starts.
         */
        suspend fun <T : Any> abortable(
            /** What [block] returned when the stall's abort won the race with its return: given up (its stream closed). */
            discard: (T) -> Unit = {},
            block: suspend () -> T,
        ): T {
            this@H3StallMonitor.stall?.let { throw it.exception(null) }
            var abort: ((Stall) -> Unit)? = null
            val made = AtomicReference<T?>(null)
            try {
                return coroutineScope {
                    val job = coroutineContext.job
                    val a: (Stall) -> Unit = { s -> job.cancel(StallAbort(s)) }
                    abort = a
                    aborts.update { it + a }
                    this@H3StallMonitor.stall?.let(a) // declared between the check and the registration
                    block().also { made.store(it) }
                }
            } catch (e: CancellationException) {
                // the abort landed after the block returned: the scope throws, and what it returned would leak
                made.load()?.let { runCatching { discard(it) } }
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
            if (completed && !everStalled) completedKeys.update { it + key }
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
            looping(1)
            try {
                watchWhileWatched()
            } catch (e: CancellationException) {
                throw e
            } catch (e: Throwable) {
                warn("HTTP/3 stall detection failed on a connection; it goes on watching", e)
                delay(settings.pollInterval)
            } finally {
                looping(-1)
            }
        }
    }

    /**
     * The connection is over (the monitor's job ends with it): one that never stalled, carried whole exchanges and was
     * closed in order by this client (the pool's idle close, a retirement, the client's close: an application close of
     * ours with H3_NO_ERROR) lets the backoff walk down. One that died otherwise (an idle timeout, a reset, an error)
     * proves nothing about the path and lowers nothing. True when it lowered.
     */
    @OptIn(kotlinx.coroutines.ExperimentalCoroutinesApi::class)
    fun ended(): Boolean {
        if (everStalled) return false
        val keys = completedKeys.load().takeIf { it.isNotEmpty() } ?: return false
        val end =
            conn.quic.closed
                .takeIf { it.isCompleted }
                ?.getCompleted()
        val orderly =
            end is io.kuicksilver.quic.QuicException.ConnectionLost.ApplicationClosed &&
                end.initiator == io.kuicksilver.quic.Initiator.Local &&
                Http3ErrorCode.normalize(end.code) == Http3ErrorCode.NO_ERROR
        if (!orderly) return false
        runCatching { onCompleted(keys) }
        return true
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
                // the path came back: work that waited on the drained connection finishes on it. A PING now gets an ACK at
                // once, which shows what the outage lost (RFC 9002 section 6.1), so the request's data is sent again without
                // waiting out a probe timeout that backed off through the outage; the socket timeout starts over meanwhile
                if (stall != null) {
                    stall = null
                    try {
                        quic.ping()
                    } catch (e: CancellationException) {
                        throw e
                    } catch (_: Throwable) {
                        // a connection that closed meanwhile: nothing to probe
                    }
                }
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
                    pinged()
                    lastPing = now
                    quiet = false
                    // at most half the idle timeout in force, so the PINGs keep the connection open (RFC 9114 section 5.1)
                    val cap = minOf(MAX_PING_INTERVAL, s.idleTimeout / 2).inWholeMilliseconds.coerceAtLeast(poll)
                    pingGap = minOf(pingGap * 2, cap)
                }
            }
        }
        // the last watcher left a connection still stalled: the path is dead, it is closed now. One that came back is the
        // pool's: drained at the stall, it closes at its last release (an unwatched WebSocket or session included)
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
        // the connection is closed below: no timer waits on it any more ([Watch.stall] keeps naming the stall)
        stalledState.value = false
        for (l in bodies.load()) runCatching { l(s.exception(null)) }
        withContext(NonCancellable) {
            runCatching { conn.close(Http3ErrorCode.NO_ERROR, "stalled: no packet for ${s.silence.inWholeMilliseconds} ms") }
        }
    }

    /** Lets every socket timeout that stood still for a stall run again (the monitor ended). */
    internal fun releaseHold() {
        stalledState.value = false
    }

    companion object {
        /** Starts [monitor] in [scope] until its connection ends; the job is cancelled when the QUIC connection ends. */
        fun launch(
            scope: CoroutineScope,
            monitor: H3StallMonitor,
            /** With whether the ended connection lowered a stall's backoff ([ended]). */
            finally: (Boolean) -> Unit,
        ): Job {
            val job =
                scope.launch {
                    try {
                        monitor.run()
                    } finally {
                        // the watch is over: a hold that outlived it would freeze a socket timeout for good
                        monitor.releaseHold()
                        finally(monitor.ended())
                    }
                }
            monitor.conn.quic.closed
                .invokeOnCompletion { job.cancel() }
            return job
        }
    }
}
