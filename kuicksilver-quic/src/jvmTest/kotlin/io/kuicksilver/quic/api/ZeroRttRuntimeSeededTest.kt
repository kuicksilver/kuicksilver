// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.api

import io.ktor.utils.io.readAvailable
import io.ktor.utils.io.writeFully
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.annotations.InternalKuicksilverApi
import io.kuicksilver.native.KslLoader
import io.kuicksilver.quic.ConnectionAdmission
import io.kuicksilver.quic.CoreFixtures
import io.kuicksilver.quic.QuicClientConfig
import io.kuicksilver.quic.QuicConnection
import io.kuicksilver.quic.QuicEndpoint
import io.kuicksilver.quic.QuicException
import io.kuicksilver.quic.QuicStream
import io.kuicksilver.quic.VersionProfile
import io.kuicksilver.quic.awaitSendStopped
import io.kuicksilver.quic.quicConfig
import io.kuicksilver.quic.runtime.ConnectionRuntime
import io.kuicksilver.quic.runtime.EndpointLoop
import io.kuicksilver.quic.runtime.StreamRuntime
import io.kuicksilver.tls.EarlyDataState
import io.kuicksilver.tls.KslQuicCrypto
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.async
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeout
import kotlinx.coroutines.withTimeoutOrNull
import kotlinx.coroutines.yield
import kotlin.random.Random
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds

/**
 * The 0-RTT invariant through the public runtime API, on a fixed set of seeds: a client resumes over 0-RTT and, before the
 * server's answer, opens streams, writes, finishes, resets, resets at a size, stops, reads and watches for STOP_SENDING
 * (each call that suspends runs as a job of its own); the server accepts, rejects (another configuration; Required mode,
 * which closes), never answers, answers after a Retry, or after a Version Negotiation, or accepts while nothing the client
 * sends after that acceptance arrives until the answer is checked (so no reset of the 0-RTT is acknowledged; the client
 * also resets a stream of its own then); or the application closes first. Odd seeds remember small limits, so calls in
 * 0-RTT also wait for stream and flow-control credit.
 *
 * Once the answer is known: no wrapper stays for a stream retired with its reset unacknowledged; after a rejection every
 * stream the application opened before it is failed with [QuicException.StreamError.EarlyDataRejected] on both halves and
 * done, it has left the connection's stream map, and every job on it (reads, writes, finishes, STOP_SENDING watchers) has
 * ended; the map holds no stream a rejection dropped. Once
 * the connection ended: its handshake and `closed` are complete, every stream the application saw is done, and no job of
 * the application waits on anything of the connection any more; each stream's Deferreds (every getter of [QuicStream] typed
 * Deferred) are awaited by such jobs. `KUICKSILVER_ZRTT_SEEDS` sets the seeds per outcome.
 */
@OptIn(ExperimentalKuicksilverApi::class, InternalKuicksilverApi::class)
class ZeroRttRuntimeSeededTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    // AcceptUnacked last: the seeds of the others (100 × ordinal) stay as they were
    private enum class Outcome { Accept, Reject, Required, Lost, CloseEarly, Retry, VersionNegotiation, AcceptUnacked }

    private val seeds = System.getenv("KUICKSILVER_ZRTT_SEEDS")?.toIntOrNull() ?: 2

    @Test fun nothingStaysPendingAfterTheAnswerOrTheEnd(): Unit =
        runBlocking {
            val only = System.getenv("KUICKSILVER_ZRTT_ONLY")?.split(",") // "<outcome>,<seed>": one scenario
            for (o in Outcome.entries) {
                if (only != null && only[0] != o.name) continue
                for (s in 0 until seeds) {
                    val seed = 100L * o.ordinal + s
                    if (only != null && only[1].toLong() != seed) continue
                    try {
                        scenario(o, seed)
                    } catch (e: Throwable) {
                        throw AssertionError("outcome $o, seed $seed: ${e.message}", e)
                    }
                }
            }
        }

    /** What the client application did, and the jobs it left running. */
    private class App(
        val conn: ConnectionRuntime,
        val rnd: Random,
        val scope: CoroutineScope,
    ) {
        val streams = ArrayList<StreamRuntime>()
        val jobs = ArrayList<Pair<String, Job>>()

        fun job(
            name: String,
            block: suspend () -> Unit,
        ) {
            jobs += name to
                scope.launch {
                    try {
                        block()
                    } catch (_: QuicException) {
                    } catch (_: IllegalStateException) {
                    } catch (_: kotlinx.io.IOException) {
                    }
                }
        }

        suspend fun open(bidi: Boolean): StreamRuntime? {
            // an open waits while the remembered stream limit is reached: then it is a job of its own. Which way an open goes
            // depends on the scheduler only when it is slower than 300 ms; both ways are held to the same checks (a stream the
            // open returned is checked as a stream, a pending open as a job that must end), so the verdict does not depend on it
            val d = scope.async { if (bidi) conn.openBidi() else conn.openUni() }
            val s = withTimeoutOrNull(300.milliseconds) { d.await() }
            if (s == null) {
                jobs += "open" to d
                return null
            }
            return (s as StreamRuntime).also {
                streams += it
                awaitDeferreds(it)
            }
        }

        /**
         * Every Deferred the application can get from the stream ([QuicStream]'s getters typed Deferred, found by reflection, so
         * one added later is covered without a change here) is awaited by a job: each must settle once the stream is gone.
         */
        fun awaitDeferreds(s: StreamRuntime) = awaitDeferreds(QuicStream::class.java, s, " ${s.id}")

        fun awaitDeferreds(
            type: Class<*>,
            target: Any,
            suffix: String,
        ) {
            for (m in type.methods) {
                if (m.parameterCount != 0 || !kotlinx.coroutines.Deferred::class.java.isAssignableFrom(m.returnType)) continue
                val d = runCatching { m.invoke(target) as kotlinx.coroutines.Deferred<*>? }.getOrNull() ?: continue
                job("${m.name}$suffix") { d.await() }
            }
        }

        fun pick(): StreamRuntime? = if (streams.isEmpty()) null else streams[rnd.nextInt(streams.size)]

        suspend fun op() {
            when (rnd.nextInt(11)) {
                0, 1 -> {
                    open(bidi = true)?.let { s -> write(s, rnd.nextInt(1, 6000)) }
                }

                2 -> {
                    open(bidi = false)?.let { s -> write(s, rnd.nextInt(0, 3000)) }
                }

                3 -> {
                    pick()?.let { write(it, rnd.nextInt(1, 20_000)) }
                }

                4 -> {
                    pick()?.let { s -> job("finish ${s.id}") { s.output.flushAndClose() } }
                }

                5 -> {
                    pick()?.reset(rnd.nextLong(0, 100))
                }

                6 -> {
                    pick()?.resetAt(rnd.nextLong(0, 100), rnd.nextLong(0, 4000))
                }

                7 -> {
                    pick()?.let { if (it.id and 2L == 0L) it.stopSending(rnd.nextLong(0, 100)) }
                }

                8 -> {
                    pick()?.let { s ->
                        if (s.id and 2L == 0L) {
                            job("read ${s.id}") {
                                val b = ByteArray(4096)
                                while (s.input.readAvailable(b, 0, b.size) >= 0) { /* until the end */ }
                            }
                        }
                    }
                }

                9 -> {
                    pick()?.let { s -> job("watch STOP_SENDING ${s.id}") { s.awaitSendStopped() } }
                }

                else -> {
                    open(bidi = true)
                }
            }
        }

        fun write(
            s: StreamRuntime,
            n: Int,
        ) = job("write ${s.id}") {
            s.output.writeFully(ByteArray(n) { it.toByte() })
            s.output.flush()
        }
    }

    private fun clientConfig(
        mode: EarlyDataState,
        vn: Boolean,
        lost: Boolean,
    ) = QuicClientConfig
        .Builder(CoreFixtures.client())
        .apply {
            earlyData = mode
            quic =
                quicConfig {
                    resetStreamAt = true
                    if (vn) versions = listOf(VersionProfile.V1, VersionProfile.V2)
                    if (lost) handshakeTimeout = 1.seconds
                }
        }.build()

    /**
     * Echoes every stream of every connection [server] accepts (closing its half once the peer's ended); [accepted] gets an
     * element for each connection handed out (a server with early data hands one out at its acceptance of the 0-RTT).
     */
    private fun CoroutineScope.echo(
        server: QuicEndpoint,
        accepted: kotlinx.coroutines.channels.Channel<Unit>? = null,
    ) = launch {
        while (true) {
            val c =
                try {
                    server.accept()
                } catch (_: Exception) {
                    return@launch
                }
            accepted?.trySend(Unit)
            launch {
                while (true) {
                    val s =
                        try {
                            c.acceptStream()
                        } catch (_: Exception) {
                            return@launch
                        }
                    launch {
                        try {
                            val b = ByteArray(4096)
                            while (true) {
                                val n = s.input.readAvailable(b, 0, b.size)
                                if (n < 0) break
                                if (s.id and 2L == 0L) s.output.writeFully(b, 0, n)
                            }
                            if (s.id and 2L == 0L) s.output.flushAndClose()
                        } catch (_: Exception) {
                        }
                    }
                }
            }
        }
    }

    private suspend fun scenario(
        o: Outcome,
        seed: Long,
    ) {
        val rnd = Random(seed)
        val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
        // odd seeds: small limits, so that 0-RTT opens wait for a stream credit and writes for flow-control credit
        val small = seed % 2 == 1L
        val p =
            ApiPair.open(
                serverQuic =
                    quicConfig {
                        if (small) {
                            maxBidiStreams = 2
                            maxUniStreams = 1
                            initialStreamWindow = 3000
                            initialConnectionWindow = 5000
                        }
                    },
                crypto = KslQuicCrypto,
                serverEarlyData = true,
                serverConfigure = { if (o == Outcome.Retry) admission = ConnectionAdmission.AlwaysRetry },
            )
        var restarted: QuicEndpoint? = null
        try {
            withTimeout(30.seconds) {
                val serverAccepted = kotlinx.coroutines.channels.Channel<Unit>(kotlinx.coroutines.channels.Channel.UNLIMITED)
                scope.echo(p.server, serverAccepted)
                val loop = p.client as EndpointLoop
                // a ticket from a first connection
                val first = p.client.connect(p.server.localAddress, clientConfig(EarlyDataState.Allowed, vn = false, lost = false))
                val s0 = first.openBidi()
                s0.output.writeFully("hello".encodeToByteArray())
                s0.output.flushAndClose()
                s0.input.readExactly(5)
                while (loop.sessions.size() == 0) yield()
                first.close()
                val server =
                    when (o) {
                        // a server restarted with another configuration (and other ticket keys) refuses the early data
                        Outcome.Reject, Outcome.Required -> p.restartServer(quicConfig { initialConnectionWindow = 700_000 }, KslQuicCrypto)

                        // one that speaks only v2 answers the v1 first flight with a Version Negotiation
                        Outcome.VersionNegotiation -> p.restartServer(quicConfig { versions = listOf(VersionProfile.V2) }, KslQuicCrypto)

                        else -> p.server
                    }
                if (server !== p.server) {
                    restarted = server
                    scope.echo(server)
                }
                while (serverAccepted.tryReceive().isSuccess) { /* the first connection's */ }
                // the server's answers wait until the application made its calls: they all happen in 0-RTT
                p.net.hold(p.clientIo.localAddress)
                val mode = if (o == Outcome.Required) EarlyDataState.Required else EarlyDataState.Allowed
                val conn =
                    p.client.connectEarly(
                        server.localAddress,
                        clientConfig(mode, vn = o == Outcome.VersionNegotiation, lost = o == Outcome.Lost),
                    ) as ConnectionRuntime
                val app = App(conn, rnd, scope)
                if (o == Outcome.AcceptUnacked) {
                    // the server accepted our 0-RTT (its answer waits): from now on nothing of ours arrives until the answer is
                    // checked, so a stream reset now retires with its size held and its reset is never acknowledged
                    serverAccepted.receive()
                    p.net.lose = { from, _, _ -> from == p.clientIo.localAddress }
                    app.open(bidi = false)?.let { s ->
                        s.reset(7)
                        withContext(conn.loopDispatcherForTest) {
                            check(conn.core.streams.heldForAnswer(s.id)) { "stream ${s.id} reset in 0-RTT is not held for the answer" }
                        }
                    }
                }
                // the connection's Deferreds too (`closed`): the reflection must find at least that one
                app.awaitDeferreds(QuicConnection::class.java, conn, "")
                check(app.jobs.any { it.first == "getClosed" }) { "no Deferred of QuicConnection found by reflection" }
                repeat(1 + rnd.nextInt(8)) { app.op() }
                check(!conn.isHandshakeComplete) { "the calls were not made in 0-RTT" }
                if (o == Outcome.CloseEarly) conn.close(3, "early")
                if (o != Outcome.Lost) p.net.release(p.clientIo.localAddress)
                val answered =
                    try {
                        conn.awaitHandshake()
                        true
                    } catch (_: QuicException.ConnectionLost) {
                        false
                    }
                if (answered) afterAnswer(app)
                p.net.lose = null // the connection goes on below
                if (!conn.closed.isCompleted) {
                    // the connection goes on: a request on a new stream gets its answer (unless the early streams, which the
                    // application never ends, hold every stream credit of a small limit)
                    val s = withTimeoutOrNull(2.seconds) { conn.openBidi() }
                    if (s != null) {
                        app.streams += s as StreamRuntime
                        app.awaitDeferreds(s)
                        s.output.writeFully("again".encodeToByteArray())
                        s.output.flushAndClose()
                        check(s.input.readExactly(5).decodeToString() == "again")
                    }
                    conn.close()
                }
                conn.closed.await()
                atEnd(app)
            }
        } finally {
            scope.cancel()
            restarted?.close()
            p.close()
        }
    }

    /**
     * The answer is known: no wrapper stays for a stream that retired with its reset unacknowledged (one retired before an
     * acceptance goes at it); a rejection failed and removed every stream opened before it, and nothing waits on them.
     */
    private suspend fun afterAnswer(app: App) {
        val conn = app.conn
        withContext(conn.loopDispatcherForTest) {
            for (id in conn.streams.keys) {
                check(!conn.core.streams.retiredAndOfferedForTest(id)) { "stream $id retired before the answer keeps its wrapper after it" }
            }
        }
        if (conn.earlyDataAccepted != false) return
        val early = app.streams.toList()
        withContext(conn.loopDispatcherForTest) {
            for (s in early) {
                check(s.done.isCompleted) { "stream ${s.id}, opened before the rejection, is not done" }
                check(conn.streams[s.id] !== s) { "stream ${s.id}, opened before the rejection, is still in the connection's map" }
                val causes = causes(s)
                for (cause in causes) {
                    // the first cause stays: a half the application itself reset or stopped before keeps that reason
                    check(cause is QuicException.StreamError.EarlyDataRejected || own(cause)) {
                        "stream ${s.id}, dropped by the rejection, failed with $cause instead of EarlyDataRejected"
                    }
                }
                // a stream the application reset (and stopped) before the answer was over already, nothing left to drop
                check(s.dropped || causes.all { own(it) }) { "stream ${s.id}, opened before the rejection, was not failed" }
            }
            for ((id, s) in conn.streams) check(s.current) { "stream $id in the map names a stream the rejection dropped" }
        }
        val ids = early.map { it.id }.toSet()
        // every job on a dropped stream has ended
        awaitJobs(app.jobs.filter { (name, _) -> name.substringAfterLast(' ').toLongOrNull() in ids }, "after the rejection")
    }

    /** The connection ended: nothing of it is pending, and no job of the application waits on it. */
    private suspend fun atEnd(app: App) {
        val conn = app.conn
        // on the loop, where the end is applied in one task (`closed` completes first, the streams within the same task)
        withContext(conn.loopDispatcherForTest) {
            check(conn.handshake.isCompleted) { "the handshake Deferred is still pending after the connection ended" }
            for (s in app.streams) check(s.done.isCompleted) { "stream ${s.id} is not done after the connection ended" }
        }
        awaitJobs(app.jobs, "after the connection ended")
    }

    private suspend fun awaitJobs(
        jobs: List<Pair<String, Job>>,
        whenWhat: String,
    ) {
        withTimeoutOrNull(5.seconds) { for ((_, j) in jobs) j.join() }
        val pending = jobs.filter { !it.second.isCompleted }.map { it.first }
        check(pending.isEmpty()) { "application calls still waiting $whenWhat: $pending" }
    }

    /** The application's own reset or stop of that half. */
    private fun own(cause: Throwable?): Boolean =
        (cause is QuicException.StreamError.Reset && cause.initiator == io.kuicksilver.quic.Initiator.Local) ||
            (cause is QuicException.StreamError.Stopped && cause.initiator == io.kuicksilver.quic.Initiator.Local)

    private fun causes(s: QuicStream): List<Throwable?> {
        val out = ArrayList<Throwable?>()
        runCatching { s.input }.getOrNull()?.let { out += it.closedCause }
        runCatching { s.output }.getOrNull()?.let { out += it.closedCause }
        return out
    }
}
