// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(
    io.kuicksilver.annotations.InternalKuicksilverApi::class,
    io.kuicksilver.annotations.ExperimentalKuicksilverApi::class,
    kotlinx.coroutines.ExperimentalCoroutinesApi::class,
)

package io.kuicksilver.http3.fuzz

import com.code_intelligence.jazzer.junit.FuzzTest
import io.ktor.utils.io.ByteReadChannel
import io.ktor.utils.io.readAvailable
import io.ktor.utils.io.writeFully
import io.kuicksilver.http3.Http3Connection
import io.kuicksilver.http3.Http3ErrorCode
import io.kuicksilver.http3.Http3Exception
import io.kuicksilver.http3.Http3Headers
import io.kuicksilver.http3.Http3ServerRequest
import io.kuicksilver.http3.Http3Settings
import io.kuicksilver.http3.http3Request
import io.kuicksilver.http3.http3Settings
import io.kuicksilver.http3.runtime.H3Session
import io.kuicksilver.quic.QuicException
import io.kuicksilver.quic.StreamPriority
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineExceptionHandler
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.TestCoroutineScheduler
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.TestInfo

/**
 * Fuzz target `h3Connection`: a client and a server HTTP/3 connection over [MemNet], driven by a program the input
 * encodes ([H3Program]); one virtual-time dispatcher runs both sides, so a run is the same every time. Requests with
 * bodies and trailers, a QPACK dynamic table on either side with blocked streams (the encoder and decoder streams are
 * pieces the program delivers late or out of order), SETTINGS variants, GOAWAY from either side at any point, client
 * cancellations and server resets, priorities, and the server application's answers in any order.
 *
 * Invariants ([H3Run.check]): no exception escapes but the protocol's own; two conforming endpoints never close the
 * connection with an error; every request ends exactly once (a response, a stream error, or RequestNotProcessed, which
 * the server application then never saw: RFC 9114 section 5.2); the QPACK dynamic tables of both sides agree once their
 * encoder streams arrived (RFC 9204 section 3.2); at quiesce no request, stream or held stream credit is left; the server
 * application never holds more requests at once than the client may open streams (RFC 9114 section 10.5, Rapid Reset).
 */
class H3ConnectionFuzzTest {
    @BeforeEach fun nameTheCase(case: TestInfo) = fuzzCase(case)

    @FuzzTest(maxDuration = "60s")
    fun h3Connection(data: ByteArray) {
        try {
            H3Run(data).run()
        } catch (e: H3Finding) {
            // the run's last steps go with the finding, so a reproducer explains itself
            throw AssertionError("${e.message}\n" + (e.trace.take(40) + listOf("...") + e.trace.takeLast(20)).joinToString("\n"), e)
        }
    }
}

/** Reads the program: bytes in order, zeros once the input is used up. */
internal class H3Program(
    private val data: ByteArray,
) {
    var pos = 0
    val exhausted: Boolean get() = pos >= data.size

    fun u8(): Int = if (pos < data.size) data[pos++].toInt() and 0xff else 0

    fun pick(n: Int): Int = if (n <= 1) 0 else u8() % n
}

/** What a fuzz run reached: feature -> count, summed over runs by the seeded test. */
internal class H3Reach {
    val hits = java.util.TreeMap<String, Long>()

    fun hit(
        feature: String,
        n: Long = 1,
    ) {
        if (n > 0) hits[feature] = (hits[feature] ?: 0) + n
    }
}

internal class H3Finding(
    message: String,
    cause: Throwable? = null,
) : AssertionError(message, cause) {
    /** The run's last steps, filled in by [H3Run.run]. */
    var trace: List<String> = emptyList()
}

internal class H3Run(
    data: ByteArray,
    private val reach: H3Reach? = null,
) {
    private val p = H3Program(data)
    private val scheduler = TestCoroutineScheduler()
    private val dispatcher = StandardTestDispatcher(scheduler)
    private val uncaught = ArrayList<Throwable>()
    private val scope = CoroutineScope(SupervisorJob() + dispatcher + CoroutineExceptionHandler { _, e -> uncaught += e })
    private lateinit var net: MemNet
    private var client: Http3Connection? = null
    private var server: Http3Connection? = null
    private var limit = 1L
    private var closedByProgram = false

    private class Req(
        val tag: Int,
        val method: String,
    ) {
        var job: Job? = null
        var response: io.kuicksilver.http3.Http3Response? = null
        var outcome: String? = null
        var failure: Throwable? = null
        var ends = 0
    }

    private val requests = ArrayList<Req>()

    /** What happened, step by step (attached to a finding). */
    val trace = ArrayList<String>()

    private fun log(s: String) {
        trace += "t=${scheduler.currentTime} $s"
    }

    private class App(
        val r: Http3ServerRequest,
        val tag: Int,
    ) {
        var acting = false
        var ended = false
    }

    private val app = ArrayList<App>()
    private val seenByServer = HashMap<Int, Int>()
    private val rejectedByApp = HashSet<Int>()
    private var maxAppActive = 0

    private val names = listOf("x-a", "x-b", "accept", "user-agent", "cookie", "x-trace", "cache-control")
    private val values = listOf("1", "v", "text/html", "kuicksilver", "a=b; c=d", "0123456789abcdef", "no-cache", "")

    private fun headers(): Http3Headers {
        val n = p.pick(5)
        val list = ArrayList<Pair<String, String>>()
        repeat(n) {
            val name = names[p.pick(names.size)]
            val v = if (p.pick(16) == 0) "x".repeat(300 + p.u8() * 4) else values[p.pick(values.size)]
            list += name to v
        }
        return Http3Headers(list)
    }

    private fun settings(b: Int): Http3Settings =
        http3Settings {
            qpack { maxTableCapacity = listOf(0L, 220L, 4096L)[b % 3] }
            qpack { blockedStreams = listOf(0L, 1L, 16L)[(b / 3) % 3] }
            qpack { encoderMaxTableCapacity = listOf(4096L, 64L)[(b / 9) % 2] }
            maxFieldSectionSize = if ((b / 18) % 4 == 0) 600L else 65_536L
            enableConnectProtocol = (b / 72) % 2 == 1
            h3Datagram = false
            expert { grease = (b / 144) % 2 == 1 }
        }

    fun run() {
        val thread = Thread.currentThread()
        val before = thread.uncaughtExceptionHandler
        thread.uncaughtExceptionHandler = Thread.UncaughtExceptionHandler { _, e -> uncaught += e }
        H3Session.dispatcherForTest = dispatcher
        try {
            setUp()
            if (client != null && server != null) {
                var steps = 0
                while (!p.exhausted && steps++ < 300 && !(client!!.closed.isCompleted && server!!.closed.isCompleted)) step()
            }
            quiesce()
            check()
        } catch (e: H3Finding) {
            e.trace = trace.toList()
            throw e
        } finally {
            H3Session.dispatcherForTest = null
            thread.uncaughtExceptionHandler = before
            client?.close()
            server?.close()
            scope.cancel()
            runCatching { scheduler.advanceTimeBy(60_000) }
        }
    }

    private var inserts = 0L

    private fun settle() {
        scheduler.runCurrent()
        val ins = (client?.session?.qpack?.encoderInserts ?: 0) + (server?.session?.qpack?.encoderInserts ?: 0)
        if (ins > inserts) {
            reach?.hit("qpack: dynamic table inserts", ins - inserts)
            inserts = ins
        }
        val active = app.count { !it.ended }
        if (active > maxAppActive) maxAppActive = active
        if (active > limit) throw H3Finding("the server application holds $active requests with $limit streams allowed")
        server?.session?.let { if (it.qpack.blockedStreamsForTest > 0) reach?.hit("qpack: blocked stream seen (server decoder)") }
        client?.session?.let { if (it.qpack.blockedStreamsForTest > 0) reach?.hit("qpack: blocked stream seen (client decoder)") }
    }

    private fun setUp() {
        val cs = settings(p.u8() or (p.u8() shl 8))
        val ss = settings(p.u8() or (p.u8() shl 8))
        limit = 1L + p.pick(6)
        reach?.hit("settings: client dynamic table ${cs.qpackMaxTableCapacity}/${cs.qpackBlockedStreams}")
        reach?.hit("settings: server dynamic table ${ss.qpackMaxTableCapacity}/${ss.qpackBlockedStreams}")
        net = MemNet(scope, limit, 100)
        val started = kotlinx.coroutines.CompletableDeferred<Http3Connection>()
        scope.launch { server = Http3Connection.server(net.server, ss).also { started.complete(it) } }
        scope.launch { client = Http3Connection.client(net.client, cs) }
        // the server application: takes each request as it comes and holds it until the program answers it
        scope.launch {
            val srv = started.await()
            while (true) {
                val r = runCatching { srv.acceptRequest() }.getOrNull() ?: break
                val tag = r.headers["x-id"]?.toIntOrNull() ?: -1
                log("server application got request $tag on stream ${r.streamId}")
                seenByServer[tag] = (seenByServer[tag] ?: 0) + 1
                app += App(r, tag)
            }
        }
        repeat(50) {
            if (client != null && server != null) return
            net.deliverAll()
            scheduler.advanceTimeBy(10)
            settle()
        }
    }

    private fun step() {
        val c = client ?: return
        val s = server ?: return
        // GOAWAY and closes end the connection's useful life: rare, so most programs also complete requests first
        when (p.pick(16).let { if (it in 10..11 || it == 14) (if (p.pick(24) == 0) it else 15) else it }) {
            0, 1, 2 -> {
                startRequest(c)
            }

            3, 4, 5 -> {
                val d = net.deliverable()
                if (d.isNotEmpty()) {
                    val piece = d[p.pick(d.size)]
                    if (piece !== net.inflight.first()) reach?.hit("transport: piece delivered out of order")
                    log("deliver ${piece::class.simpleName} -> ${if (piece.to.conn.isClient) "client" else "server"} stream ${piece.to.id}")
                    net.deliver(piece)
                }
            }

            6 -> {
                log("deliver in order")
                repeat(1 + p.pick(8)) { net.deliverable().firstOrNull()?.let { net.deliver(it) } }
            }

            7, 8 -> {
                answer()
            }

            9 -> {
                val r = requests.filter { it.job?.isActive == true }.let { if (it.isEmpty()) null else it[p.pick(it.size)] }
                if (r != null) {
                    reach?.hit("client: request cancelled")
                    if (p.pick(2) == 0) r.response?.cancel() ?: r.job?.cancel() else r.job?.cancel()
                }
            }

            10 -> {
                reach?.hit("goaway: server")
                log("server goAway()")
                scope.launch { runCatching { s.goAway() } }
            }

            11 -> {
                reach?.hit("goaway: client")
                log("client goAway()")
                scope.launch { runCatching { c.goAway() } }
            }

            12 -> {
                val ms = 1L + p.u8() * 20L
                log("advance ${ms}ms")
                scheduler.advanceTimeBy(ms)
            }

            13 -> {
                val r = requests.filter { it.response != null && it.job?.isActive == true }
                if (r.isNotEmpty()) {
                    reach?.hit("priority: PRIORITY_UPDATE")
                    val target = r[p.pick(r.size)]
                    scope.launch { runCatching { target.response!!.updatePriority(StreamPriority(p.pick(8), p.pick(2) == 1)) } }
                }
            }

            14 -> {
                if (p.pick(8) == 0) {
                    closedByProgram = true
                    reach?.hit("connection: closed by the program")
                    if (p.pick(2) == 0) c.close() else s.close()
                }
            }

            else -> {
                log("deliver all")
                net.deliverAll(max = 1 + p.pick(32))
            }
        }
        settle()
    }

    private fun startRequest(c: Http3Connection) {
        val tag = requests.size
        val method = listOf("GET", "POST", "PUT", "HEAD")[p.pick(4)]
        val r = Req(tag, method)
        requests += r
        val bodySize = if (method == "GET" || method == "HEAD") 0 else p.pick(4) * 700
        val trailers = method != "GET" && p.pick(3) == 0
        val hs = Http3Headers(listOf("x-id" to "$tag") + headers().fields)
        val prio = if (p.pick(4) == 0) StreamPriority(p.pick(8), p.pick(2) == 1) else null
        reach?.hit("client: request $method${if (bodySize > 0) " with body" else ""}${if (trailers) " and trailers" else ""}")
        val req =
            http3Request(method, "server.test", "/r$tag") {
                headers = hs
                if (bodySize > 0 || trailers) body = ByteReadChannel(ByteArray(bodySize) { it.toByte() })
                if (trailers) this.trailers = { Http3Headers.of("x-sum" to "$bodySize") }
                priority = prio
            }
        log("request $tag $method")
        r.job =
            scope.launch {
                try {
                    val resp = c.request(req)
                    log("request $tag: response ${resp.status} on stream ${resp.streamId}")
                    r.response = resp
                    val buf = ByteArray(4096)
                    while (resp.body.readAvailable(buf, 0, buf.size) >= 0) continue
                    resp.body.closedCause?.let { throw it }
                    val t = resp.trailers.await()
                    reach?.hit("client: response ${resp.status}${if (t != null) " with trailers" else ""}")
                    end(r, "response ${resp.status}", null)
                } catch (e: CancellationException) {
                    end(r, "cancelled", e)
                    throw e
                } catch (e: Throwable) {
                    end(r, e::class.simpleName ?: "?", e)
                }
            }
    }

    private fun end(
        r: Req,
        outcome: String,
        e: Throwable?,
    ) {
        r.ends++
        log("request ${r.tag} ended: $outcome ${e?.message ?: ""}")
        r.outcome = outcome
        r.failure = e
    }

    /** The server application acts on one request it holds: answers it (body, trailers), resets it, or reads it first. */
    private fun answer() {
        val open = app.filter { !it.ended && !it.acting }
        if (open.isEmpty()) return
        val a = open[p.pick(open.size)]
        a.acting = true
        val how = p.pick(6)
        val status = listOf(200, 204, 404, 500, 304, 201)[p.pick(6)]
        val size = p.pick(4) * 900
        val withTrailers = p.pick(3) == 0
        val hs = headers()
        val code = listOf(Http3ErrorCode.REQUEST_CANCELLED, Http3ErrorCode.INTERNAL_ERROR, Http3ErrorCode.REQUEST_REJECTED)[p.pick(3)]
        scope.launch {
            try {
                when (how) {
                    0 -> {
                        reach?.hit("server: request reset")
                        log("server application resets request ${a.tag} with ${Http3ErrorCode.name(code)}")
                        // the application says it did not process the request (RFC 9114 section 4.1.1)
                        if (code == Http3ErrorCode.REQUEST_REJECTED) rejectedByApp += a.tag
                        a.r.reset(code)
                    }

                    else -> {
                        if (how >= 4) {
                            val buf = ByteArray(4096)
                            runCatching { while (a.r.body.readAvailable(buf, 0, buf.size) >= 0) continue }
                            reach?.hit("server: body read before the answer")
                        }
                        log("server application answers request ${a.tag}: $status, $size bytes${if (withTrailers) ", trailers" else ""}")
                        val w = a.r.respond(status, hs)
                        if (size > 0) w.output.writeFully(ByteArray(size))
                        w.finish(if (withTrailers) Http3Headers.of("x-t" to "1") else null)
                        reach?.hit("server: response $status${if (withTrailers) " with trailers" else ""}")
                    }
                }
            } catch (e: CancellationException) {
                throw e
            } catch (e: Throwable) {
                expected(e, "server application")
            } finally {
                a.ended = true
            }
        }
    }

    /** Exceptions the API documents; anything else reaching an application is a finding. */
    private fun expected(
        e: Throwable,
        where: String,
    ) {
        val ok =
            e is Http3Exception || e is QuicException || e is CancellationException || e is kotlinx.io.IOException ||
                (
                    e is IllegalStateException && e.message?.let {
                        "request is finished" in it || "response already started" in it
                    } == true
                ) ||
                (e is IllegalArgumentException)
        if (!ok) throw H3Finding("$where: unexpected ${e::class.qualifiedName}: ${e.message}", e)
        val code = (e as? Http3Exception.Protocol)?.let { " ${Http3ErrorCode.name(it.h3Code)}" } ?: ""
        reach?.hit("$where: ${e::class.simpleName}$code")
    }

    private fun quiesce() {
        repeat(400) {
            if (!::net.isInitialized) return
            net.deliverAll()
            for (a in app) {
                if (!a.ended && !a.acting) {
                    a.acting = true
                    scope.launch {
                        try {
                            a.r.respond(200).finish()
                        } catch (e: CancellationException) {
                            throw e
                        } catch (e: Throwable) {
                            expected(e, "server application")
                        } finally {
                            a.ended = true
                        }
                    }
                }
            }
            scheduler.advanceTimeBy(100)
            settle()
            if (net.inflight.isEmpty() && requests.all { it.job?.isCompleted != false } && app.all { it.ended }) return
        }
    }

    fun check() {
        uncaught.firstOrNull()?.let { throw H3Finding("uncaught ${it::class.qualifiedName}: ${it.message}", it) }
        if (!::net.isInitialized) return
        if (net.server.peerStreamsBeyondLimit + net.client.peerStreamsBeyondLimit >
            0
        ) {
            throw H3Finding("a stream opened beyond the limit granted")
        }
        val c = client
        val s = server
        if (c == null || s == null) {
            if (!closedByProgram) throw H3Finding("the connection did not start")
            return
        }
        for (r in requests) {
            if (r.job?.isCompleted != true) throw H3Finding("request ${r.tag} never ended (${r.method})")
            if (r.ends != 1) throw H3Finding("request ${r.tag} ended ${r.ends} times")
            r.failure?.let { e ->
                if (e !is CancellationException) expected(e, "client request")
                if (e is Http3Exception.RequestNotProcessed && (seenByServer[r.tag] ?: 0) > 0 && r.tag !in rejectedByApp) {
                    throw H3Finding("request ${r.tag} failed with RequestNotProcessed, but the server application saw it")
                }
                if (e is Http3Exception.RequestNotProcessed) reach?.hit("client: RequestNotProcessed")
                // RFC 9114 section 5.2: a graceful close comes "once all accepted requests ... have been processed", and the
                // server waits until each request stream finished (a whole response, or its RESET_STREAM, acknowledged)
                if (e is Http3Exception.Protocol && e.h3Code == Http3ErrorCode.NO_ERROR && !closedByProgram &&
                    (seenByServer[r.tag] ?: 0) > 0
                ) {
                    throw H3Finding("request ${r.tag}, which the server application saw, failed with the graceful close: $e")
                }
            }
        }
        for ((tag, n) in seenByServer) if (n > 1) throw H3Finding("the server application saw request $tag $n times")
        for (conn in listOf(c, s)) {
            if (conn.closed.isCompleted && !closedByProgram) {
                val e = conn.closed.getCompleted()
                val code = (e as? Http3Exception.Protocol)?.h3Code ?: (e as? QuicException.ConnectionLost.ApplicationClosed)?.code
                if (code != Http3ErrorCode.NO_ERROR) throw H3Finding("${conn.role} connection closed with $e", e)
                reach?.hit("connection: closed with H3_NO_ERROR after GOAWAY")
            }
        }
        val open = !c.closed.isCompleted && !s.closed.isCompleted
        if (open) {
            // RFC 9204 section 3.2: both ends of each encoder stream hold the same table once its instructions arrived
            val pairs =
                listOf(
                    c.session.qpack.encoderTableForTest() to s.session.qpack.decoderTableForTest(),
                    s.session.qpack.encoderTableForTest() to c.session.qpack.decoderTableForTest(),
                )
            for ((enc, dec) in pairs) {
                if (enc != dec) throw H3Finding("QPACK tables differ: encoder $enc, decoder $dec")
                if (enc.first > 0) reach?.hit("qpack: tables compared at quiesce, with inserts")
            }
            val ss = s.session
            if (ss.activeServerRequests.isNotEmpty() || ss.pendingHeaders.isNotEmpty() || ss.handledBidi.isNotEmpty()) {
                throw H3Finding("server requests left: ${ss.activeServerRequests.keys} ${ss.pendingHeaders.keys} ${ss.handledBidi}")
            }
            if (c.session.clientStreams.isNotEmpty()) throw H3Finding("client requests left: ${c.session.clientStreams.keys}")
            val leftBidi = (net.client.liveStreams + net.server.liveStreams).filter { it.bidi }
            if (leftBidi.isNotEmpty()) throw H3Finding("request streams not finished: ${leftBidi.map { it.id }}")
            if (net.server.held.isNotEmpty()) throw H3Finding("stream credit still held: ${net.server.held}")
        }
        reach?.hit("server: requests the application held at once (max)", maxAppActive.toLong())
        reach?.hit("qpack: stream cancellations sent", c.session.qpack.streamCancellationsMade + s.session.qpack.streamCancellationsMade)
        for ((k, v) in net.delivered) reach?.hit("transport: $k delivered", v.toLong())
    }
}
