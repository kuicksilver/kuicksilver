// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)

package io.kuicksilver.ktor.server.browser

import io.ktor.server.routing.Route
import io.ktor.utils.io.ByteReadChannel
import io.ktor.utils.io.readAvailable
import io.ktor.utils.io.readByte
import io.ktor.utils.io.writeFully
import io.kuicksilver.http3.WebTransportCloseInfo
import io.kuicksilver.http3.WebTransportException
import io.kuicksilver.http3.WebTransportReceiveStream
import io.kuicksilver.http3.WebTransportSendStream
import io.kuicksilver.http3.WebTransportSession
import io.kuicksilver.ktor.server.webTransport
import io.kuicksilver.quic.QlogSink
import io.kuicksilver.quic.QlogTrace
import io.kuicksilver.tls.TlsRole
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.cancelChildren
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.delay
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withTimeout
import kotlinx.coroutines.withTimeoutOrNull
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.ConcurrentLinkedQueue
import java.util.concurrent.atomic.AtomicLong
import kotlin.time.Duration.Companion.seconds

/**
 * The stream error code probe of the browser page `wt/index.html` (its "codes" stage): which WebTransport stream error
 * codes a browser on draft-ietf-webtrans-http3-02 puts on the wire, and whether it reads ours.
 *
 * Draft-02 section 4.3 limits a stream's application error code to 8 bits (0..255); the session's close code is 32-bit
 * (section 5). The library's policy is strict (WtVersion.maxStreamErrorCode, WtErrorCodes.fromHttp3): on a draft-02
 * session [WebTransportException.StreamReset.code] and [WebTransportException.StreamStopped.code] are null for an HTTP/3
 * code that maps above 255, and [WebTransportSendStream.reset] / [WebTransportReceiveStream.stopSending] throw
 * IllegalArgumentException for a code above 255. The probe does not change that: it shows it, next to the raw code.
 *
 * The raw HTTP/3 code of each RESET_STREAM, RESET_STREAM_AT and STOP_SENDING comes from the server's qlog (this probe is a
 * [QlogSink] that passes every record on to [delegate]); it is mapped back to a WebTransport code with the draft's formula
 * (re-implemented here, unbounded, so a browser's code above 255 shows as such), and every frame and every outcome the
 * session API reports goes to [log] (the timeline, server-events.txt of the manual run).
 *
 * The page's protocol, on the session `/wt/codes`: a first bidirectional stream whose first line is `control` carries the
 * server's lines to the page (`got <case>`, `done <case> <what the server saw or did>`) and the page's requests
 * (`cancel-uni <v>`, `srv-reset-uni <v>`: the server opens the unidirectional stream; `have <case>`: the page read the
 * header of a stream the server opened). Every other stream starts with its case, `<kind> <value>`.
 */
internal class WtCodesProbe(
    private val delegate: QlogSink? = null,
    private val log: (String) -> Unit,
) : QlogSink {
    /** One stream frame with an error code, as qlog recorded it. */
    data class Frame(
        val seq: Long,
        val received: Boolean,
        val type: String,
        val streamId: Long,
        val raw: Long,
        val connection: String,
    ) {
        /** The WebTransport code [raw] carries, unbounded (draft-02 would allow only 0..255), or null outside the range. */
        val wt: Long? get() = wtCode(raw)

        override fun toString(): String {
            val dir = if (received) "rx" else "tx"
            val mapped =
                wt?.let { "WT $it${if (it > DRAFT02_MAX) " (ABOVE 255: draft-02 strict policy refuses it)" else ""}" }
                    ?: "no WT code (${h3Name(raw)})"
            return "$dir ${type.uppercase()} raw=0x${raw.toString(16)} -> $mapped"
        }
    }

    /** What the server knows about one case of the page. */
    class Case(
        val label: String,
        val streamId: Long,
        val seq: Long,
    ) {
        @Volatile var server: String = "nothing yet"
    }

    private val seq = AtomicLong()
    private val frames = ConcurrentLinkedQueue<Frame>()
    private val cases = ConcurrentHashMap<String, Case>()

    /** The page's closes of `/wt/close-probe` as the server saw them, in order. */
    val pageCloses = ConcurrentLinkedQueue<WebTransportCloseInfo>()

    override val logHeaderValues: Boolean get() = delegate?.logHeaderValues ?: false

    override fun open(
        odcidHex: String,
        role: TlsRole,
    ): QlogTrace {
        val inner = runCatching { delegate?.open(odcidHex, role) }.getOrNull()
        val connection = odcidHex.take(8)
        return object : QlogTrace {
            override fun write(record: String) {
                runCatching { scan(connection, record) }
                inner?.write(record)
            }

            override fun close() {
                inner?.close()
            }
        }
    }

    private fun scan(
        connection: String,
        record: String,
    ) {
        if ("reset_stream" !in record && "stop_sending" !in record) return
        val received =
            when {
                "packet_received" in record -> true
                "packet_sent" in record -> false
                else -> return
            }
        for (m in FRAME.findAll(record)) {
            val raw = m.groupValues[3].takeIf { it.isNotEmpty() }?.toLong() ?: m.groupValues[4].toLong(16)
            val f = Frame(seq.incrementAndGet(), received, m.groupValues[1], m.groupValues[2].toLong(), raw, connection)
            frames += f
            // the latest case on that stream id; a stream id of another connection is told apart by the connection
            val case = cases.values.filter { it.streamId == f.streamId && it.seq < f.seq }.maxByOrNull { it.seq }
            log("codes: quic $connection stream ${f.streamId} $f; case ${case?.label ?: "?"}")
        }
    }

    /** The frames of [case]'s stream since it started. */
    fun framesOf(case: Case): List<Frame> = frames.filter { it.streamId == case.streamId && it.seq > case.seq }

    fun case(label: String): Case? = cases[label]

    /** The frames received from the browser whose WebTransport code is above 255, with their case. */
    fun above255(): List<Pair<String, Frame>> =
        cases.values.flatMap { c -> framesOf(c).filter { it.received && (it.wt ?: 0) > DRAFT02_MAX }.map { c.label to it } }

    private fun register(
        label: String,
        streamId: Long,
    ): Case {
        val c = Case(label, streamId, seq.incrementAndGet())
        cases[label] = c
        log("codes: case \"$label\" on stream $streamId")
        return c
    }

    /** The routes of the probe: `/wt/codes`, `/wt/close-probe` (the page closes, 32-bit) and `/wt/server-close-32`. */
    fun routes(route: Route) {
        route.webTransport("/wt/codes") { session -> codes(session) }
        route.webTransport("/wt/close-probe") { session ->
            log("/wt/close-probe: session ${session.sessionId} accepted")
            val info = session.closed.await()
            log("/wt/close-probe: session ${session.sessionId} ended: code=${info.code} reason=\"${info.reason}\" cause=${info.cause}")
            pageCloses += info
        }
        route.webTransport("/wt/server-close-32") { session ->
            log("/wt/server-close-32: session ${session.sessionId} accepted; closing with $SERVER_CLOSE_CODE \"$SERVER_CLOSE_REASON\"")
            session.close(SERVER_CLOSE_CODE, SERVER_CLOSE_REASON)
        }
    }

    private suspend fun codes(session: WebTransportSession) {
        log("/wt/codes: session ${session.sessionId} accepted, maxStreamErrorCode=${session.maxStreamErrorCode}")
        val control = CompletableDeferred<WebTransportSendStream>()
        val lock = Mutex()
        val have = ConcurrentHashMap<String, CompletableDeferred<Unit>>()

        suspend fun say(line: String) {
            val out = control.await().output
            lock.withLock {
                out.writeFully("$line\n".encodeToByteArray())
                out.flush()
            }
        }

        suspend fun done(
            c: Case,
            what: String,
        ) {
            c.server = what
            log("codes: case \"${c.label}\" stream ${c.streamId}: server $what")
            runCatching { say("done ${c.label} $what") }
        }
        coroutineScope {
            // the page's requests on the control stream: the server opens a unidirectional stream
            suspend fun request(line: String) {
                val (kind, v) = line.split(' ', limit = 2).let { it[0] to it.getOrElse(1) { "" } }
                when (kind) {
                    "have" -> {
                        have.getOrPut(v) { CompletableDeferred() }.complete(Unit)
                    }

                    "cancel-uni", "srv-reset-uni" -> {
                        launch {
                            val uni = session.openUni()
                            val c = register(line, uni.streamId)
                            uni.output.writeFully("$line\n".encodeToByteArray())
                            uni.output.flush()
                            if (kind == "cancel-uni") {
                                done(c, writeUntilStopped(uni))
                            } else {
                                withTimeoutOrNull(10.seconds) { have.getOrPut(line) { CompletableDeferred() }.await() }
                                done(c, resetOrRefuse(uni, v.toLong()))
                            }
                        }
                    }

                    else -> {
                        log("/wt/codes: unknown control line \"$line\"")
                    }
                }
            }

            launch {
                runCatching {
                    while (true) {
                        val st = session.acceptBidi()
                        launch {
                            runCatching {
                                val line = readLine(st.input)
                                if (line == "control") {
                                    control.complete(st)
                                    while (true) request(readLine(st.input))
                                }
                                val (kind, v) = line.split(' ', limit = 2).let { it[0] to it.getOrElse(1) { "" }.toLong() }
                                val c = register(line, st.streamId)
                                when (kind) {
                                    "abort-bidi" -> {
                                        say("got $line")
                                        done(c, drain(st))
                                    }

                                    "cancel-bidi" -> {
                                        say("got $line")
                                        done(c, writeUntilStopped(st))
                                    }

                                    "srv-reset-bidi" -> {
                                        done(c, resetOrRefuse(st, v))
                                    }

                                    "srv-stop-bidi" -> {
                                        done(c, stopOrRefuse(st, v))
                                    }

                                    else -> {
                                        log("/wt/codes: unknown case \"$line\"")
                                    }
                                }
                            }.onFailure { log("/wt/codes: bidi ${st.streamId}: ${chain(it)}") }
                        }
                    }
                }
            }
            launch {
                runCatching {
                    while (true) {
                        val st = session.acceptUni()
                        launch {
                            runCatching {
                                val line = readLine(st.input)
                                val (kind, v) = line.split(' ', limit = 2).let { it[0] to it.getOrElse(1) { "" }.toLong() }
                                val c = register(line, st.streamId)
                                when (kind) {
                                    "abort-uni" -> {
                                        say("got $line")
                                        done(c, drain(st))
                                    }

                                    "srv-stop-uni" -> {
                                        done(c, stopOrRefuse(st, v))
                                    }

                                    else -> {
                                        log("/wt/codes: unknown case \"$line\"")
                                    }
                                }
                            }.onFailure { log("/wt/codes: uni ${st.streamId}: ${chain(it)}") }
                        }
                    }
                }
            }
            val info = session.closed.await()
            log("/wt/codes: session ${session.sessionId} ended: code=${info.code} reason=\"${info.reason}\"")
            coroutineContext.cancelChildren()
        }
    }

    /** Reads the stream to its end: the peer's FIN, reset or the session's end. */
    private suspend fun drain(st: WebTransportReceiveStream): String {
        val buf = ByteArray(4096)
        return try {
            withTimeout(10.seconds) {
                @Suppress("ControlFlowWithEmptyBody")
                while (st.input.readAvailable(buf) >= 0) {
                }
            }
            "FIN (no reset)"
        } catch (e: Throwable) {
            outcome(e)
        }
    }

    /** Writes until the peer's STOP_SENDING (or anything else) fails the output. */
    private suspend fun writeUntilStopped(st: WebTransportSendStream): String {
        val chunk = ByteArray(1024) { 'x'.code.toByte() }
        return try {
            withTimeout(10.seconds) {
                while (true) {
                    st.output.writeFully(chunk)
                    st.output.flush()
                    delay(20)
                }
                @Suppress("UNREACHABLE_CODE")
                "unreachable"
            }
        } catch (e: Throwable) {
            outcome(e)
        }
    }

    private suspend fun resetOrRefuse(
        st: WebTransportSendStream,
        v: Long,
    ): String =
        try {
            st.reset(v)
            "reset($v) sent"
        } catch (e: IllegalArgumentException) {
            runCatching { st.output.flushAndClose() }
            "reset($v) refused locally (${e::class.simpleName}: ${e.message}); FIN sent instead"
        }

    private suspend fun stopOrRefuse(
        st: WebTransportReceiveStream,
        v: Long,
    ): String =
        try {
            st.stopSending(v)
            "stopSending($v) sent"
        } catch (e: IllegalArgumentException) {
            "stopSending($v) refused locally (${e::class.simpleName}: ${e.message}); then ${drain(st)}"
        }

    private suspend fun outcome(e: Throwable): String {
        if (e is CancellationException && e !is kotlinx.coroutines.TimeoutCancellationException) currentCoroutineContext().ensureActive()
        val causes = generateSequence(e) { it.cause }.take(8).toList()
        causes.filterIsInstance<WebTransportException.StreamReset>().firstOrNull()?.let {
            return "RESET_STREAM, API code ${it.code ?: "null (refused: outside the session's range)"}"
        }
        causes.filterIsInstance<WebTransportException.StreamStopped>().firstOrNull()?.let {
            return "STOP_SENDING, API code ${it.code ?: "null (refused: outside the session's range)"}"
        }
        if (e is kotlinx.coroutines.TimeoutCancellationException) return "nothing within 10 s"
        return "failed: ${chain(e)}"
    }

    /**
     * The table of every case: what the page did locally, what reached the server (raw HTTP/3 code, mapped WebTransport
     * code, the code the session API reported) or what the server sent and what the page saw. [pageLines] is the page's
     * POST to `/codes`: `<case>\t<local>\t<seen>` per line.
     */
    fun table(
        browser: String,
        pageLines: String,
    ): String {
        val sb = StringBuilder()
        sb.append("WebTransport stream error codes, $browser (draft-02: stream codes 0..255, section 4.3)\n")
        sb.append("case | page: local outcome | page: what it saw | server: what it saw or did | wire (server qlog)\n")
        for (line in pageLines.lines().filter { it.isNotBlank() }) {
            val cols = line.split('\t')
            val label = cols[0]
            val c = cases[label]
            val wire = c?.let { framesOf(it).joinToString("; ") } ?: "-"
            val server =
                when {
                    c != null -> c.server
                    label.startsWith("page-close ") -> serverSawClose(label.removePrefix("page-close "))
                    label == "server-close-32" -> "close($SERVER_CLOSE_CODE, \"$SERVER_CLOSE_REASON\")"
                    else -> "no stream seen"
                }
            sb.append("$label | ${cols.getOrElse(1) { "" }} | ${cols.getOrElse(2) { "" }} | $server | $wire\n")
        }
        val above = above255()
        sb.append(
            if (above.isEmpty()) {
                "No stream code above 255 received from the browser.\n"
            } else {
                "!!! THE BROWSER SENT DRAFT-02 STREAM CODES ABOVE 255: ${above.joinToString { (l, f) -> "$l: $f" }}\n"
            },
        )
        return sb.toString()
    }

    /**
     * What the server saw of the page's close whose reason was [reason]: the session whose close carries it, or, for a
     * close whose reason did not arrive, none.
     */
    fun serverSawClose(reason: String): String =
        pageCloses.firstOrNull { it.reason == reason }?.let { "session closed with code ${it.code} reason \"${it.reason}\"" }
            ?: "no close with that reason; all page closes seen: ${pageCloses.joinToString {
                "${it.code} \"${it.reason}\" cause ${chain(
                    it.cause,
                )}"
            }}"

    companion object {
        const val DRAFT02_MAX = 255L
        const val SERVER_CLOSE_CODE = 4294967294L // 2^32-2
        const val SERVER_CLOSE_REASON = "server-bye-32"

        private const val FIRST = 0x52e4a40fa8dbL
        private const val LAST = 0x52e5ac983162L

        /** draft-02 section 4.3 / draft-17 section 4.4: the WebTransport code an HTTP/3 code carries, unbounded. */
        fun wtCode(h: Long): Long? {
            if (h !in FIRST..LAST || (h - 0x21) % 0x1f == 0L) return null
            val s = h - FIRST
            return s - s / 0x1f
        }

        /** The HTTP/3 code of WebTransport code [n]. */
        fun h3Code(n: Long): Long = FIRST + n + n / 0x1e

        private fun h3Name(h: Long): String =
            when (h) {
                0x170d7b68L -> "WT_SESSION_GONE"
                0x3994bd84L -> "WT_BUFFERED_STREAM_REJECTED"
                0x10cL -> "H3_REQUEST_CANCELLED"
                0x100L -> "H3_NO_ERROR"
                else -> "HTTP/3 0x${h.toString(16)}"
            }

        private val FRAME =
            Regex(
                "\\{\"frame_type\":\"(reset_stream|reset_stream_at|stop_sending)\",\"stream_id\":(\\d+)," +
                    "\"error_code\":(?:(\\d+)|\"application_error_0x([0-9a-f]+)\")",
            )

        private suspend fun readLine(input: ByteReadChannel): String {
            val b = StringBuilder()
            while (true) {
                val c = input.readByte().toInt().toChar()
                if (c == '\n') return b.toString()
                b.append(c)
                require(b.length <= 200) { "a line above 200 bytes" }
            }
        }

        fun chain(e: Throwable?): String =
            generateSequence(e) { it.cause }.take(6).joinToString(" <- ") { "${it::class.simpleName}(${it.message})" }.ifEmpty { "none" }
    }
}
