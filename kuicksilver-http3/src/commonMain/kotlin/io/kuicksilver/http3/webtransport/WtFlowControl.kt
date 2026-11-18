// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.http3.webtransport

import io.kuicksilver.http3.Capsule
import io.kuicksilver.http3.WebTransportException
import io.kuicksilver.http3.frame.SettingsId
import io.kuicksilver.http3.frame.VarInt
import io.kuicksilver.http3.runtime.H3Session
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.Job
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.launch

/**
 * The capsules and settings of WebTransport flow control (draft-ietf-webtrans-http3-16 section 5; draft-14 uses the same
 * codepoints) and the two HTTP/2 capsules it prohibits.
 */
internal object WtFlow {
    /** WT_MAX_DATA (section 5.6.4). */
    const val MAX_DATA: Long = 0x190B4D3D

    /** WT_MAX_STREAMS for bidirectional streams (section 5.6.2). */
    const val MAX_STREAMS_BIDI: Long = 0x190B4D3F

    /** WT_MAX_STREAMS for unidirectional streams. */
    const val MAX_STREAMS_UNI: Long = 0x190B4D40

    /** WT_DATA_BLOCKED (section 5.6.5). */
    const val DATA_BLOCKED: Long = 0x190B4D41

    /** WT_STREAMS_BLOCKED for bidirectional streams (section 5.6.3). */
    const val STREAMS_BLOCKED_BIDI: Long = 0x190B4D43

    /** WT_STREAMS_BLOCKED for unidirectional streams. */
    const val STREAMS_BLOCKED_UNI: Long = 0x190B4D44

    /** WT_MAX_STREAM_DATA of draft-ietf-webtrans-http2-16 section 6.6, prohibited over HTTP/3 (section 5.4). */
    const val MAX_STREAM_DATA: Long = 0x190B4D3E

    /** WT_STREAM_DATA_BLOCKED of draft-ietf-webtrans-http2-16 section 6.9, prohibited over HTTP/3 (section 5.4). */
    const val STREAM_DATA_BLOCKED: Long = 0x190B4D42

    /** The four "flow control capsules" of section 5.6. */
    val CAPSULES: Set<Long> = setOf(MAX_DATA, MAX_STREAMS_BIDI, MAX_STREAMS_UNI, DATA_BLOCKED, STREAMS_BLOCKED_BIDI, STREAMS_BLOCKED_UNI)

    /** Whether settings [s] carry a non-zero initial limit (section 5.5), beyond what declares flow control. */
    fun declaresInitialLimits(s: Map<Long, Long>): Boolean =
        (s[SettingsId.WT_INITIAL_MAX_STREAMS_UNI] ?: 0L) != 0L ||
            (s[SettingsId.WT_INITIAL_MAX_STREAMS_BIDI] ?: 0L) != 0L ||
            (s[SettingsId.WT_INITIAL_MAX_DATA] ?: 0L) != 0L

    /** The capsules section 5.4 prohibits: "Endpoints MUST treat receipt of a WT_MAX_STREAM_DATA or a WT_STREAM_DATA_BLOCKED capsule as a session error". */
    val PROHIBITED: Set<Long> = setOf(MAX_STREAM_DATA, STREAM_DATA_BLOCKED)

    /** Section 5.6.2: Maximum Streams "cannot exceed 2^60". */
    const val MAX_STREAM_COUNT: Long = 1L shl 60

    /**
     * Whether settings [s] (ours or the peer's) declare the intent to use flow control for a session of [version]
     * (section 5.1): "Sending SETTINGS_WT_INITIAL_MAX_STREAMS_UNI with any value other than "0"", the same for
     * `_BIDI` and `SETTINGS_WT_INITIAL_MAX_DATA`; draft-14 section 5.1 also "Sending SETTINGS_WT_MAX_SESSIONS with a value
     * greater than "1"". draft-02 has no flow control.
     */
    fun declares(
        s: Map<Long, Long>,
        version: WtVersion,
    ): Boolean =
        version != WtVersion.Draft02 &&
            (
                (s[SettingsId.WT_INITIAL_MAX_STREAMS_UNI] ?: 0L) != 0L ||
                    (s[SettingsId.WT_INITIAL_MAX_STREAMS_BIDI] ?: 0L) != 0L ||
                    (s[SettingsId.WT_INITIAL_MAX_DATA] ?: 0L) != 0L ||
                    (version == WtVersion.Draft14 && (s[SettingsId.WT_MAX_SESSIONS_DRAFT14] ?: 0L) > 1L)
            )

    /**
     * Section 5.1: "Flow control is enabled when both endpoints declare their intent to use flow control"; for a session
     * of [version] on [h3], once the peer's SETTINGS arrived.
     */
    fun enabled(
        h3: H3Session,
        version: WtVersion,
    ): Boolean = declares(WtSettings.ours(h3.isServer, h3.settings).toMap(), version) && declares(h3.wtPeerSettings, version)

    /** A capsule whose value is one variable-length integer. */
    fun capsule(
        type: Long,
        value: Long,
    ): Capsule = Capsule(type, VarInt.encode(value))

    /** The value of a flow-control capsule: exactly one variable-length integer, or null when it is not. */
    fun valueOf(c: Capsule): Long? {
        val v = c.value
        if (v.isEmpty() || VarInt.encodedLength(v[0]) != v.size) return null
        return VarInt.read(v, 0, v.size)
    }
}

/**
 * The flow control of one WebTransport session (draft-ietf-webtrans-http3-16 section 5), once both sides declared it.
 * Sending: the peer's stream limits and session data limit, initially its `SETTINGS_WT_INITIAL_*` (section 5.5) and raised
 * by its WT_MAX_STREAMS and WT_MAX_DATA capsules; opening a stream takes one, sending body bytes takes as many, and a
 * sender that has to wait announces it with WT_STREAMS_BLOCKED or WT_DATA_BLOCKED once per limit (sections 5.6.3,
 * 5.6.5: "A sender SHOULD send"). Receiving: our limits, initially our settings, enforced on every stream the peer opens
 * and every body byte it sends ("it MUST close the WebTransport session with a WT_FLOW_CONTROL_ERROR error code"), and
 * raised as the peer's streams end and its bytes are consumed ([WtInCount]: taken by the application, handed whole to a
 * stream that ended cleanly, or abandoned with a reset or stopped stream; section 5.6: "Endpoints SHOULD send WT_MAX_DATA
 * and WT_MAX_STREAMS capsules as they consume data or close streams"), never waiting for a blocked capsule.
 *
 * Order (ours; section 5 sets none): stream credit goes to opens in the order they asked; data credit follows the
 * session's RFC 9218 priority (section 3.4): a non-incremental session serves its streams in the order it handed them
 * to the application ([Sender]), an incremental one shares the credit between the streams that ask ([distribute]). The
 * order is per session: the connection's turns between sessions ([WtFairQueue], section 8) come after the credit, and a
 * stream that holds credit while it waits for its session's turn holds nothing of another session's.
 *
 * The body bytes of a stream are counted without its header (section 5.4); a stream that was reset counts its final size
 * ([io.kuicksilver.quic.QuicStream.sentFinalSize], [io.kuicksilver.quic.QuicStream.receivedFinalSize]), so both sides
 * agree on the credit it used.
 *
 * Every member runs on the session's single-threaded dispatcher.
 */
internal class WtSessionFlow(
    ourBidi: Long,
    ourUni: Long,
    ourData: Long,
    peerBidi: Long,
    peerUni: Long,
    peerData: Long,
    /**
     * draft-16 closes the session on a WT_MAX_DATA or WT_MAX_STREAMS "that does not increase" the value previously
     * received (sections 5.6.2, 5.6.4); draft-14 only on one "less than a previously received value" (its sections 5.6.2,
     * 5.6.4), so an equal one is accepted and changes nothing.
     */
    private val equalLimitIsViolation: Boolean = true,
    /** A sender just started waiting at a limit of 0. */
    private val onBlockedAtZero: () -> Unit = {},
    /**
     * The session's RFC 9218 `incremental` parameter now (its CONNECT stream's priority, which a PRIORITY_UPDATE changes):
     * how [distribute] shares the credit between the session's streams.
     */
    private val incremental: () -> Boolean = { false },
    /** Runs a block in a later turn of the session's dispatcher ([Sender.idle]); at once by default (unit tests). */
    private val later: (() -> Unit) -> Unit = { it() },
    /** Queues a capsule on the CONNECT stream; never suspends. */
    private val sendCapsule: (Capsule) -> Unit,
) {
    /** Some sender waits at a limit that is still 0 (the peer never raised it). */
    fun blockedAtZero(): Boolean =
        (dataBlockedAt == 0L && peerMaxData == 0L) || (0..1).any { streamsBlockedAt[it] == 0L && peerMaxStreams[it] == 0L }

    /** Moves at every change of the counters below and with every capsule sent (a test hook to wait on). */
    val changesForTest = MutableStateFlow(0L)

    /** The capsules sent so far, by type (a test hook; session dispatcher only). */
    val sentForTest = HashMap<Long, Int>()

    private fun send(c: Capsule) {
        sentForTest[c.type] = (sentForTest[c.type] ?: 0) + 1
        sendCapsule(c)
        changesForTest.value++
    }

    private fun changed() {
        changesForTest.value++
    }

    // sending: index 0 bidirectional, 1 unidirectional
    private val peerMaxStreams = longArrayOf(peerBidi.coerceAtMost(WtFlow.MAX_STREAM_COUNT), peerUni.coerceAtMost(WtFlow.MAX_STREAM_COUNT))
    private val opened = LongArray(2)
    private val streamsBlockedAt = longArrayOf(-1, -1)
    private var peerMaxData = peerData
    private var sentData = 0L
    private var dataBlockedAt = -1L

    /** The session is over: every wait ends with it (session dispatcher only). */
    private var over: Throwable? = null

    /** Opens waiting for the peer's stream limit, by kind, in the order they asked (section 5.6.2). */
    private val openers = arrayOf(ArrayDeque<CompletableDeferred<Unit>>(), ArrayDeque())

    /** Our writable streams, in the order the session handed them to the application: the order of service. */
    private val senders = ArrayList<Sender>()

    /** Credit kept for a stream ([Sender.reserved]) and not yet counted as sent. */
    private var reservedTotal = 0L

    // receiving
    private val initialStreams = longArrayOf(ourBidi, ourUni)
    private val ourMaxStreams = longArrayOf(ourBidi, ourUni)
    private val peerOpened = LongArray(2)
    private val peerClosed = LongArray(2)
    private val window = ourData
    private var ourMaxData = ourData
    private var received = 0L
    private var consumed = 0L

    /** Streams of the kind we opened, and that the peer opened, as counted (a test hook). */
    fun openedForTest(bidi: Boolean): Pair<Long, Long> = opened[if (bidi) 0 else 1] to peerOpened[if (bidi) 0 else 1]

    /** The peer's stream limit of the kind (a test hook). */
    fun peerMaxStreamsForTest(bidi: Boolean): Long = peerMaxStreams[if (bidi) 0 else 1]

    /** The peer's data limit and what we counted against it (a test hook). */
    val sendDataForTest: Pair<Long, Long> get() = peerMaxData to sentData

    /** Our data limit and what the peer used of it (a test hook). */
    val receiveDataForTest: Pair<Long, Long> get() = ourMaxData to received

    /**
     * Nothing waits for credit, no credit is kept for a stream and no stream holds a place (a test hook, once every stream
     * of the session ended).
     */
    val creditIdleForTest: Boolean get() = senders.isEmpty() && reservedTotal == 0L && openers.all { it.isEmpty() }

    /**
     * When a test set it (before the streams open, on the session's dispatcher): all credit ever handed to each stream, by
     * its place in the order ([Sender.order]), kept after the stream ended, a sticky record, so a test asks whether a stream
     * ever got credit, not what it holds at one instant. Null otherwise: nothing is recorded.
     */
    var grantedByOrderForTest: HashMap<Long, Long>? = null

    /** The places held, in order, as `order:need/reserved` (a test hook). */
    val sendersForTest: List<String> get() = senders.map { "${it.order}:${it.need}/${it.reserved}" }

    /** The session ended: waiters fail with [cause], and nothing stays kept or waiting. */
    fun end(cause: Throwable) {
        if (over != null) return
        over = cause
        for (q in openers) {
            while (q.isNotEmpty()) q.removeFirst().completeExceptionally(cause)
        }
        for (s in senders.toList()) {
            s.reserved = 0
            s.need = 0
            s.waiter?.complete(Unit)
        }
        senders.clear()
        reservedTotal = 0
        changed()
    }

    /**
     * Waits for the peer's limit to allow one more stream of the kind, and takes it. Opens are served in the order they
     * asked: one that started waiting earlier gets its slot before any that started later. Cancelled while waiting: it
     * leaves the queue, and a slot handed to it meanwhile goes to the next.
     */
    suspend fun takeStream(bidi: Boolean) {
        val i = if (bidi) 0 else 1
        over?.let { throw it }
        val q = openers[i]
        if (q.isEmpty() && opened[i] < peerMaxStreams[i]) {
            opened[i]++
            changed()
            return
        }
        if (streamsBlockedAt[i] != peerMaxStreams[i]) {
            streamsBlockedAt[i] = peerMaxStreams[i]
            if (peerMaxStreams[i] == 0L) onBlockedAtZero()
            send(WtFlow.capsule(if (bidi) WtFlow.STREAMS_BLOCKED_BIDI else WtFlow.STREAMS_BLOCKED_UNI, peerMaxStreams[i]))
        }
        val w = CompletableDeferred<Unit>()
        q.addLast(w)
        try {
            w.await()
        } catch (e: CancellationException) {
            q.remove(w)
            // the slot was handed over, but its opener is gone: it goes to the next
            @OptIn(ExperimentalCoroutinesApi::class)
            if (w.isCompleted && w.getCompletionExceptionOrNull() == null) returnStream(bidi)
            throw e
        }
    }

    /** Hands the free stream slots of kind [i] to the waiting opens, first come first served. */
    private fun serveOpens(i: Int) {
        val q = openers[i]
        while (q.isNotEmpty() && opened[i] < peerMaxStreams[i]) {
            opened[i]++
            q.removeFirst().complete(Unit)
            changed()
        }
    }

    /**
     * A stream [takeStream] counted was never opened (the transport refused it, or its opener gave up while it waited for
     * the transport): the peer never sees it, so it is not counted, and an open waiting for a slot takes it.
     */
    fun returnStream(bidi: Boolean) {
        val i = if (bidi) 0 else 1
        opened[i]--
        changed()
        if (over == null) serveOpens(i)
    }

    /**
     * A place in the session's data credit for one of our streams that sends, made when the session hands the stream to
     * the application (the stream we opened once [takeStream] and its header are done, the peer's bidirectional stream
     * once accepted).
     */
    fun sender(): Sender =
        Sender(nextOrder++).also {
            if (over == null) senders += it
            changed()
        }

    private var nextOrder = 0L

    /**
     * Free credit: the peer's limit less what was sent and what is kept for a stream. Section 5.6.4: "The sum of the
     * lengths of Stream Body data sent on all streams associated with this session MUST NOT exceed the Maximum Data value
     * advertised by a receiver", so nothing is ever kept or taken beyond it.
     */
    private fun free(): Long = peerMaxData - sentData - reservedTotal

    /**
     * Hands free credit to the streams that ask for it: one that waits for credit, or writes what it was just given (a
     * chunk is written in parts as credit comes), asks up to [LOOKAHEAD] kept for it; one that asks nothing (idle, or
     * ended) holds no place. How follows the session's RFC 9218 priority, the `incremental` parameter of its CONNECT
     * stream, read at every grant (draft-16 section 3.4 recommends RFC 9218's scheduling for all of a session's data):
     * - non-incremental: in [senders] order (RFC 9218 section 10: "serving one response at a time" in order): each
     *   stream gets what it asks before any stream after it gets anything;
     * - incremental: shared ("interleaved", the same section): each grant starts one stream further along the ring of
     *   the streams that ask and goes on in order from there, so with any credit at all each of n streams that keep
     *   asking leads, and gets some, within n grants, and a busy stream never holds the others. A grant is not split
     *   evenly: the stream it starts with gets what it asks first, so a stream nobody reads still gets all its bytes out
     *   and ends, and a receiver that gives credit back only for ended streams (draft-16 section 5.6) moves.
     */
    private fun distribute() {
        if (free() <= 0 || over != null) return
        if (incremental()) share() else inOrder()
        changed()
    }

    private fun ask(s: Sender): Long = if (s.need > 0 || s.writing) maxOf(s.need, LOOKAHEAD) - s.reserved else 0L

    private fun give(
        s: Sender,
        g: Long,
    ) {
        s.reserved += g
        s.grantedForTest += g
        grantedByOrderForTest?.let { it[s.order] = (it[s.order] ?: 0L) + g }
        reservedTotal += g
        s.waiter?.complete(Unit)
    }

    private fun inOrder() {
        var free = free()
        for (s in senders) {
            val cap = ask(s)
            if (cap <= 0) continue
            val g = minOf(cap, free)
            give(s, g)
            free -= g
            if (free == 0L) break
        }
    }

    /** The order of the stream the last shared grant started with: the next one starts after it. */
    private var shareFrom = -1L

    private fun share() {
        val asking = senders.filter { ask(it) > 0 }
        if (asking.isEmpty()) return
        // the first stream after the one the last grant started with, round the ring, then on in order from there
        val start = asking.indexOfFirst { it.order > shareFrom }.let { if (it < 0) 0 else it }
        shareFrom = asking[start].order
        var free = free()
        for (s in asking.drop(start) + asking.take(start)) {
            val g = minOf(ask(s), free)
            give(s, g)
            free -= g
            if (free == 0L) break
        }
    }

    /**
     * One of our streams' place in the session's data credit (section 5.4), made in the order the session hands its
     * streams to the application ([sender]). In a non-incremental session that is the order of service: whenever credit is
     * handed out, a stream that is waiting for it, or writing what it was just given, is served before every stream made
     * after it; in an incremental one the credit is shared between them ([distribute]). A take that asks more than the
     * credit there is gets what there is (a partial grant: one frame's worth goes out, never a wait for all of it), and
     * the stream keeps asking for the rest (in order, a later stream never overtakes it), and the credit that comes while
     * it writes is kept for it (up to [LOOKAHEAD]). A stream that has nothing more to send ([idle]) keeps no credit: what was kept for it goes on once its
     * pump really waits for the application (it is given back in the next turn of the session's dispatcher, so a pump
     * that finds more bytes at once keeps its place). Session dispatcher only.
     */
    inner class Sender internal constructor(
        val order: Long,
    ) {
        internal var need = 0L
        internal var reserved = 0L
        internal var writing = false
        internal var closed = false
        internal var waiter: CompletableDeferred<Unit>? = null

        /** All credit ever handed to this stream (a test hook). */
        internal var grantedForTest = 0L

        /**
         * Waits until credit is handed to this stream, and takes up to [want] bytes of it; returns how many, or 0 once the
         * stream [close]d (its final size is fixed): nothing is taken then.
         */
        suspend fun take(want: Int): Int {
            require(want > 0) { "want $want" }
            while (true) {
                over?.let { throw it }
                if (closed) return 0
                need = want.toLong()
                distribute()
                if (reserved > 0) {
                    val k = minOf(want.toLong(), reserved)
                    reserved -= k
                    reservedTotal -= k
                    sentData += k
                    need = 0
                    writing = true
                    changed()
                    return k.toInt()
                }
                // nothing for it: the peer's limit is all sent or kept for other streams. WT_DATA_BLOCKED goes now although
                // part of the limit may be kept and not yet sent: the session as a whole has no credit left for what it
                // wishes to send, which is what section 5.6.5 reports ("when it wishes to send data but is unable to do so
                // due to WebTransport session-level flow control"); the kept credit goes out as its streams write it
                if (dataBlockedAt != peerMaxData) {
                    dataBlockedAt = peerMaxData
                    if (peerMaxData == 0L) onBlockedAtZero()
                    send(WtFlow.capsule(WtFlow.DATA_BLOCKED, peerMaxData))
                }
                val w = CompletableDeferred<Unit>()
                waiter = w
                changed()
                try {
                    w.await()
                } catch (e: CancellationException) {
                    // gone while waiting: what was kept for it goes to the streams after it
                    waiter = null
                    need = 0
                    writing = false
                    giveBack()
                    throw e
                }
                waiter = null
            }
        }

        /**
         * The stream wrote everything it was given and looks for more bytes of the application: unless it takes again in
         * this turn of the dispatcher, what was kept for it goes on.
         */
        fun idle() {
            writing = false
            need = 0
            if (reserved == 0L || closed) return
            later {
                if (!closed && !writing && waiter == null && reserved > 0) giveBack()
            }
        }

        /** The stream's sending half ended (FIN, reset, the pump's end): it leaves the order, and a waiting take returns 0. */
        fun close() {
            if (closed) return
            closed = true
            need = 0
            writing = false
            senders.remove(this)
            waiter?.complete(Unit)
            changed()
            giveBack()
        }

        private fun giveBack() {
            if (reserved > 0) {
                reservedTotal -= reserved
                reserved = 0
                changed()
            }
            distribute()
        }
    }

    /**
     * Our stream's sending half ended with final size [bodyFinal] (without its header) after [counted] bytes were taken
     * for it: what was taken and never sent goes back (a reset dropped it).
     */
    fun sentFinal(
        counted: Long,
        bodyFinal: Long,
    ) {
        if (bodyFinal < counted) {
            sentData -= counted - bodyFinal
            changed()
            distribute()
        }
    }

    /**
     * The peer opened a stream of the kind for this session; returns the violation when it is beyond the limit we gave
     * (section 5.6.2: "If an endpoint receives an incoming stream for a session that would exceed the advertised Maximum
     * Streams value, it MUST close the WebTransport session with a WT_FLOW_CONTROL_ERROR error code").
     */
    fun onPeerStream(bidi: Boolean): String? {
        val i = if (bidi) 0 else 1
        peerOpened[i]++
        changed()
        if (peerOpened[i] > ourMaxStreams[i]) {
            val kind = if (bidi) "bidirectional" else "unidirectional"
            return "the peer opened ${peerOpened[i]} $kind streams, beyond our limit of ${ourMaxStreams[i]}"
        }
        return null
    }

    /** A stream the peer opened ended: its slot is given back with WT_MAX_STREAMS once half the initial window is. */
    fun onPeerStreamClosed(bidi: Boolean) {
        val i = if (bidi) 0 else 1
        peerClosed[i]++
        val next = (peerClosed[i] + initialStreams[i]).coerceAtMost(WtFlow.MAX_STREAM_COUNT)
        if (next - ourMaxStreams[i] >= maxOf(1L, initialStreams[i] / 2)) {
            ourMaxStreams[i] = next
            send(WtFlow.capsule(if (bidi) WtFlow.MAX_STREAMS_BIDI else WtFlow.MAX_STREAMS_UNI, next))
        }
    }

    /**
     * [n] more body bytes of the peer were received; returns the violation when they pass our limit (section 5.6.4: "If an
     * endpoint receives Stream Body data in excess of this limit, it MUST close the WebTransport session with a
     * WT_FLOW_CONTROL_ERROR error code").
     */
    fun onReceived(n: Long): String? {
        if (n <= 0) return null
        received += n
        changed()
        if (received > ourMaxData) return "the peer sent $received bytes of stream data, beyond our limit of $ourMaxData"
        return null
    }

    /**
     * [n] more body bytes of the peer were consumed ([WtInCount]): taken by the application from a stream's input, all of a
     * stream that ended cleanly once every byte of it was handed to that input, or abandoned (a reset or stopped stream,
     * whose bytes nobody reads). Once half the window is consumed the limit moves to what was
     * consumed plus the window (section 5.6: "Endpoints SHOULD send WT_MAX_DATA and WT_MAX_STREAMS capsules as they consume
     * data"); bytes only received, of a stream nobody reads yet, give no credit.
     */
    fun onConsumed(n: Long) {
        if (n <= 0) return
        consumed += n
        changed()
        if (ourMaxData - consumed < (window + 1) / 2) {
            // a variable-length integer holds at most 2^62-1: the limit stops there, and goes out only when it grew
            val next = if (consumed > VarInt.MAX - window) VarInt.MAX else consumed + window
            if (next > ourMaxData) {
                ourMaxData = next
                send(WtFlow.capsule(WtFlow.MAX_DATA, ourMaxData))
            }
        }
    }

    /**
     * Streams the router rejected for this session before it existed (over its buffering bounds): the peer counted them,
     * so they are opened and closed here, and their [bytes] received and consumed; returns the violation, if any.
     */
    fun onRejected(
        bidi: Int,
        uni: Int,
        bytes: Long,
    ): String? {
        repeat(bidi) {
            onPeerStream(true)?.let { return it }
            onPeerStreamClosed(true)
        }
        repeat(uni) {
            onPeerStream(false)?.let { return it }
            onPeerStreamClosed(false)
        }
        onReceived(bytes)?.let { return it }
        onConsumed(bytes)
        return null
    }

    /** A flow-control capsule from the peer (section 5.6); returns the violation that closes the session, if any. */
    fun onCapsule(
        type: Long,
        value: Long,
    ): String? {
        when (type) {
            WtFlow.MAX_DATA -> {
                // section 5.6.4: "If an endpoint receives a WT_MAX_DATA capsule with a Maximum Data value that does not
                // increase the Maximum Data value previously received, it MUST close the WebTransport session"
                if (value < peerMaxData || (equalLimitIsViolation && value == peerMaxData)) {
                    return "WT_MAX_DATA $value does not increase the limit $peerMaxData"
                }
                if (value == peerMaxData) return null
                peerMaxData = value
                changed()
                distribute()
            }

            WtFlow.MAX_STREAMS_BIDI, WtFlow.MAX_STREAMS_UNI -> {
                val i = if (type == WtFlow.MAX_STREAMS_BIDI) 0 else 1
                // section 5.6.2: "Recipients of a capsule with a Maximum Streams value larger than this limit MUST close the
                // WebTransport session", and one "that does not increase the Maximum Streams value previously received"
                if (value > WtFlow.MAX_STREAM_COUNT) return "WT_MAX_STREAMS $value is beyond 2^60"
                if (value < peerMaxStreams[i] || (equalLimitIsViolation && value == peerMaxStreams[i])) {
                    return "WT_MAX_STREAMS $value does not increase the limit ${peerMaxStreams[i]}"
                }
                if (value == peerMaxStreams[i]) return null
                peerMaxStreams[i] = value
                changed()
                if (over == null) serveOpens(i)
            }

            WtFlow.STREAMS_BLOCKED_BIDI, WtFlow.STREAMS_BLOCKED_UNI -> {
                // section 5.6.3: the same bound; otherwise only a hint
                if (value > WtFlow.MAX_STREAM_COUNT) return "WT_STREAMS_BLOCKED $value is beyond 2^60"
            }

            else -> {} // WT_DATA_BLOCKED: a hint
        }
        return null
    }

    companion object {
        /** The session's flow control on [h3] for [version], or null when it is not enabled (section 5.1). */
        fun of(
            h3: H3Session,
            version: WtVersion,
            send: (Capsule) -> Unit,
            incremental: () -> Boolean,
            onBlockedAtZero: () -> Unit = {},
        ): WtSessionFlow? {
            if (!WtFlow.enabled(h3, version)) return null
            val ours = h3.settings
            val peer = h3.wtPeerSettings
            return WtSessionFlow(
                ourBidi = ours.webTransportInitialMaxStreamsBidi,
                ourUni = ours.webTransportInitialMaxStreamsUni,
                ourData = ours.webTransportInitialMaxData,
                peerBidi = peer[SettingsId.WT_INITIAL_MAX_STREAMS_BIDI] ?: 0L,
                peerUni = peer[SettingsId.WT_INITIAL_MAX_STREAMS_UNI] ?: 0L,
                peerData = peer[SettingsId.WT_INITIAL_MAX_DATA] ?: 0L,
                equalLimitIsViolation = version != WtVersion.Draft14,
                sendCapsule = send,
                onBlockedAtZero = onBlockedAtZero,
                later = { block -> h3.scope.launch { block() } },
                incremental = incremental,
            )
        }

        /** The most credit kept for a stream while it writes what it was given: one chunk, what its next take asks at most. */
        const val LOOKAHEAD: Long = WtFairness.SEND_QUANTUM

        /** Why a session failed its flow control. */
        fun error(reason: String): WebTransportException = WebTransportException.FlowControl(reason)
    }
}

/**
 * The count of one stream's body bytes from the peer against the session's limit (section 5.4). Received: the most the
 * peer is known to have sent, without the header: the highest offset the transport received (read or not, in order or
 * not), the bytes taken from it, or the final size once its FIN or reset told it. Consumed (the credit given back):
 * what the application read, or everything received once nobody will read it (the peer reset the stream, we stopped
 * reading). Made when the stream reaches its session, accepted or not. Session dispatcher only.
 */
internal class WtInCount(
    private val flow: WtSessionFlow,
    private val headerLength: Int,
    private val onViolation: (String) -> Unit,
) {
    private var taken = 0L
    private var highestBody = 0L
    private var finalBody = -1L
    private var read = 0L
    private var counted = 0L
    private var abandoned = false
    private var consumedCount = 0L
    private val watchers = ArrayList<Job>()

    /** [n] more bytes were taken from the transport. */
    fun taken(n: Int) {
        taken += n
        update()
    }

    /** The transport received the peer's half up to [offset] (header included). */
    fun received(offset: Long) {
        highestBody = maxOf(highestBody, offset - headerLength)
        update()
    }

    /** The peer's half has final size [size] (header included): nothing more will come, the watchers stop. */
    fun final(size: Long) {
        finalBody = maxOf(0L, size - headerLength)
        update()
        stop()
    }

    /** The application read [n] more bytes. */
    fun read(n: Long) {
        read += n
        update()
    }

    /**
     * The peer's half ended cleanly and every byte of it was handed to the application's input: it counts as consumed (an
     * exact read after the last wait is never reported, and what is left is at most what the application holds).
     */
    fun delivered() {
        read = maxOf(read, taken)
        update()
    }

    /** Nobody reads the rest (the peer reset the stream, or we stopped reading): it counts as consumed once its size is known. */
    fun abandon() {
        abandoned = true
        update()
    }

    /** The stream is gone from the session: the watchers of its offsets stop. */
    fun stop() {
        for (w in watchers) w.cancel()
        watchers.clear()
    }

    private fun update() {
        val target = maxOf(taken, highestBody, finalBody)
        if (target > counted) {
            val delta = target - counted
            counted = target
            flow.onReceived(delta)?.let(onViolation)
        }
        val consumed = if (abandoned) target else minOf(read, target)
        if (consumed > consumedCount) {
            flow.onConsumed(consumed - consumedCount)
            consumedCount = consumed
        }
    }

    companion object {
        /** A count for [st] on [h3]'s session scope; it follows the transport's received offset and final size. */
        @OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)
        fun start(
            h3: H3Session,
            st: io.kuicksilver.quic.QuicStream,
            flow: WtSessionFlow,
            headerLength: Int,
            onViolation: (String) -> Unit,
        ): WtInCount {
            val c = WtInCount(flow, headerLength, onViolation)
            c.watchers +=
                h3.scope.launch {
                    val f = runCatching { st.receivedFinalSize?.await() }.getOrNull() ?: return@launch
                    c.final(f)
                }
            st.receivedOffset?.let { offsets -> c.watchers += h3.scope.launch { offsets.collect { c.received(it) } } }
            return c
        }
    }
}
