// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.http3.webtransport

import io.kuicksilver.http3.Capsule
import io.kuicksilver.http3.WebTransportException
import io.kuicksilver.http3.frame.SettingsId
import io.kuicksilver.http3.frame.VarInt
import io.kuicksilver.http3.runtime.H3Session
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.first
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
 * raised as the peer's streams end and its bytes are taken from the transport (section 5.6: "Endpoints SHOULD send
 * WT_MAX_DATA and WT_MAX_STREAMS capsules as they consume data or close streams"), never waiting for a blocked capsule.
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
    /** Queues a capsule on the CONNECT stream; never suspends. */
    private val sendCapsule: (Capsule) -> Unit,
) {
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

    /** Moves whenever sending credit grows or the session ends: waiters look again. */
    private val credit = MutableStateFlow(0L)
    private var over: Throwable? = null

    // receiving
    private val initialStreams = longArrayOf(ourBidi, ourUni)
    private val ourMaxStreams = longArrayOf(ourBidi, ourUni)
    private val peerOpened = LongArray(2)
    private val peerClosed = LongArray(2)
    private val window = ourData
    private var ourMaxData = ourData
    private var received = 0L
    private var consumed = 0L

    /** The peer's stream limit of the kind (a test hook). */
    fun peerMaxStreamsForTest(bidi: Boolean): Long = peerMaxStreams[if (bidi) 0 else 1]

    /** The peer's data limit and what we counted against it (a test hook). */
    val sendDataForTest: Pair<Long, Long> get() = peerMaxData to sentData

    /** Our data limit and what the peer used of it (a test hook). */
    val receiveDataForTest: Pair<Long, Long> get() = ourMaxData to received

    /** The session ended: waiters fail with [cause]. */
    fun end(cause: Throwable) {
        if (over != null) return
        over = cause
        credit.value++
    }

    private suspend fun awaitCredit(seen: Long) {
        credit.first { it != seen }
    }

    /** Waits for the peer's limit to allow one more stream of the kind, and takes it. */
    suspend fun takeStream(bidi: Boolean) {
        val i = if (bidi) 0 else 1
        while (true) {
            over?.let { throw it }
            if (opened[i] < peerMaxStreams[i]) {
                opened[i]++
                changed()
                return
            }
            if (streamsBlockedAt[i] != peerMaxStreams[i]) {
                streamsBlockedAt[i] = peerMaxStreams[i]
                send(WtFlow.capsule(if (bidi) WtFlow.STREAMS_BLOCKED_BIDI else WtFlow.STREAMS_BLOCKED_UNI, peerMaxStreams[i]))
            }
            awaitCredit(credit.value)
        }
    }

    /** A stream [takeStream] counted was never opened (the transport refused it): the peer never sees it, so it is not counted. */
    fun returnStream(bidi: Boolean) {
        opened[if (bidi) 0 else 1]--
    }

    /** Waits until the peer's data limit leaves room, and takes up to [want] bytes of it; returns how many. */
    suspend fun takeData(want: Int): Int {
        while (true) {
            over?.let { throw it }
            val room = peerMaxData - sentData
            if (room > 0) {
                val n = minOf(want.toLong(), room).toInt()
                sentData += n
                changed()
                return n
            }
            if (dataBlockedAt != peerMaxData) {
                dataBlockedAt = peerMaxData
                send(WtFlow.capsule(WtFlow.DATA_BLOCKED, peerMaxData))
            }
            awaitCredit(credit.value)
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
            credit.value++
            changed()
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
     * [n] more body bytes of the peer were consumed: taken from the transport into a stream's own buffer, or abandoned (a
     * reset or stopped stream, whose bytes nobody reads). Once half the window is consumed the limit moves to what was
     * consumed plus the window (section 5.6: "Endpoints SHOULD send WT_MAX_DATA and WT_MAX_STREAMS capsules as they consume
     * data"); bytes only received, of a stream nobody reads yet, give no credit.
     */
    fun onConsumed(n: Long) {
        if (n <= 0) return
        consumed += n
        changed()
        if (ourMaxData - consumed < (window + 1) / 2) {
            ourMaxData = consumed + window
            send(WtFlow.capsule(WtFlow.MAX_DATA, ourMaxData))
        }
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
                if (value <= peerMaxData) return "WT_MAX_DATA $value does not increase the limit $peerMaxData"
                peerMaxData = value
                credit.value++
                changed()
            }

            WtFlow.MAX_STREAMS_BIDI, WtFlow.MAX_STREAMS_UNI -> {
                val i = if (type == WtFlow.MAX_STREAMS_BIDI) 0 else 1
                // section 5.6.2: "Recipients of a capsule with a Maximum Streams value larger than this limit MUST close the
                // WebTransport session", and one "that does not increase the Maximum Streams value previously received"
                if (value > WtFlow.MAX_STREAM_COUNT) return "WT_MAX_STREAMS $value is beyond 2^60"
                if (value <= peerMaxStreams[i]) return "WT_MAX_STREAMS $value does not increase the limit ${peerMaxStreams[i]}"
                peerMaxStreams[i] = value
                credit.value++
                changed()
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
                sendCapsule = send,
            )
        }

        /** Why a session failed its flow control. */
        fun error(reason: String): WebTransportException = WebTransportException.FlowControl(reason)
    }
}

/**
 * The count of one stream's body bytes from the peer against the session's limit (section 5.4): what was taken from the
 * transport, or the final size without the header once the peer's FIN or reset told it, whichever is larger, so a stream
 * the application never read, or stopped, counts what the peer sent. Made when the stream reaches its session, accepted
 * or not. Session dispatcher only.
 */
internal class WtInCount(
    private val flow: WtSessionFlow,
    private val headerLength: Int,
    private val onViolation: (String) -> Unit,
) {
    private var taken = 0L
    private var finalBody = -1L
    private var counted = 0L
    private var abandoned = false
    private var consumedCount = 0L

    /** [n] more bytes were taken from the transport. */
    fun taken(n: Int) {
        taken += n
        update()
    }

    /** The peer's half has final size [size] (header included). */
    fun final(size: Long) {
        finalBody = maxOf(0L, size - headerLength)
        update()
    }

    /** Nobody reads the rest (the peer reset the stream, or we stopped reading): it counts as consumed once its size is known. */
    fun abandon() {
        abandoned = true
        update()
    }

    private fun update() {
        val target = maxOf(taken, finalBody)
        if (target > counted) {
            val delta = target - counted
            counted = target
            flow.onReceived(delta)?.let(onViolation)
        }
        val consumed = if (abandoned) target else taken
        if (consumed > consumedCount) {
            flow.onConsumed(consumed - consumedCount)
            consumedCount = consumed
        }
    }

    companion object {
        /** A count for [st] on [h3]'s session scope; it learns the final size when the transport does. */
        fun start(
            h3: H3Session,
            st: io.kuicksilver.quic.QuicStream,
            flow: WtSessionFlow,
            headerLength: Int,
            onViolation: (String) -> Unit,
        ): WtInCount {
            val c = WtInCount(flow, headerLength, onViolation)
            @OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)
            h3.scope.launch {
                val f = runCatching { st.receivedFinalSize?.await() }.getOrNull() ?: return@launch
                c.final(f)
            }
            return c
        }
    }
}
