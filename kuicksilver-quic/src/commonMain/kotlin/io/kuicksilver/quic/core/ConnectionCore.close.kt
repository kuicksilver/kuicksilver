// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(ExperimentalKuicksilverApi::class)

package io.kuicksilver.quic.core

import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.annotations.InternalKuicksilverApi
import io.kuicksilver.native.PacketBuffer
import io.kuicksilver.quic.ConnectionCore
import io.kuicksilver.quic.ConnectionCore.CloseFrame
import io.kuicksilver.quic.ConnectionEvent
import io.kuicksilver.quic.ConnectionState
import io.kuicksilver.quic.Initiator
import io.kuicksilver.quic.QuicException
import io.kuicksilver.quic.TimeMark
import io.kuicksilver.quic.TransportError
import io.kuicksilver.quic.recovery.SpaceId
import io.kuicksilver.quic.wire.QuicWireException
import io.kuicksilver.tls.Certificate
import io.kuicksilver.tls.CertificateCompression
import io.kuicksilver.tls.QuicTlsSession
import io.kuicksilver.tls.TlsException
import io.kuicksilver.tls.sniSelectedFor
import io.kuicksilver.tls.tlsAlertName

// How a [ConnectionCore] ends: CONNECTION_CLOSE, draining, silent close, stateless reset, release of native resources and the glitch
// budget (RFC 9000 sections 10 and 21.9).

/** The longest reason phrase we send, in bytes. */
internal const val MAX_REASON_BYTES = 1024

/**
 * The length of the longest prefix of the UTF-8 bytes [b] of at most [max] bytes that ends on a code point boundary (RFC 9000
 * section 19.19: the Reason Phrase "SHOULD be a UTF-8 encoded string"). Bytes that are not UTF-8 are cut at [max].
 */
internal fun utf8Prefix(
    b: ByteArray,
    max: Int,
): Int {
    if (b.size <= max) return b.size
    var n = max
    // step back over at most three continuation bytes (10xxxxxx) to the lead byte of the character [max] splits
    while (n > 0 && max - n < 3 && b[n].toInt() and 0xc0 == 0x80) n--
    return if (b[n].toInt() and 0xc0 == 0x80) max else n
}

/**
 * Why something this side sent still waits for the peer, or null when nothing does ([sendsSettled]): an ack-eliciting
 * packet in flight in a space whose keys are still held, a probe due, or CRYPTO data, a stream control frame
 * (RESET_STREAM, STOP_SENDING, a RESET_STREAM_AT queued once its reliable bytes went out, the flow-control updates), a
 * connection ID frame or stream data the stream may send now (new or queued again after a loss, also while the pacer
 * holds it) waiting for a packet. A frame of a lost packet is queued again (RFC 9002 section 6), so it is in one of these
 * until the peer acknowledged the packet that carried it. Stream data blocked on the peer's credit is not counted (the
 * scheduler drops such a stream until credit comes): only the peer can release it, and its reliable bytes hold a
 * RESET_STREAM_AT back with it. Null once the connection is closing, draining or closed: it sends nothing more but its
 * CONNECTION_CLOSE.
 */
internal fun ConnectionCore.sendsUnsettled(): String? {
    if (state == ConnectionState.Closing || state == ConnectionState.Draining || state == ConnectionState.Closed) return null
    for (space in SpaceId.entries) {
        if (spaceDiscarded[space.ordinal]) continue
        val inFlight = loss.space(space).ackElicitingInFlight
        if (inFlight > 0) return "${space.name}: $inFlight ack-eliciting packet(s) in flight"
        if (probePending[space.ordinal] > 0) return "${space.name}: a probe is due"
    }
    if (!spaceDiscarded[SpaceId.Initial.ordinal] && cryptoStreams.send[0].hasPending) return "Initial CRYPTO data waits"
    if (!spaceDiscarded[SpaceId.Handshake.ordinal] && cryptoStreams.send[2].hasPending) return "Handshake CRYPTO data waits"
    if (cryptoStreams.send[3].hasPending) return "1-RTT CRYPTO data waits"
    if (streams.hasControlFrames()) return "stream control frames wait"
    if (cids.hasPendingFrames()) return "connection ID frames wait"
    if (streams.hasStreamData()) return "stream data waits"
    return null
}

/** [sendsUnsettled] is null: everything this side sent was acknowledged and nothing waits to be sent. */
internal fun ConnectionCore.sendsSettled(): Boolean = sendsUnsettled() == null

/**
 * Before a close: every space's unacknowledged frames are queued again, to go now within the congestion window instead
 * of at the next probe timeout, which a backoff may have put seconds away. No probe is owed: RFC 9002 section 7 lets a
 * packet exceed the window only "on a PTO timer expiration (see Section 6.2) or when entering recovery", and this is
 * neither (section 7.5 exempts the probes of an expiry, not this resend). With the window full nothing more goes, and the
 * regular PTO probe is the fallback. The PTO backoff stays as it is (section 6.2.1: it grows only when the timer
 * expires). Retransmitting unacknowledged data early is the content a probe may carry (section 6.2.4) and what
 * `resendInFlightAtOnce` does when a handshake's active address comes back. No-op once closing.
 */
internal fun ConnectionCore.probeUnsettledNow() {
    if (state == ConnectionState.Closing || state == ConnectionState.Draining || state == ConnectionState.Closed) return
    for (space in SpaceId.entries) {
        if (spaceDiscarded[space.ordinal] || loss.space(space).ackElicitingInFlight <= 0) continue
        requeueForProbe(space, Int.MAX_VALUE)
    }
}

/**
 * A closing connection sends its CONNECTION_CLOSE once more at the next poll, whatever the rate limit of its answers
 * (RFC 9000 section 10.2.1 lets the closing packet be sent again, and limits only the rate): true when it is closing (not
 * draining: a peer that closed too wants nothing more).
 */
internal fun ConnectionCore.repeatCloseNow(): Boolean {
    if (state != ConnectionState.Closing || closeFrame == null) return false
    closeSent = false
    return true
}

/** The closing or draining period starts now: it ends 3 x the current PTO from now (RFC 9000 section 10.2). */
private fun ConnectionCore.startClosePeriod() {
    val p = pto()
    timers.closePto = p
    timers.closeDeadline = now + p * 3
}

internal fun ConnectionCore.enterClosing(reason: QuicException.ConnectionLost) {
    state = ConnectionState.Closing
    closedReason = reason
    closeSent =
        false
    startClosePeriod()
    paths.dropAllResponses()
    streams.settleHeldUntilAnswer(false) // an answer that never comes stands for no acceptance
    events += ConnectionEvent.Closed(reason)
    // `now` must be the moment the closing state begins (a fresh `loop.now()`, see ConnectionRuntime.close), never a cached
    // time: tools/interop/closing-challenge.py takes this connection_closed time as proof that our client was closing before a
    // PATH_CHALLENGE arrived
    qlog?.connectionClosed(reason, now)
}

/** An unexpected exception inside this connection: it closes silently with [QuicException.ConnectionLost.Internal]; the endpoint and its other connections go on. */
internal fun ConnectionCore.failInternal(e: Throwable) {
    if (state ==
        ConnectionState.Closed
    ) {
        return
    }
    silentClose(QuicException.ConnectionLost.Internal("internal error: ${e.message ?: e::class.simpleName}", e))
}

/** Idle and handshake timeouts close without a CONNECTION_CLOSE (RFC 9000 section 10.1). */
internal fun ConnectionCore.silentClose(reason: QuicException.ConnectionLost) {
    closedReason = reason
    streams.settleHeldUntilAnswer(false)
    events += ConnectionEvent.Closed(reason)
    qlog?.connectionClosed(reason, now)
    markClosed()
}

/**
 * The terminal state: every native resource of this connection (TLS session, packet protectors) still held is freed here; a
 * draining connection gave them up already ([releaseCryptoIfDraining]).
 */
internal fun ConnectionCore.markClosed() {
    state = ConnectionState.Closed
    release()
}

internal fun ConnectionCore.release() {
    if (released) return
    released = true
    releaseCrypto()
    qlog?.close()
}

/**
 * RFC 9000 section 10.2.2: "Retaining packet protection keys is unnecessary once a connection is in the draining state". A
 * draining connection sends nothing and reads nothing ([ConnectionCore.handleDatagram] drops every datagram, [ConnectionCore.poll] builds none), so its
 * packet protectors and TLS session are freed at once instead of 3 x PTO later (about 3 s before the first RTT sample);
 * what the period needs, the connection IDs that route the peer's late packets to this connection so they are dropped
 * without a Stateless Reset, stays until `markClosed`. Run from [ConnectionCore.poll], after the application side read what the session
 * reported (the peer's certificates, the ALPN) with the events of the datagram that started draining; a TLS step still
 * running when the CONNECTION_CLOSE was parsed has ended by then. The closing state keeps both: its CONNECTION_CLOSE is
 * built anew each time it is repeated (§10.2.1), and the keys authenticate the packets it answers and find the peer's
 * CONNECTION_CLOSE in them ("An endpoint MAY retain packet protection keys for incoming packets").
 */
internal fun ConnectionCore.releaseCryptoIfDraining() {
    if (state == ConnectionState.Draining) releaseCrypto()
}

private fun ConnectionCore.releaseCrypto() {
    if (cryptoReleased) return
    cryptoReleased = true
    beforeCryptoReleaseForTest?.invoke()
    // what the session said stays readable through the core's getters (a draining connection's peer certificates, ALPN,
    // 0-RTT outcome) once it is gone; a getter that fails here (a session that never got going) answers as nothing
    tlsFacts = TlsFacts.of(handshake.session)
    keyUpdatesAtRelease = keyPhase?.updates ?: 0L
    keyPhase?.close()
    keyPhase = null
    for (i in 0 until 4) {
        readKeys[i]?.close()
        writeKeys[i]?.close()
        readKeys[i] = null
        writeKeys[i] = null
    }
    initialReadOriginal?.close()
    initialReadOriginal = null
    handshake.session.close()
}

internal fun ConnectionCore.fail(
    code: Long,
    frameType: Long,
    reason: String,
    cause: Throwable?,
) {
    if (state == ConnectionState.Closing || state == ConnectionState.Draining || state == ConnectionState.Closed) return
    val bytes = reason.encodeToByteArray().let { it.copyOf(utf8Prefix(it, MAX_REASON_BYTES)) }
    closeFrame = CloseFrame(false, code, frameType, bytes)
    enterClosing(QuicException.ConnectionLost.TransportClosed(code, frameType, reason, bytes, Initiator.Local, cause))
}

internal fun ConnectionCore.peerClosed(
    application: Boolean,
    code: Long,
    frameType: Long,
    reasonBytes: ByteArray,
) {
    if (state == ConnectionState.Draining || state == ConnectionState.Closed) return
    val closing = state == ConnectionState.Closing
    state = ConnectionState.Draining
    // RFC 9000 section 10.2.2: a closing endpoint MAY enter the draining state on the peer's CONNECTION_CLOSE, and "In this
    // case, the draining state ends when the closing state would have ended"; only a connection that was not closing starts
    // a period now
    if (!closing) startClosePeriod()
    paths.dropAllResponses()
    streams.settleHeldUntilAnswer(false) // an answer that never comes stands for no acceptance
    // RFC 9000 section 10.2.2: a closing endpoint that receives CONNECTION_CLOSE may drain; the connection already ended with our
    // own reason, reported once
    if (closing) return
    var reason = reasonBytes.decodeToString() // lossy UTF-8; keep its encoding within 1 KiB
    while (reason.encodeToByteArray().size > 1024) reason = reason.dropLast(1)
    val cause: Throwable? =
        if (!application &&
            code in 0x100..0x1ff
        ) {
            // RFC 9001 section 4.8: CRYPTO_ERROR 0x0100 + the alert; named as over TCP ("certificate_required", not "TLS
            // alert 116"), so the message reads the same on every protocol
            (code - 0x100).toInt().let {
                @OptIn(InternalKuicksilverApi::class)
                TlsException.AlertReceived(it, tlsAlertName(it))
            }
        } else {
            null
        }
    closedReason =
        if (application) {
            QuicException.ConnectionLost.ApplicationClosed(
                code,
                reason,
                Initiator.Peer,
            )
        } else {
            QuicException.ConnectionLost.TransportClosed(code, frameType, reason, reasonBytes, Initiator.Peer, cause)
        }
    events += ConnectionEvent.Closed(closedReason!!)
    qlog?.connectionClosed(closedReason!!, now)
}

/**
 * RFC 9000 section 10.3.1: a datagram from [from] that could not be processed and ends with the reset token of a peer ID we used
 * towards [from] is a Stateless Reset — the connection enters Draining with [QuicException.ConnectionLost.StatelessReset] and sends
 * nothing more. Anything else is ignored and, with [countInvalid], counted in `ConnectionStats.invalidResets`: a datagram
 * whose first packet was not ours or did not authenticate. One led by a packet of a space whose keys we discarded is
 * checked but not counted.
 */
internal fun ConnectionCore.checkStatelessReset(
    data: PacketBuffer,
    length: Int,
    from: io.ktor.network.sockets.InetSocketAddress,
    now: TimeMark,
    countInvalid: Boolean = true,
): Boolean {
    if (state == ConnectionState.Draining || state == ConnectionState.Closed ||
        length < io.kuicksilver.quic.endpoint.StatelessReset.MIN_SIZE
    ) {
        return false
    }
    if (!cids.matchesPeerToken(data, length, from)) {
        if (countInvalid) invalidResets++
        return false
    }
    this.now = now
    // a Stateless Reset that reaches a closing connection ends its closing period as draining at the end the closing state
    // had: section 10.3.1 says only that the endpoint "MUST enter the draining period"; keeping the end is our reading, by
    // analogy with section 10.2.2's draining after closing
    if (state != ConnectionState.Closing) startClosePeriod()
    state = ConnectionState.Draining
    paths.dropAllResponses()
    streams.settleHeldUntilAnswer(false) // an answer that never comes stands for no acceptance
    val reason = QuicException.ConnectionLost.StatelessReset()
    closedReason = reason
    events += ConnectionEvent.Closed(reason)
    qlog?.connectionClosed(reason, now)
    return true
}

/** Spends one glitch token; throws PROTOCOL_VIOLATION "excessive peer activity" when the bucket is empty (docs/guide/quic.md, "Glitch protection"). */
internal fun ConnectionCore.glitch(frameType: Long) {
    val g =
        glitch ?: return
    glitchCounts[minOf(frameType, 31L).toInt()]++
    if (!g.spend(now)) {
        throw QuicWireException(
            TransportError.PROTOCOL_VIOLATION,
            frameType,
            "excessive peer activity (" + glitchSummary() + ")",
        )
    }
}

/** The reason text of a glitch close names the frame types that spent the tokens: what a peer or a pcap reader needs to see. */
private fun ConnectionCore.glitchSummary(): String {
    val sb = StringBuilder()
    for (i in glitchCounts.indices) {
        if (glitchCounts[i] >
            0
        ) {
            if (sb.isNotEmpty()) sb.append(' ')
            sb
                .append("0x")
                .append(i.toString(16))
                .append('=')
                .append(glitchCounts[i])
        }
    }
    return sb.toString()
}

/** What a QUIC connection's TLS session says: [Live] while it exists, a [Snapshot] ([of]) taken as it is freed. */
@OptIn(ExperimentalKuicksilverApi::class, io.kuicksilver.annotations.InternalKuicksilverApi::class)
internal interface TlsFacts {
    val peerCertificates: List<Certificate>
    val localCertificates: List<Certificate>
    val negotiatedAlpn: String?
    val keyExchangeGroup: String?
    val peerCertificateCompression: CertificateCompression?
    val earlyDataAccepted: Boolean?
    val sniSelectedFor: String?

    /** The current session's own answers, read on each call (a version change replaces the session: [core] names it). */
    class Live(
        private val core: ConnectionCore,
    ) : TlsFacts {
        private val s: QuicTlsSession get() = core.handshake.session
        override val peerCertificates: List<Certificate> get() = s.peerCertificates
        override val localCertificates: List<Certificate> get() = s.localCertificates
        override val negotiatedAlpn: String? get() = s.negotiatedAlpn
        override val keyExchangeGroup: String? get() = s.keyExchangeGroup
        override val peerCertificateCompression: CertificateCompression? get() = s.peerCertificateCompression
        override val earlyDataAccepted: Boolean? get() = s.earlyDataAccepted
        override val sniSelectedFor: String? get() = s.sniSelectedFor
    }

    /** The answers as they were when the session was freed. */
    class Snapshot(
        override val peerCertificates: List<Certificate>,
        override val localCertificates: List<Certificate>,
        override val negotiatedAlpn: String?,
        override val keyExchangeGroup: String?,
        override val peerCertificateCompression: CertificateCompression?,
        override val earlyDataAccepted: Boolean?,
        override val sniSelectedFor: String?,
    ) : TlsFacts

    companion object {
        /** Each answer on its own: one getter that fails (a session that never got going) leaves the others. */
        fun of(s: QuicTlsSession): TlsFacts =
            Snapshot(
                runCatching { s.peerCertificates }.getOrDefault(emptyList()),
                runCatching { s.localCertificates }.getOrDefault(emptyList()),
                runCatching { s.negotiatedAlpn }.getOrNull(),
                runCatching { s.keyExchangeGroup }.getOrNull(),
                runCatching { s.peerCertificateCompression }.getOrNull(),
                runCatching { s.earlyDataAccepted }.getOrNull(),
                runCatching { s.sniSelectedFor }.getOrNull(),
            )
    }
}
