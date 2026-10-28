// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(ExperimentalKuicksilverApi::class)

package io.kuicksilver.quic.core

import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.native.PacketBuffer
import io.kuicksilver.quic.ConnectionCore
import io.kuicksilver.quic.ConnectionCore.CloseFrame
import io.kuicksilver.quic.ConnectionEvent
import io.kuicksilver.quic.ConnectionState
import io.kuicksilver.quic.Initiator
import io.kuicksilver.quic.QuicException
import io.kuicksilver.quic.TimeMark
import io.kuicksilver.quic.TransportError
import io.kuicksilver.quic.wire.QuicWireException
import io.kuicksilver.tls.TlsException

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

internal fun ConnectionCore.enterClosing(reason: QuicException.ConnectionLost) {
    state = ConnectionState.Closing
    closedReason = reason
    closeSent =
        false
    timers.closeDeadline = now + pto() * 3
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
    events += ConnectionEvent.Closed(reason)
    qlog?.connectionClosed(reason, now)
    markClosed()
}

/** The terminal state: every native resource of this connection (TLS session, packet protectors) is freed here and only here. */
internal fun ConnectionCore.markClosed() {
    state = ConnectionState.Closed
    release()
}

internal fun ConnectionCore.release() {
    if (released) return
    released = true
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
    qlog?.close()
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
    state = ConnectionState.Draining
    timers.closeDeadline = now + pto() * 3
    var reason = reasonBytes.decodeToString() // lossy UTF-8; keep its encoding within 1 KiB
    while (reason.encodeToByteArray().size > 1024) reason = reason.dropLast(1)
    val cause: Throwable? =
        if (!application &&
            code in 0x100..0x1ff
        ) {
            TlsException.AlertReceived((code - 0x100).toInt(), "TLS alert ${code - 0x100}")
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
 * RFC 9000 section 10.3.1: a datagram that could not be processed and ends with the reset token of a peer ID we used
 * is a Stateless Reset — the connection enters Draining with [QuicException.ConnectionLost.StatelessReset] and sends
 * nothing more. Anything else is ignored and, with [countInvalid], counted in `ConnectionStats.invalidResets`: a datagram
 * whose first packet was not ours or did not authenticate. One led by a packet of a space whose keys we discarded is
 * checked but not counted.
 */
internal fun ConnectionCore.checkStatelessReset(
    data: PacketBuffer,
    length: Int,
    now: TimeMark,
    countInvalid: Boolean = true,
): Boolean {
    if (state == ConnectionState.Draining || state == ConnectionState.Closed ||
        length < io.kuicksilver.quic.endpoint.StatelessReset.MIN_SIZE
    ) {
        return false
    }
    if (!cids.matchesPeerToken(data, length)) {
        if (countInvalid) invalidResets++
        return false
    }
    this.now = now
    state = ConnectionState.Draining
    timers.closeDeadline = now + pto() * 3
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
internal fun ConnectionCore.glitchSummary(): String {
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
