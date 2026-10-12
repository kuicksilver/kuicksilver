// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.flow

import io.kuicksilver.quic.TransportError
import io.kuicksilver.quic.wire.QuicWireException
import io.kuicksilver.tls.TlsRole

/**
 * Stream count limits in both directions (RFC 9000 section 4.6): what the peer may open (checked before any
 * allocation) and what we may open. MAX_STREAMS goes out after half the concurrency limit closed.
 */
internal class StreamLimits(
    private val role: TlsRole,
    private val localMaxBidi: Long,
    private val localMaxUni: Long,
) {
    private val peerLimit = longArrayOf(localMaxBidi, localMaxUni) // [bidi, uni]: streams the peer may open
    private val peerOpened = LongArray(2)
    private val peerClosed = LongArray(2)
    private val closedAtUpdate = LongArray(2)
    private val ourLimit = LongArray(2) // streams we may open (peer's MAX_STREAMS)
    private val ourOpened = LongArray(2)
    private val blockedReportedAt = longArrayOf(-1, -1)

    private fun idx(bidi: Boolean) = if (bidi) 0 else 1

    private val peerBit: Long get() = if (role == TlsRole.Client) 1L else 0L

    fun peerStreamsOpened(bidi: Boolean): Long = peerOpened[idx(bidi)]

    fun peerMaxStreams(bidi: Boolean): Long = ourLimit[idx(bidi)]

    /** The stream count we allow the peer (what our MAX_STREAMS said last). */
    fun peerMaxStreamsGranted(bidi: Boolean): Long = peerLimit[idx(bidi)]

    /** A frame named a peer-initiated stream [id]: opens it (and every lower one of its kind) or fails with STREAM_LIMIT_ERROR / STREAM_STATE_ERROR. */
    fun onPeerStream(id: Long) {
        if (id and 0x1L != peerBit) throw QuicWireException(TransportError.STREAM_STATE_ERROR, 0, "stream $id is locally initiated")
        val bidi = id and 0x2L == 0L
        val index = id ushr 2
        if (index >=
            peerLimit[idx(bidi)]
        ) {
            throw QuicWireException(TransportError.STREAM_LIMIT_ERROR, 0, "stream $id exceeds the limit of ${peerLimit[idx(bidi)]}")
        }
        if (index + 1 > peerOpened[idx(bidi)]) peerOpened[idx(bidi)] = index + 1
    }

    fun localOpened(bidi: Boolean): Long = ourOpened[idx(bidi)]

    fun canOpenLocal(bidi: Boolean): Boolean = ourOpened[idx(bidi)] < ourLimit[idx(bidi)]

    fun onLocalOpened(bidi: Boolean) {
        ourOpened[idx(bidi)]++
    }

    /** True when the limit grew. */
    fun onPeerMaxStreams(
        bidi: Boolean,
        max: Long,
    ): Boolean {
        if (max <=
            ourLimit[idx(bidi)]
        ) {
            return false
        }
        ourLimit[idx(bidi)] = max
        return true
    }

    /** After a rejected 0-RTT: the server's new MAX_STREAMS replaces the remembered one, even when lower. */
    fun resetPeerMaxStreams(
        bidi: Boolean,
        max: Long,
    ) {
        ourLimit[idx(bidi)] = max
        blockedReportedAt[idx(bidi)] = -1
    }

    /** A peer-initiated stream closed; returns the new MAX_STREAMS value when it is time to send one, else -1. */
    fun onPeerStreamClosed(bidi: Boolean): Long {
        val i = idx(bidi)
        peerClosed[i]++
        val concurrency = if (bidi) localMaxBidi else localMaxUni
        if (peerClosed[i] - closedAtUpdate[i] < (concurrency + 1) / 2) return -1
        closedAtUpdate[i] = peerClosed[i]
        peerLimit[i] = peerClosed[i] + concurrency
        return peerLimit[i]
    }

    /** The limit to report in STREAMS_BLOCKED the first time we are blocked at it, else -1. */
    fun takeStreamsBlocked(bidi: Boolean): Long {
        val i = idx(bidi)
        if (canOpenLocal(bidi) ||
            blockedReportedAt[i] == ourLimit[i]
        ) {
            return -1
        }
        blockedReportedAt[i] = ourLimit[i]
        return ourLimit[i]
    }
}
