// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.wire

import io.kuicksilver.native.PacketBuffer

/** Receives decoded frames; data arguments are slices of the packet buffer and are valid only during the call. */
internal interface FrameHandler {
    fun padding(count: Int)

    fun ping()

    fun ack(ack: AckFrameView)

    fun resetStream(
        id: Long,
        code: Long,
        finalSize: Long,
    )

    fun stopSending(
        id: Long,
        code: Long,
    )

    fun crypto(
        offset: Long,
        data: PacketBuffer,
        off: Int,
        len: Int,
    )

    fun newToken(
        token: PacketBuffer,
        off: Int,
        len: Int,
    )

    fun stream(
        id: Long,
        offset: Long,
        data: PacketBuffer,
        off: Int,
        len: Int,
        fin: Boolean,
    )

    fun maxData(max: Long)

    fun maxStreamData(
        id: Long,
        max: Long,
    )

    fun maxStreams(
        bidi: Boolean,
        max: Long,
    )

    fun dataBlocked(limit: Long)

    fun streamDataBlocked(
        id: Long,
        limit: Long,
    )

    fun streamsBlocked(
        bidi: Boolean,
        limit: Long,
    )

    /** The 16-byte stateless reset token follows the connection ID in the same buffer at [resetTokenOff]. */
    fun newConnectionId(
        seq: Long,
        retirePriorTo: Long,
        cid: PacketBuffer,
        cidOff: Int,
        cidLen: Int,
        resetTokenOff: Int,
    )

    fun retireConnectionId(seq: Long)

    fun pathChallenge(data: Long)

    fun pathResponse(data: Long)

    fun connectionClose(
        application: Boolean,
        code: Long,
        frameType: Long,
        reason: PacketBuffer,
        off: Int,
        len: Int,
    )

    fun handshakeDone()

    fun datagram(
        data: PacketBuffer,
        off: Int,
        len: Int,
    )
}
