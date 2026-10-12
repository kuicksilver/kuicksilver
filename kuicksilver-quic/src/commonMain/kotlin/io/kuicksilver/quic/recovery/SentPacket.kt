// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.recovery

import io.kuicksilver.quic.TimeMark

/** Packet number spaces (RFC 9000 section 12.3). */
internal enum class SpaceId { Initial, Handshake, Application }

/** What a sent packet carried, for retransmission on loss; reusable, grows once. */
internal class SentFrames {
    var flags: Int = 0

    /** Largest packet number acknowledged by an ACK frame in this packet, -1 when none. */
    var ackLargest: Long = -1
    var cryptoCount: Int = 0
    var cryptoLevel = IntArray(4)
    var cryptoOffset = LongArray(4)
    var cryptoLength = IntArray(4)
    var streamCount: Int = 0
    var streamId = LongArray(4)
    var streamOffset = LongArray(4)
    var streamLength = IntArray(4)
    var streamFin = BooleanArray(4)
    var idCount: Int = 0
    var idKind = IntArray(4)
    var idValue = LongArray(4)
    var idExtra = LongArray(4)
    var idExtra2 = LongArray(4)
    var pathChallenge: Long = 0

    /** Ids of DATAGRAM frames (RFC 9221) for the sender's acked/lost callbacks; never retransmitted. */
    var dgCount: Int = 0
    var dgId = LongArray(2)

    fun clear() {
        flags = 0
        ackLargest = -1
        cryptoCount = 0
        streamCount = 0
        idCount = 0
        pathChallenge = 0
        dgCount = 0
    }

    fun addDatagram(id: Long) {
        if (dgCount == dgId.size) dgId = dgId.copyOf(dgCount * 2)
        dgId[dgCount++] = id
    }

    fun addCrypto(
        level: Int,
        offset: Long,
        length: Int,
    ) {
        if (cryptoCount ==
            cryptoLevel.size
        ) {
            cryptoLevel = cryptoLevel.copyOf(cryptoCount * 2)
            cryptoOffset = cryptoOffset.copyOf(cryptoCount * 2)
            cryptoLength =
                cryptoLength.copyOf(cryptoCount * 2)
        }
        cryptoLevel[cryptoCount] = level
        cryptoOffset[cryptoCount] = offset
        cryptoLength[cryptoCount] = length
        cryptoCount++
    }

    fun addStream(
        id: Long,
        offset: Long,
        length: Int,
        fin: Boolean,
    ) {
        if (streamCount ==
            streamId.size
        ) {
            streamId = streamId.copyOf(streamCount * 2)
            streamOffset = streamOffset.copyOf(streamCount * 2)
            streamLength =
                streamLength.copyOf(streamCount * 2)
            streamFin = streamFin.copyOf(streamCount * 2)
        }
        streamId[streamCount] = id
        streamOffset[streamCount] = offset
        streamLength[streamCount] = length
        streamFin[streamCount] = fin
        streamCount++
    }

    /** Control frames keyed by an id: [kind] is one of the ID_* constants, [value] the stream id / sequence number, [extra] a code or limit. */
    fun addId(
        kind: Int,
        value: Long,
        extra: Long = 0,
        extra2: Long = 0,
    ) {
        if (idCount ==
            idKind.size
        ) {
            idKind = idKind.copyOf(idCount * 2)
            idValue = idValue.copyOf(idCount * 2)
            idExtra = idExtra.copyOf(idCount * 2)
            idExtra2 =
                idExtra2.copyOf(idCount * 2)
        }
        idKind[idCount] = kind
        idValue[idCount] = value
        idExtra[idCount] = extra
        idExtra2[idCount] = extra2
        idCount++
    }

    companion object {
        const val PING = 1
        const val HANDSHAKE_DONE = 2
        const val MAX_DATA = 4
        const val MAX_STREAMS_BIDI = 8
        const val MAX_STREAMS_UNI = 16
        const val DATA_BLOCKED = 32
        const val PATH_CHALLENGE = 64
        const val PATH_RESPONSE = 128
        const val NEW_TOKEN = 256
        const val STREAMS_BLOCKED_BIDI = 512
        const val STREAMS_BLOCKED_UNI = 1024
        const val PMTU_PROBE = 2048
        const val ID_MAX_STREAM_DATA = 1
        const val ID_RESET_STREAM = 2
        const val ID_STOP_SENDING = 3
        const val ID_NEW_CONNECTION_ID = 4
        const val ID_RETIRE_CONNECTION_ID = 5
        const val ID_STREAM_DATA_BLOCKED = 6
    }
}

/** A packet we sent and may still have to account for (RFC 9002 appendix A.1); pooled per space. */
internal class SentPacket {
    var pn: Long = 0
    var timeSent: TimeMark = TimeMark(0)
    var size: Int = 0
    var ackEliciting: Boolean = false
    var inFlight: Boolean = false

    /** The path the packet went out on (RTT samples count only for the active path; RFC 9002 section 5). */
    var pathId: Int = 0

    /** The congestion controller that counted this packet: a NAT rebinding moves the controller to the new path (`Paths.inheritFrom`), so the path id alone would credit the wrong window. */
    var cc: io.kuicksilver.quic.CongestionController? = null

    /** Sent with ECT(0) (RFC 9000 section 13.4.2). */
    var ecnMarked: Boolean = false

    val frames: SentFrames = SentFrames()

    internal fun reset() {
        pn = 0
        timeSent = TimeMark(0)
        size = 0
        ackEliciting = false
        inFlight = false
        pathId = 0
        cc = null
        ecnMarked =
            false
        frames.clear()
    }
}
