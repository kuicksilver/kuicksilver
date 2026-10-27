// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.http3.runtime

import io.ktor.utils.io.readByte
import io.ktor.utils.io.writeFully
import io.kuicksilver.http3.frame.FrameHeaders
import io.kuicksilver.http3.frame.FrameType
import io.kuicksilver.http3.frame.SettingsCodec
import io.kuicksilver.http3.frame.StreamType
import io.kuicksilver.http3.frame.VarInt
import io.kuicksilver.http3.qpack.QpackEncoder
import io.kuicksilver.quic.QuicConnection
import io.kuicksilver.quic.QuicException
import io.kuicksilver.quic.QuicStream

/** A hand-driven HTTP/3 peer on a raw QUIC connection, for protocol-violation tests. */
internal class RawPeer(
    val quic: QuicConnection,
) {
    private val qpack = QpackEncoder()
    lateinit var control: QuicStream

    suspend fun openControl(
        settings: List<Pair<Long, Long>> = emptyList(),
        sendSettings: Boolean = true,
    ): QuicStream {
        control = quic.openUni()
        control.output.writeFully(VarInt.encode(StreamType.CONTROL))
        if (sendSettings) control.output.writeFully(FrameHeaders.frame(FrameType.SETTINGS, SettingsCodec.encode(settings)))
        peerMayHaveClosed { control.output.flush() }
        return control
    }

    suspend fun uni(
        type: Long,
        body: ByteArray = ByteArray(0),
        fin: Boolean = false,
    ): QuicStream {
        val s = quic.openUni()
        s.output.writeFully(VarInt.encode(type) + body)
        peerMayHaveClosed { if (fin) s.output.flushAndClose() else s.output.flush() }
        return s
    }

    fun headers(
        streamId: Long,
        fields: List<Pair<String, String>>,
    ): ByteArray = FrameHeaders.frame(FrameType.HEADERS, qpack.encode(streamId, fields))

    fun data(payload: ByteArray): ByteArray = FrameHeaders.frame(FrameType.DATA, payload)

    fun frame(
        type: Long,
        payload: ByteArray,
    ): ByteArray = FrameHeaders.frame(type, payload)
}

/**
 * Runs a write of a protocol-violation test, tolerating the peer's reaction arriving first: these tests provoke a
 * STOP_SENDING or a connection close and assert it afterwards, and on a fast host it can land before the flush
 * returns (seen on GitHub's Linux runners). Any other failure propagates.
 */
internal suspend fun peerMayHaveClosed(write: suspend () -> Unit) {
    try {
        write()
    } catch (e: Throwable) {
        val byPeer =
            generateSequence(e) { it.cause }.any {
                it is QuicException.StreamError.Stopped || it is QuicException.ConnectionLost
            }
        if (!byPeer) throw e
    }
}

internal suspend fun QuicStream.readVarInt(): Long {
    val first = input.readByte()
    val n = VarInt.encodedLength(first)
    val b = ByteArray(n)
    b[0] = first
    for (i in 1 until n) b[i] = input.readByte()
    return VarInt.read(b, 0, n)
}

/** The next bidirectional stream the peer opened (acceptStream also returns its unidirectional ones). */
internal suspend fun QuicConnection.acceptBidi(): QuicStream {
    while (true) {
        val s = acceptStream()
        if (s.id and 2L == 0L) return s
    }
}

internal val GET = listOf(":method" to "GET", ":scheme" to "https", ":authority" to "server.test", ":path" to "/")

internal val POST = listOf(":method" to "POST", ":scheme" to "https", ":authority" to "server.test", ":path" to "/")
