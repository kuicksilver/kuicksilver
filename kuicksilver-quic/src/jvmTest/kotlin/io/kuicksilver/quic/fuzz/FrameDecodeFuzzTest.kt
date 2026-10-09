// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.fuzz

import com.code_intelligence.jazzer.junit.FuzzTest
import io.kuicksilver.native.KslLoader
import io.kuicksilver.native.PacketBuffer
import io.kuicksilver.quic.CollectingHandler
import io.kuicksilver.quic.wire.AckFrameView
import io.kuicksilver.quic.wire.FrameDecoder
import io.kuicksilver.quic.wire.PacketType
import io.kuicksilver.quic.wire.WireReader

/** Fuzz target `frameDecode`: input = [packet type selector][packet payload]. */
class FrameDecodeFuzzTest {
    private val types = arrayOf(PacketType.Initial, PacketType.ZeroRtt, PacketType.Handshake, PacketType.OneRtt)
    private val ackView = AckFrameView()

    @FuzzTest(maxDuration = "60s")
    fun frameDecode(data: ByteArray) {
        if (data.isEmpty()) return
        KslLoader.ensureLoaded()
        val type = types[(data[0].toInt() and 0xff) % types.size]
        val n = data.size - 1
        val b = PacketBuffer.allocate(maxOf(1, n))
        b.copyFrom(data, 1, 0, n)
        try {
            // CollectingHandler copies every slice, so an out-of-bounds slice fails the target
            wireContract { FrameDecoder.decode(WireReader(b, 0, n), type, CollectingHandler(), ackView) }
        } finally {
            b.close()
        }
    }
}
