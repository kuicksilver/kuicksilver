// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.fuzz

import com.code_intelligence.jazzer.junit.FuzzTest
import io.kuicksilver.native.KslLoader
import io.kuicksilver.native.PacketBuffer
import io.kuicksilver.quic.wire.PacketHeaderCodec
import io.kuicksilver.quic.wire.PacketHeaderView
import io.kuicksilver.quic.wire.PacketType
import io.kuicksilver.quic.wire.VersionNegotiationPacket

/**
 * Fuzz target `packetHeader`: input = [short-header DCID length selector][datagram]. Every coalesced packet the
 * parser accepts must lie inside the datagram, and the walk must make progress.
 */
class PacketHeaderFuzzTest {
    private val hv = PacketHeaderView()

    @FuzzTest(maxDuration = "60s")
    fun packetHeader(data: ByteArray) {
        if (data.isEmpty()) return
        KslLoader.ensureLoaded()
        val shortDcid = (data[0].toInt() and 0xff) % 21
        val n = data.size - 1
        val b = PacketBuffer.allocate(maxOf(1, n))
        b.copyFrom(data, 1, 0, n)
        try {
            var off = 0
            while (off < n && PacketHeaderCodec.parse(b, off, n, shortDcid, hv)) {
                check(hv.dcidOff >= off && hv.dcidOff + hv.dcidLen <= n) { "DCID outside the datagram" }
                check(hv.scidOff >= off && hv.scidOff + hv.scidLen <= n) { "SCID outside the datagram" }
                check(hv.tokenLen >= 0 && hv.tokenOff + hv.tokenLen <= n) { "token outside the datagram" }
                check(
                    hv.pnOffset in off..hv.packetEnd && hv.packetEnd <= n,
                ) { "packet bounds ${hv.pnOffset}..${hv.packetEnd} outside $off..$n" }
                if (hv.isVersionNegotiation) VersionNegotiationPacket.versions(b, hv.pnOffset, hv.packetEnd)
                if (hv.type ==
                    PacketType.Retry
                ) {
                    check(hv.retryTagOff >= off && hv.retryTagOff + 16 <= n) { "Retry tag outside the datagram" }
                }
                if (hv.packetEnd <= off) break
                off = hv.packetEnd
            }
        } finally {
            b.close()
        }
    }
}
