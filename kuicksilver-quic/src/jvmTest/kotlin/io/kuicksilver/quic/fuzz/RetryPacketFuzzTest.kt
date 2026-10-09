// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.fuzz

import com.code_intelligence.jazzer.junit.FuzzTest
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.native.PacketBuffer
import io.kuicksilver.quic.NullCryptoProvider
import io.kuicksilver.quic.VersionProfile
import io.kuicksilver.quic.wire.ConnectionId
import io.kuicksilver.quic.wire.RetryPacket

/**
 * Fuzz target, RFC 9000 section 17.2.5: a client that sent its Initial receives a Retry shaped by the input, then its
 * Initial with that token reaches a server endpoint whose token check must reject it statelessly. Input:
 * flags (bit 0 = corrupt the integrity tag, bit 1 = v2), scid length, scid, token bytes.
 */
@OptIn(ExperimentalKuicksilverApi::class)
class RetryPacketFuzzTest {
    @FuzzTest(maxDuration = "60s")
    fun retryPacket(data: ByteArray) {
        if (data.size < 2) return
        CoreDriver().use { d ->
            val c = d.client()
            d.service(c)
            val flags = data[0].toInt()
            val scidLen = (data[1].toInt() and 0xff) % 21
            val scid = ConnectionId(ByteArray(scidLen) { if (2 + it < data.size) data[2 + it] else 0 })
            val token = if (data.size > 2 + scidLen) data.copyOfRange(2 + scidLen, data.size) else ByteArray(0)
            val profile = if (flags and 2 != 0) VersionProfile.V2 else VersionProfile.V1
            val buf = PacketBuffer.allocate(1500)
            try {
                val n =
                    RetryPacket.write(
                        buf,
                        profile,
                        c.localCid,
                        scid,
                        token.copyOf(minOf(token.size, 1200)),
                        c.odcid,
                        NullCryptoProvider,
                        flags ushr 4,
                    )
                val bytes = ByteArray(n)
                buf.copyTo(bytes, 0, 0, n)
                if (flags and 1 != 0) bytes[n - 1] = (bytes[n - 1].toInt() xor 0x5a).toByte()
                d.deliver(c, bytes, fuzzServerAddr)
            } finally {
                buf.close()
            }
            val ep = d.serverEndpoint()
            // the client's Initial with the fuzzed token: INVALID_TOKEN or a drop, never a throw
            for (dg in d.service(c)) d.deliver(ep, dg, fuzzClientAddr)
            d.service(ep)
            d.tick()
            d.service(c)
            d.service(ep)
        }
    }
}
