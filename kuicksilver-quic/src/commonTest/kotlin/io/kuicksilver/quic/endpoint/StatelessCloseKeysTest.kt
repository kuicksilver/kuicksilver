// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.endpoint

import io.kuicksilver.native.Ksl
import io.kuicksilver.native.KslConst
import io.kuicksilver.native.KslLoader
import io.kuicksilver.native.PacketBuffer
import io.kuicksilver.quic.TransportError
import io.kuicksilver.quic.VersionProfile
import io.kuicksilver.quic.wire.ConnectionId
import io.kuicksilver.tls.KslQuicCrypto
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals

/**
 * A stateless Initial CONNECTION_CLOSE (INVALID_TOKEN, CONNECTION_REFUSED at a full accept queue) derives both Initial keys
 * and must free both: the soak harness found one native key leaked per refused connection.
 */
class StatelessCloseKeysTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    @Test fun statelessCloseFreesBothInitialKeys() {
        val out = PacketBuffer.allocate(1500)
        try {
            val before = Ksl.liveObjects()[KslConst.LIVE_KEY]
            repeat(10) {
                StatelessClose.writeInitialClose(
                    out,
                    VersionProfile.V1,
                    ConnectionId(ByteArray(8) { b -> (it + b).toByte() }),
                    ConnectionId(ByteArray(8) { b -> (it * 3 + b).toByte() }),
                    TransportError.CONNECTION_REFUSED,
                    KslQuicCrypto,
                )
            }
            assertEquals(before, Ksl.liveObjects()[KslConst.LIVE_KEY], "native keys left by 10 stateless closes")
        } finally {
            out.close()
        }
    }
}
