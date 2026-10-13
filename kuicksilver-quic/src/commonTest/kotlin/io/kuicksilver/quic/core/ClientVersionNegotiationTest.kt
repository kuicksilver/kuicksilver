// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.core

import io.kuicksilver.annotations.DelicateKuicksilverApi
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.native.KslLoader
import io.kuicksilver.native.PacketBuffer
import io.kuicksilver.native.of
import io.kuicksilver.native.toByteArray
import io.kuicksilver.quic.CoreFixtures
import io.kuicksilver.quic.CorePair
import io.kuicksilver.quic.Ecn
import io.kuicksilver.quic.QuicException
import io.kuicksilver.quic.VersionProfile
import io.kuicksilver.quic.ksl
import io.kuicksilver.quic.quicConfig
import io.kuicksilver.quic.wire.PacketHeaderCodec
import io.kuicksilver.quic.wire.PacketHeaderView
import io.kuicksilver.quic.wire.VersionNegotiationPacket
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds

@OptIn(ExperimentalKuicksilverApi::class, DelicateKuicksilverApi::class)
class ClientVersionNegotiationTest {
    // ---- K2 review leftover (VN restart kept the first flight in bytesInFlight) ----
    @Test fun vnRestartResetsCongestionState() {
        val p = CorePair(clientQuic = quicConfig { versions = listOf(VersionProfile.V2, VersionProfile.V1) }, crypto = ksl)
        var fed = false
        p.filterToServer = { _, b ->
            if (!fed) {
                fed = true
                feed(p, vn(b, 0x00000001))
                false
            } else {
                true
            }
        }
        try {
            assertTrue(p.handshake())
            p.runUntil(limit = 2.seconds) { false }
            assertEquals(0L, p.client.stats.bytesInFlight, "the first flight of the abandoned version is not counted forever")
        } finally {
            p.close()
        }
    }

    @BeforeTest fun load() = KslLoader.ensureLoaded()

    /** A Version Negotiation packet answering the client's Initial [initial] with [versions]. */
    private fun vn(
        initial: ByteArray,
        vararg versions: Int,
    ): ByteArray {
        val b = PacketBuffer.of(initial)
        val out = PacketBuffer.allocate(1200)
        try {
            val v = PacketHeaderView()
            check(PacketHeaderCodec.parse(b, 0, initial.size, 8, v))
            val n = VersionNegotiationPacket.write(out, b, v.scidOff, v.scidLen, b, v.dcidOff, v.dcidLen, versions, 0x12, 1200)
            return out.toByteArray(n)
        } finally {
            b.close()
            out.close()
        }
    }

    private fun feed(
        p: CorePair,
        bytes: ByteArray,
    ) {
        val b = PacketBuffer.of(bytes)
        try {
            p.client.handleDatagram(b, bytes.size, CoreFixtures.serverAddr, Ecn.NotEct, p.now)
        } finally {
            b.close()
        }
        p.drainEvents(p.client, p.clientEvents)
    }

    @Test fun vnWithoutOurVersionFails() {
        val p = CorePair(crypto = ksl)
        p.filterToServer = { _, _ -> false }
        try {
            p.step()
            feed(p, vn(p.lastClientInitial!!, 0x0a0a0a0a, 0x1a2a3a4a))
            val r = p.closedReason(p.clientEvents)
            assertIs<QuicException.ConnectionLost.VersionNegotiation>(r)
            assertEquals(listOf(0x0a0a0a0a, 0x1a2a3a4a), r.offered)
            assertEquals(listOf(1), r.supported)
        } finally {
            p.close()
        }
    }

    @Test fun vnRestartsWithOtherConfiguredVersion() {
        val p = CorePair(clientQuic = quicConfig { versions = listOf(VersionProfile.V2, VersionProfile.V1) }, crypto = ksl)
        var fed = false
        p.filterToServer = { _, b ->
            if (!fed) {
                fed = true
                feed(p, vn(b, 0x00000001))
                false
            } else {
                true
            }
        }
        try {
            assertTrue(p.handshake(), "client=${p.closedReason(p.clientEvents)} server=${p.closedReason(p.serverEvents)}")
            assertEquals(VersionProfile.V1, p.client.version)
            assertEquals(VersionProfile.V1, p.server!!.version)
            assertNull(p.closedReason(p.clientEvents))
        } finally {
            p.close()
        }
    }

    @Test fun negative_vnListsOwnVersion() {
        val p = CorePair(crypto = ksl)
        try {
            p.step()
            feed(p, vn(p.lastClientInitial!!, 0x00000001, 0x0a0a0a0a))
            assertNull(p.closedReason(p.clientEvents))
            assertEquals(VersionProfile.V1, p.client.version)
            assertTrue(p.handshake())
        } finally {
            p.close()
        }
    }

    @Test fun negative_versionNegotiationAfterInitial() {
        val p = CorePair(crypto = ksl)
        try {
            assertTrue(p.runUntil { p.client.hasHandshakeKeys })
            feed(p, vn(p.lastClientInitial!!, 0x0a0a0a0a))
            assertNull(p.closedReason(p.clientEvents))
            assertTrue(p.handshake())
        } finally {
            p.close()
        }
    }

    /** RFC 9000 section 6.2: a client that already acted on a Version Negotiation packet discards any later one; a forged second VN must not end the restarted attempt. */
    @Test fun negative_secondVnIgnored() {
        val p = CorePair(clientQuic = quicConfig { versions = listOf(VersionProfile.V2, VersionProfile.V1) }, crypto = ksl)
        var n = 0
        p.filterToServer =
            { _, b ->
                when (n++) {
                    0 -> {
                        feed(p, vn(b, 0x00000001))
                        false
                    }

                    1 -> {
                        feed(p, vn(b, 0x0a0a0a0a))
                        true
                    }

                    else -> {
                        true
                    }
                }
            }
        try {
            assertTrue(p.handshake(), "client=${p.closedReason(p.clientEvents)}")
            assertEquals(VersionProfile.V1, p.client.version)
            assertNull(p.closedReason(p.clientEvents))
        } finally {
            p.close()
        }
    }

    /**
     * Review finding 15, RFC 9000 section 6.2: "A client MUST discard any Version Negotiation packet if it has received and
     * successfully processed any other packet". A processed Retry counts: a VN echoing the original IDs afterwards used to end the
     * connection (or restart it with the Retry state left over).
     */
    @Test fun negative_versionNegotiationAfterRetryIgnored() {
        val p = CorePair(crypto = ksl)
        p.filterToServer = { _, _ -> false }
        try {
            p.step()
            val first = p.lastClientInitial!!
            p.client.onRetry(io.kuicksilver.quic.wire.ConnectionId(ByteArray(8) { 0x42 }), ByteArray(16) { 7 })
            feed(p, vn(first, 0x0a0a0a0a))
            assertNull(p.closedReason(p.clientEvents), "the Version Negotiation after a Retry is discarded")
            assertNull(p.client.receivedVnVersions)
        } finally {
            p.close()
        }
    }
}
