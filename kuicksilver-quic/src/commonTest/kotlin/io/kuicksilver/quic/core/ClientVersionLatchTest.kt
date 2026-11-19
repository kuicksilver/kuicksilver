// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.core

import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.native.KslLoader
import io.kuicksilver.native.PacketBuffer
import io.kuicksilver.native.of
import io.kuicksilver.native.toByteArray
import io.kuicksilver.quic.ConnectionCore
import io.kuicksilver.quic.CoreFixtures
import io.kuicksilver.quic.CorePair
import io.kuicksilver.quic.Ecn
import io.kuicksilver.quic.VersionProfile
import io.kuicksilver.quic.crypto.PacketProtection
import io.kuicksilver.quic.ksl
import io.kuicksilver.quic.quicConfig
import io.kuicksilver.tls.TlsRole
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * RFC 9369 section 4.1: "The client learns the negotiated version by observing the first long header Version field that differs
 * from the original version", and once it has, it "SHOULD send subsequent Initial packets using that version"; "If the client
 * receives a CRYPTO frame from the server in the original version, that indicates that the negotiated version is equal to the
 * original version". The client switched its Initial keys for every server Initial of another configured version until it had
 * Handshake keys, before the packet was even authenticated: a packet that failed to decrypt left the switch in place (RFC 9000
 * section 12.2: such a packet is discarded, it changes nothing), and a later Initial of the original version switched back.
 */
@OptIn(ExperimentalKuicksilverApi::class)
class ClientVersionLatchTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    private val v1v2 = quicConfig { versions = listOf(VersionProfile.V1, VersionProfile.V2) }
    private val v2v1 = quicConfig { versions = listOf(VersionProfile.V2, VersionProfile.V1) }

    /**
     * An ACK-only server Initial of [version] to [client], from the client's own DCID (so it fixes no SCID: the real server's
     * packets still count), sealed with that version's server Initial keys, or with garbage in place of the tag ([sealed] false).
     */
    private fun ackOnlyInitial(
        client: ConnectionCore,
        version: VersionProfile,
        pn: Long,
        sealed: Boolean = true,
    ): ByteArray {
        val dcid = client.localCid.toByteArray()
        val scid = client.remoteCid.toByteArray()
        val payload = byteArrayOf(0x02, 0, 0, 0, 0) + ByteArray(30) // ACK of packet 0, PADDING
        val length = 2 + payload.size + 16
        val v = version.version
        val first = 0xc1 or (version.bitsOf(io.kuicksilver.quic.wire.PacketType.Initial) shl 4)
        val header =
            byteArrayOf(first.toByte(), (v ushr 24).toByte(), (v ushr 16).toByte(), (v ushr 8).toByte(), v.toByte()) +
                byteArrayOf(dcid.size.toByte()) + dcid + byteArrayOf(scid.size.toByte()) + scid +
                byteArrayOf(0, (0x40 or (length shr 8)).toByte(), length.toByte())
        val pnOffset = header.size
        val bytes = header + ByteArray(length)
        payload.copyInto(bytes, pnOffset + 2)
        val (r, w) = ksl.initialProtectors(client.initialKeyCid.toByteArray(), v, TlsRole.Server)
        val buf = PacketBuffer.of(bytes)
        try {
            val end = PacketProtection.protect(buf, 0, pnOffset, 2, pnOffset + 2 + payload.size, pn, w, ByteArray(5))
            val out = buf.toByteArray(end)
            if (!sealed) out[out.size - 1] = (out[out.size - 1].toInt() xor 0x5a).toByte()
            return out
        } finally {
            buf.close()
            r.close()
            w.close()
        }
    }

    private fun feed(
        p: CorePair,
        d: ByteArray,
    ) {
        val b = PacketBuffer.of(d)
        try {
            p.client.handleDatagram(b, d.size, CoreFixtures.serverAddr, Ecn.NotEct, p.now)
        } finally {
            b.close()
        }
    }

    @Test fun negative_anInitialThatFailsToDecryptChangesNoVersion() {
        val p = CorePair(clientQuic = v1v2, serverQuic = v2v1, crypto = ksl)
        p.use { _ ->
            p.filterToClient = { _, _ -> false }
            p.step()
            feed(p, ackOnlyInitial(p.client, VersionProfile.V2, 5, sealed = false))
            assertEquals(VersionProfile.V1, p.client.version, "a v2 Initial that does not decrypt is discarded and switches nothing")
            p.filterToClient = { _, _ -> true }
            assertTrue(p.handshake())
            assertEquals(VersionProfile.V2, p.client.version)
        }
    }

    @Test fun negative_aSpoofedInitialOfTheOriginalVersionDoesNotSwitchBack() {
        val p = CorePair(clientQuic = v1v2, serverQuic = v2v1, crypto = ksl)
        p.use { _ ->
            // the real server's first flight (pn 0 and 1, v2: it negotiated v2) is held back while the spoofed Initials arrive;
            // they take pn 2 and 3, which the server has not used, and the pair is not run on (their ACKs would reach it)
            val held = ArrayList<ByteArray>()
            p.filterToClient = { _, b ->
                held += b
                false
            }
            for (i in 0 until 4) if (held.isEmpty()) p.step()
            assertTrue(held.isNotEmpty(), "the server answered")
            feed(p, ackOnlyInitial(p.client, VersionProfile.V2, 2))
            assertEquals(VersionProfile.V2, p.client.version, "the first server Initial of another version gives the negotiated one")
            feed(p, ackOnlyInitial(p.client, VersionProfile.V1, 3))
            assertEquals(VersionProfile.V2, p.client.version, "a later Initial of the original version does not switch back")
            for (d in held) feed(p, d)
            assertTrue(p.client.hasHandshakeKeys, "the server's v2 ServerHello is still taken")
            assertEquals(VersionProfile.V2, p.client.version)
        }
    }
}
