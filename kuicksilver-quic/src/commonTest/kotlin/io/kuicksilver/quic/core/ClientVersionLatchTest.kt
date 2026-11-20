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

    private fun recordVersions(into: MutableList<Int>): (Int, ByteArray) -> Boolean =
        { _, b ->
            if (b[0].toInt() and 0x80 != 0) {
                into += ((b[1].toInt() and 0xff) shl 24) or ((b[2].toInt() and 0xff) shl 16) or ((b[3].toInt() and 0xff) shl 8) or
                    (b[4].toInt() and 0xff)
            }
            true
        }

    /** RFC 9369 section 4.1 / RFC 9368 section 2.3: ACK-only server Initials in the original version come before the switch. */
    @Test fun originalVersionAckOnlyInitialsBeforeTheSwitchFixNothing() {
        val p = CorePair(clientQuic = v1v2, serverQuic = v2v1, crypto = ksl)
        p.use { _ ->
            val held = ArrayList<ByteArray>()
            p.filterToClient = { _, b ->
                held += b
                false
            }
            for (i in 0 until 4) if (held.isEmpty()) p.step()
            // the server acknowledged the ClientHello in v1 before it read the transport parameters: two such Initials
            feed(p, ackOnlyInitial(p.client, VersionProfile.V1, 2))
            feed(p, ackOnlyInitial(p.client, VersionProfile.V1, 3))
            assertEquals(VersionProfile.V1, p.client.version)
            for (d in held) feed(p, d)
            assertTrue(p.client.hasHandshakeKeys, "the v2 ServerHello that follows is taken")
            assertEquals(VersionProfile.V2, p.client.version)
        }
    }

    /** A HelloRetryRequest with a compatible upgrade: the retry and the ServerHello both come in the negotiated version. */
    @Test fun helloRetryRequestWithAnUpgrade() {
        val groups = { names: List<String> -> io.kuicksilver.tls.KeyExchangeGroups(names) }
        val serverVersions = ArrayList<Int>()
        val p =
            CorePair(
                clientQuic = v1v2,
                serverQuic = v2v1,
                crypto = ksl,
                clientTls =
                    CoreFixtures.client {
                        keyExchangeGroups =
                            groups(listOf(io.kuicksilver.tls.KeyExchangeGroups.X25519, io.kuicksilver.tls.KeyExchangeGroups.SECP256R1))
                    },
                serverTls =
                    CoreFixtures.server {
                        keyExchangeGroups =
                            groups(listOf(io.kuicksilver.tls.KeyExchangeGroups.SECP384R1, io.kuicksilver.tls.KeyExchangeGroups.SECP256R1))
                    },
            )
        p.filterToClient = recordVersions(serverVersions)
        p.use { _ ->
            assertTrue(p.handshake(), "the handshake completes after the retry")
            assertEquals(VersionProfile.V2, p.client.version)
            assertEquals(VersionProfile.V2, p.server!!.version)
            assertEquals(io.kuicksilver.tls.KeyExchangeGroups.SECP256R1, p.client.keyExchangeGroup, "a HelloRetryRequest was made")
            assertTrue(serverVersions.all { it == VersionProfile.V2.version }, "the retry is in the negotiated version: $serverVersions")
        }
    }

    /** The server's first v2 Initial is lost: its retransmission at the PTO is the first v2 packet the client sees. */
    @Test fun aLostFirstUpgradedInitialIsMadeUpByItsRetransmission() {
        val p = CorePair(clientQuic = v1v2, serverQuic = v2v1, crypto = ksl)
        p.use { _ ->
            var dropped = 0
            p.filterToClient = { _, _ -> if (dropped < 1) false.also { dropped++ } else true }
            assertTrue(p.handshake())
            assertEquals(1, dropped)
            assertEquals(VersionProfile.V2, p.client.version)
            assertEquals(VersionProfile.V2, p.server!!.version)
        }
    }

    /**
     * A Version Negotiation restart starts a new attempt whose first flight is in the version it chose: the version a later
     * server Initial fixes is measured against that one, not against the abandoned first flight's.
     */
    @Test fun negative_aRestartAfterVersionNegotiationMeasuresTheSwitchFromItsOwnFlight() {
        val v2First = quicConfig { versions = listOf(VersionProfile.V2, VersionProfile.V1) }
        val p = CorePair(clientQuic = v2First, serverQuic = v2v1, crypto = ksl)
        p.use { _ ->
            p.filterToClient = { _, _ -> false }
            p.filterToServer = { _, _ -> false }
            p.step()
            assertEquals(VersionProfile.V2, p.client.version)
            // a Version Negotiation that offers v1 only: the client restarts in v1
            val dcid = p.client.localCid.toByteArray()
            val scid = p.client.remoteCid.toByteArray()
            val vn =
                byteArrayOf(0xc0.toByte(), 0, 0, 0, 0, dcid.size.toByte()) + dcid + byteArrayOf(scid.size.toByte()) + scid +
                    byteArrayOf(0, 0, 0, 1)
            feed(p, vn)
            assertEquals(VersionProfile.V1, p.client.version, "restarted in v1")
            p.step() // the new first flight, in v1
            feed(p, ackOnlyInitial(p.client, VersionProfile.V2, 0))
            assertEquals(VersionProfile.V2, p.client.version, "an Initial of another version than the new flight's")
            feed(p, ackOnlyInitial(p.client, VersionProfile.V1, 1))
            assertEquals(VersionProfile.V2, p.client.version, "fixed: an Initial of the restarted flight's version does not switch back")
        }
    }

    /** The coalesced long-header packets of [d] (RFC 9000 section 12.2), each as its own byte array. */
    private fun splitCoalesced(d: ByteArray): List<ByteArray> {
        val out = ArrayList<ByteArray>()
        var p = 0

        fun varint(): Long {
            val len = 1 shl ((d[p].toInt() and 0xff) ushr 6)
            var v = (d[p].toLong() and 0x3f)
            for (k in 1 until len) v = (v shl 8) or (d[p + k].toLong() and 0xff)
            p += len
            return v
        }
        while (p < d.size && d[p].toInt() and 0x80 != 0) {
            val start = p
            // the server's flight is all v2 here
            val initial = (d[p].toInt() ushr 4 and 0x03) == VersionProfile.V2.bitsOf(io.kuicksilver.quic.wire.PacketType.Initial)
            p += 5
            p += 1 + (d[p].toInt() and 0xff)
            p += 1 + (d[p].toInt() and 0xff)
            if (initial) {
                val token = varint().toInt() // read first: `p += varint()` would add to p as it was before the read
                p += token
            }
            val len = varint().toInt()
            p += len
            out += d.copyOfRange(start, p)
        }
        return out
    }

    /**
     * A server Handshake packet that arrives before the server's first Initial (reordered) is held until the Handshake keys come,
     * whatever its version, and processed then; before 0.3.0's version check it was held too.
     */
    @Test fun aHandshakePacketBeforeTheFirstServerInitialIsHeld() {
        val p = CorePair(clientQuic = v1v2, serverQuic = v2v1, crypto = ksl)
        p.use { _ ->
            val held = ArrayList<ByteArray>()
            p.filterToClient = { _, b ->
                held += b
                false
            }
            for (i in 0 until 4) if (held.isEmpty()) p.step()
            val packets = held.flatMap { splitCoalesced(it) }
            val initials =
                packets.filter {
                    (it[0].toInt() ushr 4 and 0x03) ==
                        VersionProfile.V2.bitsOf(io.kuicksilver.quic.wire.PacketType.Initial)
                }
            val others = packets - initials.toSet()
            assertTrue(
                initials.isNotEmpty() && others.isNotEmpty(),
                "the server's flight has Initial and Handshake packets: ${held.map {
                    it.size
                }} ${packets.map {
                    "${(it[0].toInt() and 0xff).toString(
                        16,
                    )}/${it.size}"
                }}",
            )
            for (h in others) feed(p, h)
            assertEquals(others.size, p.client.stats.undecryptableBuffered, "the Handshake packets wait for their keys")
            assertEquals(VersionProfile.V1, p.client.version, "a Handshake packet switches nothing")
            for (i in initials) feed(p, i)
            assertTrue(p.client.hasHandshakeKeys)
            assertEquals(0, p.client.stats.undecryptableBuffered, "the held packets were processed with the keys")
            assertEquals(VersionProfile.V2, p.client.version)
        }
    }
}
