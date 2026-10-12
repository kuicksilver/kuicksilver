// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.tls

import io.kuicksilver.native.KslLoader
import io.kuicksilver.native.PacketBuffer
import io.kuicksilver.native.of
import io.kuicksilver.native.toByteArray
import kotlinx.coroutines.runBlocking
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFails
import kotlin.test.assertFailsWith
import kotlin.test.assertIs
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

internal object Fixtures {
    val tp = byteArrayOf(0x01, 0x02, 0x67, 0x10)
    val testCa = Certificate(TestCerts.testCa)

    fun client(
        trust: TrustConfig = TrustConfig.AnchoredCa(listOf(testCa)),
        name: String? = "server.test",
        block: TlsConfig.Builder.() -> Unit = {
        },
    ): TlsConfig =
        tlsConfig(TlsRole.Client) {
            alpn = listOf("h3")
            serverName = name
            this.trust = trust
            block()
        }

    fun server(
        chain: List<ByteArray> = listOf(TestCerts.server),
        key: ByteArray = TestCerts.serverKey,
        block: TlsConfig.Builder.() -> Unit = {
        },
    ): TlsConfig =
        tlsConfig(TlsRole.Server) {
            alpn = listOf("h3")
            identity = TlsIdentity.fromDer(chain, key.copyOf())
            block()
        }
}

/** Shuttles CRYPTO between two sessions in memory. */
internal class Pump(
    val c: QuicTlsSession,
    val s: QuicTlsSession,
) {
    class Side {
        var done = false
        val keys = ArrayList<PacketProtector>()
        var tp: ByteArray? = null
        var last: DriveResult = DriveResult.WantRead
    }

    val cs = Side()
    val ss = Side()

    /** Sees every event (true = from the client) before the pump handles it. */
    var onEvent: (Boolean, TlsEvent) -> Unit = { _, _ -> }

    fun run(
        rounds: Int = 40,
        onVerify: ((DriveResult.WantVerify) -> VerifyResult)? = null,
    ): Pair<DriveResult, DriveResult> {
        repeat(rounds) {
            var progressed = false
            for ((me, peer, side) in listOf(Triple(c, s, cs), Triple(s, c, ss))) {
                val r = me.drive()
                side.last = r
                if (r is DriveResult.WantVerify && onVerify != null) me.resumeVerify(onVerify(r))
                while (true) {
                    val ev = me.nextEvent() ?: break
                    progressed = true
                    onEvent(me === c, ev)
                    when (ev) {
                        is TlsEvent.CryptoData -> {
                            peer.provide(ev.level, ev.data)
                        }

                        is TlsEvent.Keys -> {
                            side.keys += ev.protector
                        }

                        is TlsEvent.PeerTransportParameters -> {
                            side.tp = ev.encoded
                        }

                        TlsEvent.HandshakeDone -> {
                            side.done = true
                        }

                        is TlsEvent.SessionTicket -> {}
                    }
                }
                if (r is DriveResult.Failed) return cs.last to ss.last
            }
            if (cs.done && ss.done && !progressed) return cs.last to ss.last
        }
        return cs.last to ss.last
    }

    fun close() {
        (cs.keys + ss.keys).forEach { it.close() }
        c.close()
        s.close()
    }
}

class QuicHandshakeTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    /** Misuse of the public session surfaces as IllegalStateException, never as the native layer's KslException. */
    @Test fun exportBeforeHandshakeIsNotKslException() {
        val s = KslQuicCrypto.newSession(Fixtures.client())
        try {
            assertFailsWith<IllegalStateException> { s.exportKeyingMaterial("EXPORTER-x", null, 32) }
        } finally {
            s.close()
        }
    }

    @Test fun resumeVerifyWithoutPauseIsIllegalState() {
        val s = KslQuicCrypto.newSession(Fixtures.client())
        try {
            assertFailsWith<IllegalStateException> { s.resumeVerify(VerifyResult.Accepted(emptyList())) }
        } finally {
            s.close()
        }
    }

    private fun pair(
        client: TlsConfig = Fixtures.client(),
        server: TlsConfig = Fixtures.server(),
    ): Pump =
        Pump(KslQuicCrypto.newSession(client), KslQuicCrypto.newSession(server)).also {
            it.c.setTransportParameters(Fixtures.tp)
            it.s.setTransportParameters(Fixtures.tp)
        }

    @Test fun handshakeAnchoredCaAlpnH3() {
        val p = pair()
        try {
            p.run()
            assertTrue(p.cs.done && p.ss.done, "both done")
            assertEquals("h3", p.c.negotiatedAlpn)
            assertEquals("h3", p.s.negotiatedAlpn)
            assertEquals(4, p.cs.keys.size)
            assertEquals(4, p.ss.keys.size)
            assertEquals(Aead.AES_128_GCM, p.cs.keys[0].aead, "first configured suite wins")
            assertContentEquals(Fixtures.tp, p.cs.tp)
            assertContentEquals(Fixtures.tp, p.ss.tp)
            assertEquals(listOf(Certificate(TestCerts.server)), p.c.peerCertificates)
            assertContentEquals(p.c.exportKeyingMaterial("l", byteArrayOf(1), 32), p.s.exportKeyingMaterial("l", byteArrayOf(1), 32))
        } finally {
            p.close()
        }
    }

    /**
     * A self-signed certificate whose validity times OpenSSL parses but the minimal DER walker does not (a fractional
     * GeneralizedTime, a UTCTime with an offset; UTCTime without seconds is already refused by OpenSSL 3.5) and whose
     * SAN does not match. The name failure must come back as DriveResult.Failed(Verify(HostnameMismatch)), not as an exception from
     * the minimal DER walker building the failure's details.
     */
    @Test fun negative_oddTimeCertificateNameMismatchFailsCleanly() {
        val accept = CertificateVerifier { chain, _, _ -> VerifyResult.Accepted(chain) }
        val p = pair(Fixtures.client(TrustConfig.Custom(accept)), Fixtures.server(listOf(OddTimeCert.der), OddTimeCert.key))
        try {
            val (c, _) = p.run { VerifyResult.Accepted(it.chain) }
            val f = assertIs<DriveResult.Failed>(c, "client result")
            val reason = assertIs<VerifyReason.HostnameMismatch>(assertIs<TlsException.Verify>(f.exception).reason)
            assertEquals(listOf("other.test"), reason.presented, "the names are read although the times are not")
            assertFailsWith<TlsException.Config> { Certificate(OddTimeCert.der).notBeforeEpochSeconds }
            Certificate(OddTimeCert.der).toString()
        } finally {
            p.close()
        }
    }

    @Test fun splitServerHelloWantRead() {
        val p = pair()
        try {
            assertIs<DriveResult.WantRead>(p.c.drive())
            while (true) {
                val ev = p.c.nextEvent() ?: break
                if (ev is TlsEvent.CryptoData) p.s.provide(ev.level, ev.data)
            }
            p.s.drive()
            var split = false
            while (true) {
                val ev = p.s.nextEvent() ?: break
                when (ev) {
                    is TlsEvent.CryptoData -> {
                        if (!split &&
                            ev.level == EncryptionLevel.Initial
                        ) {
                            split = true
                            p.c.provide(ev.level, ev.data, 0, ev.data.size - 1)
                            assertIs<DriveResult.WantRead>(p.c.drive())
                            p.c.provide(
                                ev.level,
                                ev.data,
                                ev.data.size - 1,
                                1,
                            )
                        } else {
                            p.c.provide(ev.level, ev.data)
                        }
                    }

                    is TlsEvent.Keys -> {
                        p.ss.keys += ev.protector
                    }

                    else -> {}
                }
            }
            assertTrue(split)
            p.run()
            assertTrue(p.cs.done && p.ss.done)
        } finally {
            p.close()
        }
    }

    @Test fun unknownCaFailsWithVerifyAndAlert48() {
        val p = pair(client = Fixtures.client(trust = TrustConfig.AnchoredCa(listOf(Certificate(TestCerts.otherCa)))))
        try {
            val (rc, _) = p.run()
            val f = assertIs<DriveResult.Failed>(rc)
            assertIs<TlsException.Verify>(f.exception)
            assertEquals(48, f.alert)
            assertTrue(!p.ss.done)
            assertIs<DriveResult.Failed>(p.c.drive()) // stable
        } finally {
            p.close()
        }
    }

    @Test fun nameMismatchFailsWithAlert42() {
        val p = pair(client = Fixtures.client(name = "wrong.test"))
        try {
            val f = assertIs<DriveResult.Failed>(p.run().first)
            assertEquals(42, f.alert)
            assertIs<TlsException.Verify>(f.exception)
        } finally {
            p.close()
        }
    }

    @Test fun corruptByteFailsStable() {
        val p = pair()
        try {
            p.c.drive()
            while (true) {
                val ev = p.c.nextEvent() ?: break
                if (ev is TlsEvent.CryptoData) p.s.provide(ev.level, ev.data)
            }
            p.s.drive()
            var first = true
            while (true) {
                val ev =
                    p.s.nextEvent() ?: break
                when (ev) {
                    is TlsEvent.CryptoData -> {
                        val d = ev.data.copyOf()
                        if (first &&
                            ev.level == EncryptionLevel.Handshake
                        ) {
                            d[d.size / 2] = (d[d.size / 2].toInt() xor 0xff).toByte()
                            first = false
                        }
                        p.c.provide(ev.level, d)
                    }

                    is TlsEvent.Keys -> {
                        p.ss.keys +=
                            ev.protector
                    }

                    else -> {}
                }
            }
            val f1 = assertIs<DriveResult.Failed>(p.c.drive())
            val f2 = assertIs<DriveResult.Failed>(p.c.drive())
            assertTrue(f1 === f2, "same failure on repeated drive")
        } finally {
            p.close()
        }
    }

    @Test fun largeChainHandshake() {
        val p = pair(server = Fixtures.server(listOf(TestCerts.serverBigChain, TestCerts.intermediate), TestCerts.serverBigChainKey))
        try {
            p.run()
            assertTrue(p.cs.done && p.ss.done)
            assertTrue(
                p.c.peerCertificates[0]
                    .der.size > 12_000,
            )
            assertEquals(2, p.c.peerCertificates.size)
        } finally {
            p.close()
        }
    }

    @Test fun postHandshakeTicketDelivered() {
        val p = pair()
        try {
            p.run()
            assertTrue(p.cs.done && p.ss.done)
            (p.s as KslQuicTlsSession).newSessionTicket()
            var crypto = 0
            repeat(4) {
                p.s.drive()
                while (true) {
                    val ev =
                        p.s.nextEvent() ?: break
                    if (ev is TlsEvent.CryptoData) {
                        crypto++
                        assertEquals(EncryptionLevel.Application, ev.level)
                        p.c.provide(ev.level, ev.data)
                    }
                }
                p.c.drive()
            }
            assertEquals(1, crypto, "one NewSessionTicket at the application level")
        } finally {
            p.close()
        }
    }

    @Test fun sniSelectorIsConfigErrorForQuic() {
        assertFailsWith<TlsException.Config> {
            KslQuicCrypto.newSession(
                Fixtures.server {
                    sniSelector =
                        { null }
                },
            )
        }
    }

    @Test fun clientWithoutReferenceNameIsConfigError() {
        assertFailsWith<TlsException.Config> { KslQuicCrypto.newSession(Fixtures.client(name = null)) }
    }
}

class PacketProtectorTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    private val dcid = Rfc9001Vectors.DCID

    @Test fun sealOpenRoundTripAndWrongTag() {
        val (cr, cw) = KslQuicCrypto.initialProtectors(dcid, 1, TlsRole.Client)
        val (sr, sw) = KslQuicCrypto.initialProtectors(dcid, 1, TlsRole.Server)
        val header = PacketBuffer.of(byteArrayOf(0xc3.toByte(), 0, 0, 0, 1))
        val payload = PacketBuffer.allocate(80)
        try {
            val plain = ByteArray(50) { it.toByte() }
            payload.copyFrom(plain, 0, 0, 50)
            assertEquals(66, cw.seal(3, header, 5, payload, 50))
            assertEquals(50, sr.open(3, header, 5, payload, 66))
            assertContentEquals(plain, payload.toByteArray(50))
            cw.seal(3, header, 5, payload, 50)
            payload[7] = (payload[7].toInt() xor 1).toByte()
            assertFailsWith<PacketProtectionException> { sr.open(3, header, 5, payload, 66) }
            sw.seal(9, header, 5, payload, 50)
            assertEquals(50, cr.open(9, header, 5, payload, 66))
        } finally {
            listOf(cr, cw, sr, sw).forEach { it.close() }
            header.close()
            payload.close()
        }
    }

    @Test fun nextKeepsHeaderKeyAndChangesCiphertext() {
        val (_, w) = KslQuicCrypto.initialProtectors(dcid, 1, TlsRole.Client)
        val w2 = w.next()
        val header = PacketBuffer.of(byteArrayOf(0x40, 1))
        val a = PacketBuffer.allocate(64)
        val b = PacketBuffer.allocate(64)
        val sample = PacketBuffer.of(ByteArray(16) { it.toByte() })
        try {
            w.seal(1, header, 2, a, 20)
            w2.seal(1, header, 2, b, 20)
            assertNotEquals(a.toByteArray(36).toList(), b.toByteArray(36).toList())
            val m1 = ByteArray(5)
            val m2 = ByteArray(5)
            w.headerMask(sample, 0, m1)
            w2.headerMask(sample, 0, m2)
            assertContentEquals(m1, m2)
        } finally {
            w.close()
            w2.close()
            header.close()
            a.close()
            b.close()
            sample.close()
        }
    }

    @Test fun negative_lengthsBeyondBuffersAreRejected() {
        val (r, w) = KslQuicCrypto.initialProtectors(dcid, 1, TlsRole.Client)
        val header = PacketBuffer.of(byteArrayOf(0x40, 1))
        val payload = PacketBuffer.allocate(64)
        val sample = PacketBuffer.of(ByteArray(16))
        try {
            assertFailsWith<IndexOutOfBoundsException> { w.seal(1, header, 3, payload, 20) }
            assertFailsWith<IndexOutOfBoundsException> { w.seal(1, header, 2, payload, 65) }
            assertFailsWith<IndexOutOfBoundsException> { r.open(1, header, 2, payload, 65) }
            assertFailsWith<IndexOutOfBoundsException> { w.headerMask(sample, 1, ByteArray(5)) }
            assertFailsWith<IndexOutOfBoundsException> { w.headerMask(sample, 0, ByteArray(4)) }
            assertFails { w.seal(1, header, 2, payload, 60) } // no room for the 16-byte tag
        } finally {
            r.close()
            w.close()
            header.close()
            payload.close()
            sample.close()
        }
    }

    @Test fun closeRejectsUse() {
        val (r, w) = KslQuicCrypto.initialProtectors(dcid, 1, TlsRole.Client)
        r.close()
        w.close()
        r.close()
        assertFailsWith<IllegalStateException> { r.next() }
    }
}

class RfcVectorsTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    private fun check(
        version: Int,
        dcid: ByteArray,
        a2Crypto: ByteArray,
        a2Header: ByteArray,
        a2Sample: ByteArray,
        a2Mask: ByteArray,
        a2Protected: ByteArray,
        a3Payload: ByteArray,
        a3Header: ByteArray,
        a3Mask: ByteArray,
        a3Sample: ByteArray,
        a3Protected: ByteArray,
        a4Retry: ByteArray,
    ) {
        val (cr, cw) = KslQuicCrypto.initialProtectors(dcid, version, TlsRole.Client)
        val (sr, sw) = KslQuicCrypto.initialProtectors(dcid, version, TlsRole.Server)
        val header = PacketBuffer.of(a2Header)
        val payload = PacketBuffer.allocate(1200)
        val sample = PacketBuffer.of(a2Sample)
        try {
            payload.copyFrom(a2Crypto, 0, 0, a2Crypto.size)
            assertEquals(1178, cw.seal(2, header, a2Header.size, payload, 1162))
            assertContentEquals(a2Protected.copyOfRange(22, 1200), payload.toByteArray(1178))
            val mask = ByteArray(5)
            cw.headerMask(sample, 0, mask)
            assertContentEquals(a2Mask, mask)
            assertEquals(1162, sr.open(2, header, a2Header.size, payload, 1178))
            assertContentEquals(a2Crypto, payload.toByteArray(a2Crypto.size))
            val h3 = PacketBuffer.of(a3Header)
            val p3 = PacketBuffer.allocate(200)
            p3.copyFrom(a3Payload, 0, 0, a3Payload.size)
            val s3 = PacketBuffer.of(a3Sample)
            assertEquals(a3Payload.size + 16, sw.seal(1, h3, a3Header.size, p3, a3Payload.size))
            assertContentEquals(
                a3Protected.copyOfRange(a3Header.size, a3Protected.size),
                p3.toByteArray(a3Payload.size + 16),
            )
            sw.headerMask(s3, 0, mask)
            assertContentEquals(a3Mask, mask)
            assertEquals(
                a3Payload.size,
                cr.open(
                    1,
                    h3,
                    a3Header.size,
                    p3,
                    a3Payload.size + 16,
                ),
            )
            h3.close()
            p3.close()
            s3.close()
            val pseudo = byteArrayOf(8) + dcid + a4Retry.copyOfRange(0, a4Retry.size - 16)
            assertContentEquals(
                a4Retry.copyOfRange(a4Retry.size - 16, a4Retry.size),
                KslQuicCrypto.retryIntegrityTag(version, dcid, pseudo),
            )
        } finally {
            listOf(cr, cw, sr, sw).forEach { it.close() }
            header.close()
            payload.close()
            sample.close()
        }
    }

    @Test fun rfc9001AppendixA() =
        with(Rfc9001Vectors) {
            check(
                VERSION,
                DCID,
                A2_CRYPTO,
                A2_HEADER,
                A2_SAMPLE,
                A2_MASK,
                A2_PROTECTED,
                A3_PAYLOAD,
                A3_HEADER,
                A3_MASK,
                A3_SAMPLE,
                A3_PROTECTED,
                A4_RETRY,
            )
        }

    @Test fun rfc9369AppendixA() =
        with(Rfc9369Vectors) {
            check(
                VERSION,
                DCID,
                A2_CRYPTO,
                A2_HEADER,
                A2_SAMPLE,
                A2_MASK,
                A2_PROTECTED,
                A3_PAYLOAD,
                A3_HEADER,
                A3_MASK,
                A3_SAMPLE,
                A3_PROTECTED,
                A4_RETRY,
            )
        }

    @Test fun unknownVersionRejected() {
        assertFailsWith<io.kuicksilver.native.KslException.Internal> {
            KslQuicCrypto.initialProtectors(Rfc9001Vectors.DCID, 0xdeadbeef.toInt(), TlsRole.Client)
        }
    }
}

/** QUIC v2 and RFC 9368 version choice through ksl (owner decision 2026-10-02). */
class QuicVersionTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    private val v1 = 0x00000001
    private val v2 = 0x6b3343cf

    private fun be32(v: Int) = byteArrayOf((v ushr 24).toByte(), (v ushr 16).toByte(), (v ushr 8).toByte(), v.toByte())

    /** Fixtures.tp plus version_information(chosen, available...). */
    private fun tpWith(
        chosen: Int,
        vararg available: Int,
    ): ByteArray =
        Fixtures.tp + byteArrayOf(0x11, (4 + 4 * available.size).toByte()) + be32(chosen) +
            available.fold(ByteArray(0)) { a, v -> a + be32(v) }

    private class Side {
        var done = false
        val app = HashMap<Direction, PacketProtector>()
        var negotiated = -1
        var last: DriveResult = DriveResult.WantRead
    }

    /** Pumps CRYPTO between the sessions; [clientSwitch] is applied before the first server Initial reaches the client (the Initial header carries the version). */
    private fun pump(
        c: QuicTlsSession,
        s: QuicTlsSession,
        clientSwitch: Int?,
    ): Pair<Side, Side> {
        var switch = clientSwitch
        val cs = Side()
        val ss = Side()
        repeat(40) {
            var progressed = false
            for ((me, peer, side) in listOf(Triple(c, s, cs), Triple(s, c, ss))) {
                side.last = me.drive()
                if (side.last is DriveResult.WantVerify) {
                    me.resumeVerify(
                        runBlocking { me.verifyPeer((side.last as DriveResult.WantVerify).chain) },
                    )
                }
                while (true) {
                    val ev = me.nextEvent() ?: break
                    progressed = true
                    when (ev) {
                        is TlsEvent.SessionTicket -> {
                            ev.ticket.close()
                        }

                        is TlsEvent.CryptoData -> {
                            if (me === s && ev.level == EncryptionLevel.Initial &&
                                switch != null
                            ) {
                                c.setQuicVersion(switch!!)
                                switch = null
                            }
                            peer.provide(ev.level, ev.data)
                        }

                        is TlsEvent.Keys -> {
                            if (ev.level ==
                                EncryptionLevel.Application
                            ) {
                                side.app[ev.direction] = ev.protector
                            } else {
                                ev.protector.close()
                            }
                        }

                        is TlsEvent.PeerTransportParameters -> {
                            side.negotiated = ev.negotiatedVersion
                        }

                        TlsEvent.HandshakeDone -> {
                            side.done = true
                        }
                    }
                }
                if (side.last is DriveResult.Failed) return cs to ss
            }
            if (cs.done && ss.done && !progressed) return cs to ss
        }
        return cs to ss
    }

    private fun oneRttRoundTrip(
        cs: Side,
        ss: Side,
    ) {
        val header = PacketBuffer.of(byteArrayOf(0x41, 1, 2))
        val payload = PacketBuffer.allocate(64)
        try {
            payload.copyFrom(ByteArray(20) { 5 }, 0, 8, 20)
            assertEquals(36, ss.app[Direction.Write]!!.seal(9, header, 0, 3, payload, 8, 20))
            assertEquals(20, cs.app[Direction.Read]!!.open(9, header, 0, 3, payload, 8, 36))
            assertContentEquals(ByteArray(20) { 5 }, payload.toByteArray(28).copyOfRange(8, 28))
        } finally {
            header.close()
            payload.close()
        }
    }

    private fun close(vararg sides: Side) = sides.forEach { s -> s.app.values.forEach { it.close() } }

    @Test fun clientV1OnlyNeverDerivesV2Keys() {
        val c = KslQuicCrypto.newSession(Fixtures.client())
        val s = KslQuicCrypto.newSession(Fixtures.server())
        try {
            c.setTransportParameters(Fixtures.tp)
            s.setTransportParameters(tpWith(v2, v2, v1))
            val (cs, ss) = pump(c, s, null)
            assertTrue(cs.done && ss.done)
            assertEquals(v1, ss.negotiated)
            assertEquals(v1, cs.negotiated)
            oneRttRoundTrip(cs, ss)
            val other = KslQuicCrypto.newSession(Fixtures.client())
            val other2 = KslQuicCrypto.newSession(Fixtures.server())
            other.close()
            other2.close()
            close(cs, ss)
        } finally {
            c.close()
            s.close()
        }
    }

    @Test fun v1v2ClientWithV2v1ServerEndToEnd() {
        val c = KslQuicCrypto.newSession(Fixtures.client())
        val s = KslQuicCrypto.newSession(Fixtures.server())
        try {
            c.setTransportParameters(tpWith(v1, v1, v2))
            s.setTransportParameters(tpWith(v2, v2, v1))
            c.setQuicVersion(v1)
            val (cs, ss) = pump(c, s, v2)
            assertTrue(cs.done && ss.done, "handshake with a v1→v2 upgrade")
            assertEquals(v2, ss.negotiated)
            assertEquals(v2, cs.negotiated)
            oneRttRoundTrip(cs, ss)
            close(cs, ss)
        } finally {
            c.close()
            s.close()
        }
    }

    @Test fun serverReportsNegotiatedVersion() {
        val c = KslQuicCrypto.newSession(Fixtures.client())
        val s = KslQuicCrypto.newSession(Fixtures.server())
        try {
            c.setTransportParameters(tpWith(v1, v1, v2))
            s.setTransportParameters(tpWith(v2, v2, v1))
            val (cs, ss) = pump(c, s, v2)
            assertEquals(v2, ss.negotiated)
            close(cs, ss)
        } finally {
            c.close()
            s.close()
        }
    }

    @Test fun clientWithoutSwitchFailsToOpenV2Packets() {
        // the client never learned v2 from the server Initial: its 1-RTT keys use v1 labels and cannot open the server's v2 packets
        val c = KslQuicCrypto.newSession(Fixtures.client())
        val s = KslQuicCrypto.newSession(Fixtures.server())
        try {
            c.setTransportParameters(tpWith(v1, v1, v2))
            s.setTransportParameters(tpWith(v2, v2, v1))
            val (cs, ss) = pump(c, s, null)
            assertTrue(cs.done && ss.done)
            assertFailsWith<PacketProtectionException> { oneRttRoundTrip(cs, ss) }
            close(cs, ss)
        } finally {
            c.close()
            s.close()
        }
    }

    @Test fun setQuicVersionAfterHandshakeKeysIsIllegalState() {
        val c = KslQuicCrypto.newSession(Fixtures.client())
        val s = KslQuicCrypto.newSession(Fixtures.server())
        try {
            c.setTransportParameters(Fixtures.tp)
            s.setTransportParameters(Fixtures.tp)
            val (cs, ss) = pump(c, s, null)
            assertTrue(cs.done)
            assertFailsWith<IllegalStateException> { c.setQuicVersion(v2) }
            close(cs, ss)
        } finally {
            c.close()
            s.close()
        }
    }

    @Test fun setQuicVersionRejectsUnknown() {
        val c = KslQuicCrypto.newSession(Fixtures.client())
        try {
            assertFailsWith<IllegalArgumentException> { c.setQuicVersion(0x0a0a0a0a) }
        } finally {
            c.close()
        }
    }
}

/** Self-signed P-256 leaf for other.test; notBefore GeneralizedTime with a fraction (20260101000000.5Z), notAfter UTCTime with an offset (490101000000+0000): OpenSSL 3.5 parses both, RFC 5280 forbids both. */
internal object OddTimeCert {
    val der: ByteArray get() =
        kotlin.io.encoding.Base64.decode(
            "MIIBSTCB8aADAgECAgEHMAoGCCqGSM49BAMCMBMxETAPBgNVBAMMCG9kZCB0aW1lMCYYETIwMjYwMTAxMDAwMDAwLjVaFxE0OTAxMDEwMDAwMDArMDAwMDATMREwDwYDVQQDDAhvZGQgdGltZTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABC/OqrtshedwAQZ7vkm+8Xz70OJS90EkRXiVBirsyO8Jp3CoslrhzgWcuc1rZxe4buWxSb1HuORFQwNqb46KzWmjLjAsMBUGA1UdEQQOMAyCCm90aGVyLnRlc3QwEwYDVR0lBAwwCgYIKwYBBQUHAwEwCgYIKoZIzj0EAwIDRwAwRAIgcxHOccqXeR7RZGkgzPxTKUsTpPz+E6S4vdbyPgA1FjUCIG1jgQ+eOCc3/JkZHhXelnV4dzuEXqoRENfGRBOhYf+u",
        )
    val key: ByteArray get() =
        kotlin.io.encoding.Base64.decode(
            "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgq/hsE2z43a5xtWERrjVnVG6f0G1yPrAzPCg7DyjMS/ehRANCAAQvzqq7bIXncAEGe75JvvF8+9DiUvdBJEV4lQYq7MjvCadwqLJa4c4FnLnNa2cXuG7lsUm9R7jkRUMDam+Ois1p",
        )
}
