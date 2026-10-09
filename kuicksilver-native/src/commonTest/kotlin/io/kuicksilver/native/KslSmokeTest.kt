// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(InternalKuicksilverApi::class)

package io.kuicksilver.native

import io.kuicksilver.annotations.InternalKuicksilverApi
import kotlinx.coroutines.async
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

/** The bindings against the real native library: the same checks on every platform (JVM, Android, Native). */
class KslSmokeTest {
    private val tp = byteArrayOf(0x01, 0x02, 0x67, 0x10)
    private val alpnH3 = byteArrayOf(2, 'h'.code.toByte(), '3'.code.toByte())

    @BeforeTest fun load() = KslLoader.ensureLoaded()

    @Test fun abiVersionMatches() = assertEquals(KSL_ABI_VERSION, Ksl.abiVersion())

    @Test fun versionStringMentionsOpenSsl359() = assertTrue(Ksl.version().contains("OpenSSL 3.5.9"), Ksl.version())

    @Test fun ctxFreezeRejectsMutation() {
        val ctx = Ksl.ctxNew(KslConst.SERVER)
        try {
            Ksl.ctxFreeze(ctx)
            val e = assertFailsWith<KslException.Internal> { Ksl.ctxSetOption(ctx, KslConst.OPT_NUM_TICKETS, 1) }
            assertEquals(KslConst.E_CTX_FROZEN, e.packed)
            assertTrue(e.isKsl)
        } finally {
            Ksl.ctxFree(ctx)
        }
    }

    /** tcpFeed/Drain/Write/Read check the Kotlin array range before any native call, on every platform. */
    @Test fun negative_tcpArrayBoundsChecked() {
        val ctx = Ksl.ctxNew(KslConst.CLIENT)
        val ssl = Ksl.sslNew(ctx, KslConst.MODE_TCP)
        try {
            val a = ByteArray(4)
            assertFailsWith<IndexOutOfBoundsException> { Ksl.tcpFeed(ssl, a, 2, 4) }
            assertFailsWith<IndexOutOfBoundsException> { Ksl.tcpDrain(ssl, a, 1, 4) }
            assertFailsWith<IndexOutOfBoundsException> { Ksl.tcpWrite(ssl, a, -1, 2) }
            assertFailsWith<IndexOutOfBoundsException> { Ksl.tcpRead(ssl, a, 0, 5) }
            assertFailsWith<IndexOutOfBoundsException> { Ksl.tcpFeed(ssl, a, 1, Int.MAX_VALUE) }
        } finally {
            Ksl.sslFree(ssl)
            Ksl.ctxFree(ctx)
        }
    }

    @Test fun serverPauseModeIsRejected() {
        val ctx = Ksl.ctxNew(KslConst.SERVER)
        try {
            assertEquals(
                KslConst.E_SERVER_PAUSE_FORBIDDEN,
                assertFailsWith<KslException.Internal> {
                    Ksl.ctxSetOption(ctx, KslConst.OPT_VERIFY_MODE, KslConst.VERIFY_PAUSE)
                }.packed,
            )
        } finally {
            Ksl.ctxFree(ctx)
        }
    }

    private class Side(
        val ssl: Long,
    ) {
        var done = false
        val keys = ArrayList<Long>()
        var tp: ByteArray? = null
        val ev = KslEvent()
    }

    private fun pump(
        c: Side,
        s: Side,
        rounds: Int = 40,
    ): Pair<Int, Int> {
        var rc = KslConst.OK
        var rs = KslConst.OK
        repeat(rounds) {
            var progressed = false
            for ((me, peer) in listOf(c to s, s to c)) {
                val r = Ksl.drive(me.ssl)
                if (me === c) rc = r else rs = r
                while (Ksl.quicNextEvent(me.ssl, me.ev)) {
                    progressed = true
                    when (me.ev.type) {
                        KslConst.EV_CRYPTO_SEND -> Ksl.quicProvide(peer.ssl, me.ev.level, me.ev.payload, 0, me.ev.payload.size)
                        KslConst.EV_KEY -> me.keys += me.ev.key
                        KslConst.EV_TRANSPORT_PARAMS -> me.tp = me.ev.payload
                        KslConst.EV_HANDSHAKE_DONE -> me.done = true
                    }
                }
            }
            if (c.done && s.done && !progressed) return rc to rs
        }
        return rc to rs
    }

    private fun handshake(
        serverChain: List<ByteArray>,
        serverKey: ByteArray,
        body: (Side, Side) -> Unit,
    ) {
        val cc = Ksl.ctxNew(KslConst.CLIENT)
        val sc = Ksl.ctxNew(KslConst.SERVER)
        Ksl.ctxSetAlpn(cc, alpnH3)
        Ksl.ctxSetAlpn(sc, alpnH3)
        Ksl.ctxSetRoots(cc, listOf(TestCerts.testCa))
        Ksl.ctxSetIdentity(sc, serverChain, serverKey)
        val c = Side(Ksl.sslNew(cc, KslConst.MODE_QUIC))
        val s = Side(Ksl.sslNew(sc, KslConst.MODE_QUIC))
        try {
            Ksl.sslSet(c.ssl, KslConst.SET_SNI, "server.test".encodeToByteArray())
            Ksl.sslSet(c.ssl, KslConst.SET_VERIFY_NAME, "server.test".encodeToByteArray())
            Ksl.quicSetTransportParams(c.ssl, tp)
            Ksl.quicSetTransportParams(s.ssl, tp)
            body(c, s)
        } finally {
            (c.keys + s.keys).forEach(Ksl::keyFree)
            Ksl.sslFree(c.ssl)
            Ksl.sslFree(s.ssl)
            Ksl.ctxFree(cc)
            Ksl.ctxFree(sc)
        }
    }

    @Test fun quicHandshakeInMemory() =
        handshake(listOf(TestCerts.server), TestCerts.serverKey) { c, s ->
            pump(c, s)
            assertTrue(c.done && s.done, "both sides done")
            assertEquals(4, c.keys.size)
            assertEquals(4, s.keys.size)
            assertTrue(c.keys.all { it != 0L })
            assertContentEquals("h3".encodeToByteArray(), Ksl.sslGet(c.ssl, KslConst.GET_ALPN))
            assertContentEquals(tp, c.tp)
            assertContentEquals(tp, s.tp)
            assertEquals(2, Ksl.sslPeerChain(c.ssl, KslConst.CHAIN_VALIDATED).size)
            assertContentEquals(TestCerts.server, Ksl.sslPeerChain(c.ssl, KslConst.CHAIN_PRESENTED)[0])
            assertContentEquals(
                Ksl.sslExportKeyingMaterial(c.ssl, "t", byteArrayOf(1), 32),
                Ksl.sslExportKeyingMaterial(s.ssl, "t", byteArrayOf(1), 32),
            )
        }

    @Test fun eventLargerThanBufferNotLost() =
        handshake(listOf(TestCerts.serverBigChain, TestCerts.intermediate), TestCerts.serverBigChainKey) { c, s ->
            // the big-chain leaf is ~14 KB: the server's CRYPTO flight exceeds the bindings' initial event buffer
            pump(c, s)
            assertTrue(c.done && s.done, "handshake with a 14 KB certificate completes")
            assertTrue(Ksl.sslPeerChain(c.ssl, KslConst.CHAIN_PRESENTED)[0].size > 12_000)
        }

    @Test fun forgottenVerifyNameFails() {
        val cc = Ksl.ctxNew(KslConst.CLIENT)
        Ksl.ctxSetAlpn(cc, alpnH3)
        Ksl.ctxSetRoots(cc, listOf(TestCerts.testCa))
        val ssl = Ksl.sslNew(cc, KslConst.MODE_QUIC)
        try {
            Ksl.quicSetTransportParams(ssl, tp)
            assertEquals(KslConst.E_NO_VERIFY_NAME, assertFailsWith<KslException.Internal> { Ksl.drive(ssl) }.packed)
            assertFailsWith<KslException.Internal> { Ksl.sslSet(ssl, KslConst.SET_VERIFY_NAME, "".encodeToByteArray()) }
        } finally {
            Ksl.sslFree(ssl)
            Ksl.ctxFree(cc)
        }
    }

    @Test fun sealOpenRoundTripAndWrongTag() {
        val dcid = byteArrayOf(0x83.toByte(), 0x94.toByte(), 0xc8.toByte(), 0xf0.toByte(), 0x3e, 0x51, 0x57, 0x08)
        val w = Ksl.keyInitial(dcid, false, KslConst.DIR_WRITE, 1)
        val r = Ksl.keyInitial(dcid, true, KslConst.DIR_READ, 1)
        val header = PacketBuffer.of(byteArrayOf(0xc3.toByte(), 0, 0, 0, 1))
        val payload = PacketBuffer.allocate(64)
        try {
            val plain = ByteArray(40) { (it * 3).toByte() }
            payload.copyFrom(plain, 0, 0, 40)
            assertEquals(56, Ksl.seal(w, 2, header, 0, 5, payload, 0, 40))
            assertEquals(40, Ksl.open(r, 2, header, 0, 5, payload, 0, 56))
            assertContentEquals(plain, payload.toByteArray(40))
            Ksl.seal(w, 2, header, 0, 5, payload, 0, 40)
            payload[10] = (payload[10].toInt() xor 1).toByte()
            assertFailsWith<KslException.Internal> { Ksl.open(r, 2, header, 0, 5, payload, 0, 56) }
            val mask = ByteArray(5)
            Ksl.headerMask(w, payload, 4, mask)
            assertTrue(mask.any { it != 0.toByte() })
        } finally {
            Ksl.keyFree(w)
            Ksl.keyFree(r)
            header.close()
            payload.close()
        }
    }

    @Test fun cryptoHelpers() {
        assertEquals(32, Ksl.sha2(256, byteArrayOf()).size)
        assertEquals(48, Ksl.sha2(384, byteArrayOf()).size)
        assertTrue(Ksl.rand(16).any { it != 0.toByte() })
        assertEquals(16, Ksl.hkdfExpandLabel(KslConst.HASH_SHA256, ByteArray(32), "key", byteArrayOf(), 16).size)
        assertContentEquals(TestCerts.serverSpkiSha256, Ksl.spkiSha256(TestCerts.server))
        val sig = Ksl.sign(KslConst.SIG_ECDSA_P256, TestCerts.serverKey, "m".encodeToByteArray())
        assertTrue(sig.size >= 64)
    }
}

/** Sessions on different threads must not share the event buffer (double free / cross-wired CRYPTO otherwise). */
class ConcurrentSessionsTest {
    @kotlin.test.BeforeTest fun load() = KslLoader.ensureLoaded()

    private fun handshake(): Boolean {
        val tp = byteArrayOf(0x01, 0x02, 0x67, 0x10)
        val alpn = byteArrayOf(2, 'h'.code.toByte(), '3'.code.toByte())
        val cc = Ksl.ctxNew(KslConst.CLIENT)
        val sc = Ksl.ctxNew(KslConst.SERVER)
        Ksl.ctxSetAlpn(cc, alpn)
        Ksl.ctxSetAlpn(sc, alpn)
        Ksl.ctxSetRoots(cc, listOf(TestCerts.testCa))
        Ksl.ctxSetIdentity(sc, listOf(TestCerts.server), TestCerts.serverKey)
        val c = Ksl.sslNew(cc, KslConst.MODE_QUIC)
        val s = Ksl.sslNew(sc, KslConst.MODE_QUIC)
        val ec = KslEvent()
        val es = KslEvent()
        val keys = ArrayList<Long>()
        var cd = false
        var sd = false
        try {
            Ksl.sslSet(c, KslConst.SET_SNI, "server.test".encodeToByteArray())
            Ksl.sslSet(c, KslConst.SET_VERIFY_NAME, "server.test".encodeToByteArray())
            Ksl.quicSetTransportParams(c, tp)
            Ksl.quicSetTransportParams(s, tp)
            repeat(40) {
                for ((me, peer, ev) in listOf(Triple(c, s, ec), Triple(s, c, es))) {
                    Ksl.drive(me)
                    while (Ksl.quicNextEvent(me, ev)) {
                        when (ev.type) {
                            KslConst.EV_CRYPTO_SEND -> {
                                Ksl.quicProvide(peer, ev.level, ev.payload, 0, ev.payload.size)
                            }

                            KslConst.EV_KEY -> {
                                keys +=
                                    ev.key
                            }

                            KslConst.EV_HANDSHAKE_DONE -> {
                                if (me == c) cd = true else sd = true
                            }
                        }
                    }
                }
                if (cd && sd) return true
            }
            return false
        } finally {
            keys.forEach(Ksl::keyFree)
            Ksl.sslFree(c)
            Ksl.sslFree(s)
            Ksl.ctxFree(cc)
            Ksl.ctxFree(sc)
        }
    }

    @Test fun eightParallelHandshakesWithPrivateEventBuffers() =
        kotlinx.coroutines.runBlocking {
            val results =
                kotlinx.coroutines.coroutineScope {
                    (1..8).map { async(kotlinx.coroutines.Dispatchers.Default) { (1..5).all { handshake() } } }.map { it.await() }
                }
            assertTrue(results.all { it }, "every parallel handshake completes: $results")
        }
}
