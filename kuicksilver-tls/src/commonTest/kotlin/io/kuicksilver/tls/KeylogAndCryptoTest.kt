// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(
    DelicateKuicksilverApi::class,
    io.kuicksilver.annotations.InternalKuicksilverApi::class,
    io.kuicksilver.annotations.ExperimentalKuicksilverApi::class,
)

package io.kuicksilver.tls

import io.kuicksilver.annotations.DelicateKuicksilverApi
import io.kuicksilver.native.KslLoader
import kotlinx.coroutines.runBlocking
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class KeylogTest {
    @BeforeTest fun load() {
        KslLoader.ensureLoaded()
        runBlocking { SessionCache.Default.clear() }
    }

    @Test fun explicitSinkReceivesRfc9850Lines() {
        val sink = KeylogSink.inMemory()
        val p = Pump(KslQuicCrypto.newSession(Fixtures.client { keylog = sink }), KslQuicCrypto.newSession(Fixtures.server()))
        p.c.setTransportParameters(Fixtures.tp)
        p.s.setTransportParameters(Fixtures.tp)
        try {
            p.run()
            assertTrue(p.cs.done && p.ss.done)
            val labels = sink.lines.map { it.substringBefore(' ') }
            assertTrue("CLIENT_HANDSHAKE_TRAFFIC_SECRET" in labels && "SERVER_TRAFFIC_SECRET_0" in labels, labels.toString())
            assertFalse("EXPORTER_SECRET" in labels, "exporter secret is not logged by default")
            assertTrue(sink.lines.all { it.split(' ').size == 3 && it.split(' ')[1].length == 64 }, "label client_random secret")
        } finally {
            p.close()
        }
    }

    @Test fun noSinkMeansNoLines() {
        val p = Pump(KslQuicCrypto.newSession(Fixtures.client()), KslQuicCrypto.newSession(Fixtures.server()))
        p.c.setTransportParameters(Fixtures.tp)
        p.s.setTransportParameters(Fixtures.tp)
        try {
            p.run()
            assertTrue((p.c as KslQuicTlsSession).drainKeylog().isEmpty())
        } finally {
            p.close()
        }
    }

    @Test fun tcpConnectionLogsBothSides() =
        runBlocking {
            val cs = KeylogSink.inMemory()
            val ss = KeylogSink.inMemory()
            val (cd, sd) = connect(TcpFixtures.client { keylog = cs }, TcpFixtures.server { keylog = ss })
            val c = cd.await()
            val s = sd.await()
            try {
                assertTrue(cs.lines.size >= 4 && ss.lines.size >= 4, "${cs.lines.size}/${ss.lines.size}")
            } finally {
                c.close()
                s.close()
            }
        }
}

class KslCryptoTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    private val sha256abc = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"

    private fun hex(b: ByteArray) = b.joinToString("") { (it.toInt() and 0xff).toString(16).padStart(2, '0') }

    @Test fun sha2Known() {
        assertEquals(sha256abc, hex(KslCrypto.sha256("abc".encodeToByteArray())))
        assertEquals(48, KslCrypto.sha384("abc".encodeToByteArray()).size)
    }

    @Test fun hkdfRfc8448() {
        val chts = "b3eddb126e067f35a780b3abf45e2d8f3b1a950738f52e9600746a0e27a55a21".chunked(2).map { it.toInt(16).toByte() }.toByteArray()
        assertEquals("dbfaa693d1762c5b666af5d950258d01", hex(KslCrypto.hkdfExpandLabel(Hash.Sha256, chts, "key", byteArrayOf(), 16)))
        assertEquals("5bd3c71b836e0b76bb73265f", hex(KslCrypto.hkdfExpandLabel(Hash.Sha256, chts, "iv", byteArrayOf(), 12)))
        assertFailsWith<IllegalArgumentException> { KslCrypto.hkdfExpandLabel(Hash.Sha256, chts, "x".repeat(250), byteArrayOf(), 16) }
    }

    @Test fun ecdsaRoundTrip() {
        val msg = "kuicksilver".encodeToByteArray()
        val sig = KslCrypto.sign(SignatureAlgorithm.EcdsaP256, TestCerts.serverKey, msg)
        val spki = SpkiExtractor.spkiDer(TestCerts.server)
        assertTrue(KslCrypto.verify(SignatureAlgorithm.EcdsaP256, spki, msg, sig))
        sig[12] = (sig[12].toInt() xor 1).toByte()
        assertFalse(KslCrypto.verify(SignatureAlgorithm.EcdsaP256, spki, msg, sig))
        assertFailsWith<io.kuicksilver.native.KslException.Internal> {
            KslCrypto.sign(
                SignatureAlgorithm.Ed25519,
                TestCerts.serverKey,
                msg,
            )
        }
    }

    /** The KDoc promises false for a bad signature: one that is not a DER ECDSA-Sig-Value is a bad signature, not an error. */
    @Test fun negative_malformedEcdsaSignatureVerifiesFalse() {
        val msg = "kuicksilver".encodeToByteArray()
        val spki = SpkiExtractor.spkiDer(TestCerts.server)
        assertFalse(KslCrypto.verify(SignatureAlgorithm.EcdsaP256, spki, msg, ByteArray(8)))
        assertFalse(KslCrypto.verify(SignatureAlgorithm.EcdsaP256, spki, msg, byteArrayOf(0x30, 0x7f, 0x02)))
        assertFalse(KslCrypto.verify(SignatureAlgorithm.EcdsaP256, spki, msg, ByteArray(0)))
        // a key of the wrong type still throws
        assertFailsWith<io.kuicksilver.native.KslException.Internal> {
            KslCrypto.verify(SignatureAlgorithm.Ed25519, spki, msg, ByteArray(64))
        }
    }

    @Test fun randomNotRepeating() {
        assertFalse(KslCrypto.randomBytes(32).contentEquals(KslCrypto.randomBytes(32)))
        assertEquals(0, KslCrypto.randomBytes(0).size)
    }

    @Test fun spkiMatchesCli() {
        assertContentEquals(TestCerts.serverSpkiSha256, KslCrypto.spkiSha256(TestCerts.server).bytes)
    }

    private fun unhex(s: String) = ByteArray(s.length / 2) { s.substring(2 * it, 2 * it + 2).toInt(16).toByte() }

    /** FIPS-197 Appendix C.1 (AES-128). */
    @Test fun lbKeyFips197() {
        KslLbKey.of(unhex("000102030405060708090a0b0c0d0e0f")).use { k ->
            val pt = unhex("00112233445566778899aabbccddeeff")
            val ct = ByteArray(16)
            k.encrypt(pt, ct)
            assertContentEquals(unhex("69c4e0d86a7b0430d8cdb78070b4c55a"), ct)
            val back = ByteArray(16)
            k.decrypt(ct, back)
            assertContentEquals(pt, back)
            val inPlace = ByteArray(20).also { pt.copyInto(it, 2) }
            k.encrypt(inPlace, 2, inPlace, 2)
            assertContentEquals(ct, inPlace.copyOfRange(2, 18), "in place, at an offset")
        }
    }

    @Test fun lbKeyThroughQuicCrypto() {
        val key = unhex("000102030405060708090a0b0c0d0e0f")
        KslQuicCrypto.newLoadBalancerKey(key).use { k ->
            val ct = ByteArray(16)
            k.encrypt(unhex("00112233445566778899aabbccddeeff"), 0, ct, 0)
            assertContentEquals(unhex("69c4e0d86a7b0430d8cdb78070b4c55a"), ct)
        }
        assertTrue(key.all { it == 0.toByte() }, "the provider wipes the caller's key bytes")
        KslQuicCrypto.newLoadBalancerKey(null).use { a ->
            KslQuicCrypto.newLoadBalancerKey(null).use { b ->
                val x = ByteArray(16)
                val y = ByteArray(16)
                a.encrypt(ByteArray(16), 0, x, 0)
                b.encrypt(ByteArray(16), 0, y, 0)
                assertFalse(x.contentEquals(y), "two random keys differ")
            }
        }
    }

    @Test fun lbKeyDerivedIsTheEncryptedLabel() {
        val label = ByteArray(16) { (0x40 + it).toByte() }
        KslLbKey.of(unhex("000102030405060708090a0b0c0d0e0f")).use { k ->
            val bytes = ByteArray(16)
            k.encrypt(label, bytes)
            k.derive(label).use { d ->
                KslLbKey.of(bytes).use { expect ->
                    val a = ByteArray(16)
                    val b = ByteArray(16)
                    d.encrypt(ByteArray(16), 0, a, 0)
                    expect.encrypt(ByteArray(16), b)
                    assertContentEquals(b, a)
                }
            }
        }
    }

    @Test fun negative_lbKeySourceArrayWiped() {
        val k = unhex("8f95f09245765f80256934e50c66207f")
        KslLbKey.of(k).close()
        assertTrue(k.all { it == 0.toByte() }, "the key bytes are wiped once copied into ksl")
        val short = ByteArray(15) { 1 }
        assertFailsWith<IllegalArgumentException> { KslLbKey.of(short) }
        assertTrue(short.all { it == 0.toByte() }, "a refused key is wiped too")
    }

    @Test fun negative_lbKeyClosedOrMisused() {
        val k = KslLbKey.of(ByteArray(16) { 3 })
        assertFailsWith<IndexOutOfBoundsException> { k.encrypt(ByteArray(16), 1, ByteArray(16), 0) }
        assertFailsWith<IndexOutOfBoundsException> { k.decrypt(ByteArray(16), 0, ByteArray(16), Int.MAX_VALUE - 8) }
        k.close()
        k.close()
        assertFailsWith<IllegalStateException> { k.encrypt(ByteArray(16), ByteArray(16)) }
    }
}

/** Pulls the DER SubjectPublicKeyInfo out of a certificate with the same minimal walker the library uses. */
internal object SpkiExtractor {
    fun spkiDer(cert: ByteArray): ByteArray {
        fun tlv(at: Int): Triple<Int, Int, Int> {
            var i =
                at + 1
            var len =
                cert[i++].toInt() and 0xff
            if (len and 0x80 !=
                0
            ) {
                val n =
                    len and 0x7f
                len = 0
                repeat(n) { len = (len shl 8) or (cert[i++].toInt() and 0xff) }
            }
            return Triple(cert[at].toInt() and 0xff, i, i + len)
        }
        val (_, tbsStart, _) = tlv(0)
        val (_, fStart, fEnd) = tlv(tbsStart)
        var at = fStart
        val fields = ArrayList<Triple<Int, Int, Int>>()
        while (at < fEnd) {
            val t = tlv(at)
            fields += Triple(t.first, at, t.third)
            at = t.third
        }
        var i = 0
        if (fields[i].first == 0xa0) i++
        i += 5 // serial, sigalg, issuer, validity, subject
        val spki = fields[i]
        return cert.copyOfRange(spki.second, spki.third)
    }
}
