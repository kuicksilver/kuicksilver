// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(DelicateKuicksilverApi::class, io.kuicksilver.annotations.InternalKuicksilverApi::class)

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
        runBlocking { SessionCache.clear() }
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

    @Test fun randomNotRepeating() {
        assertFalse(KslCrypto.randomBytes(32).contentEquals(KslCrypto.randomBytes(32)))
        assertEquals(0, KslCrypto.randomBytes(0).size)
    }

    @Test fun spkiMatchesCli() {
        assertContentEquals(TestCerts.serverSpkiSha256, KslCrypto.spkiSha256(TestCerts.server).bytes)
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
