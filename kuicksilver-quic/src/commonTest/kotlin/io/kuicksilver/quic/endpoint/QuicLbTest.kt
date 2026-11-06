// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(ExperimentalKuicksilverApi::class)

package io.kuicksilver.quic.endpoint

import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.native.KslLoader
import io.kuicksilver.native.PacketBuffer
import io.kuicksilver.native.of
import io.kuicksilver.quic.QuicLbConfig
import io.kuicksilver.tls.KslQuicCrypto
import io.kuicksilver.tls.LoadBalancerKey
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** The QUIC-LB connection ID codec against draft-ietf-quic-load-balancers-21 (section 5.4.2.4 and Appendix B). */
class QuicLbTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    private fun hex(s: String) = ByteArray(s.length / 2) { s.substring(2 * it, 2 * it + 2).toInt(16).toByte() }

    private fun hexOf(b: ByteArray) = b.joinToString("") { (it.toInt() and 0xff).toString(16).padStart(2, '0') }

    private fun <T> codec(
        configId: Int,
        sid: String,
        nonceLength: Int,
        key: String?,
        block: (QuicLbCodec) -> T,
    ): T {
        val config = QuicLbConfig(configId, hex(sid), nonceLength, key?.let { hex(it) })
        val k = key?.let { KslQuicCrypto.newLoadBalancerKey(hex(it)) }
        try {
            return block(QuicLbCodec(config, k))
        } finally {
            k?.close()
        }
    }

    /** Encodes (cr_bits, sid, nonce) and checks the CID and that the server ID decodes back from it. */
    private fun vector(
        cr: Int,
        sid: String,
        nonce: String,
        cid: String,
        key: String?,
    ) = codec(cr, sid, nonce.length / 2, key) { c ->
        val out = ByteArray(c.cidLength)
        c.encode(hex(nonce), out)
        assertEquals(cid, hexOf(out), "cr $cr sid $sid nonce $nonce")
        assertEquals(sid, hexOf(assertNotNull(c.decodeServerId(out, 0))), "server ID decoded from $cid")
        val buf = PacketBuffer.of(byteArrayOf(0x40) + out)
        try {
            assertTrue(c.matchesServerId(buf, 1), "the server ID matches in a packet buffer")
        } finally {
            buf.close()
        }
    }

    private val b2Key = "8f95f09245765f80256934e50c66207f"

    /** B.1, first line, as printed: "0 c4605e 4504cc4f 07c4605e4504cc4f". */
    @Test fun plaintextVector1() = vector(0, "c4605e", "4504cc4f", "07c4605e4504cc4f", null)

    /**
     * B.1, second line. The draft prints "1 350d28b420 3487d970b 20a350d28b4203487d970b": a nine-digit nonce and a first octet
     * that cannot be cr_bits 1 (0b001xxxxx) are what a generator gives that drops leading zeros and prints the first octet as
     * "2" (the config ID, shifted) followed by "0a" (the length). Read with the leading zeros, the nonce is 03487d970b (five
     * bytes, as the eleven-byte CID requires) and the CID is 2a | 350d28b420 | 03487d970b: cr_bits 1, length 10.
     */
    @Test fun plaintextVector2() = vector(1, "350d28b420", "03487d970b", "2a350d28b42003487d970b", null)

    /** B.2: "0 ed793a ee080dbf 0720b1d07b359d3c" (four-pass, seven bytes: odd). */
    @Test fun encryptedVector1() = vector(0, "ed793a", "ee080dbf", "0720b1d07b359d3c", b2Key)

    /** B.2: "1 ed793a51d49b8f5fab65 ee080dbf48 2fcc381bc74cb4fbad2823a3d1f8fed2" (four-pass, the server ID longer than the nonce). */
    @Test fun encryptedVector2() = vector(1, "ed793a51d49b8f5fab65", "ee080dbf48", "2fcc381bc74cb4fbad2823a3d1f8fed2", b2Key)

    /** B.2: "2 ed793a51d49b8f5f ee080dbf48c0d1e5 504dd2d05a7b0de9b2b9907afb5ecf8cc3" (single pass: 16 bytes). */
    @Test fun encryptedVector3() = vector(2, "ed793a51d49b8f5f", "ee080dbf48c0d1e5", "504dd2d05a7b0de9b2b9907afb5ecf8cc3", b2Key)

    /**
     * B.2: "3 ed793a51d49b8f5fab ee080dbf48c0d1e55d 125779c9cc86beb3a3a4a3ca96fce4bfe0cdbc". The first octet 0x12 is
     * cr_bits 0 and length 18, not cr_bits 3; the config rotation bits are not part of the encryption, so the vector is
     * checked with configuration 0, which reproduces the CID byte for byte.
     */
    @Test fun encryptedVector4() = vector(0, "ed793a51d49b8f5fab", "ee080dbf48c0d1e55d", "125779c9cc86beb3a3a4a3ca96fce4bfe0cdbc", b2Key)

    /** Section 5.4.2.4, the worked four-pass example: cid = 0x0767947d29be054a. */
    @Test fun encryptionExample() = vector(0, "31441a", "9c69c275", "0767947d29be054a", "fdf726a9893ec05c0632d3956680baf0")

    /** Section 5.4.2.4, step 3: expand(7, 1, left_0) under the example key gives the printed AES output. */
    @Test fun expandMatchesExample() {
        val block = ByteArray(16)
        QuicLbCipher.expand(7, 1, hex("31441a90"), 4, block)
        assertEquals("31441a90000000000000000000000701", hexOf(block))
        // section 5.4.2.2: expand(0x06, 0x02, 0xaaba3c) = 0xaaba3c00000000000000000000000602
        QuicLbCipher.expand(6, 2, hex("aaba3c"), 3, block)
        assertEquals("aaba3c00000000000000000000000602", hexOf(block))
        KslQuicCrypto.newLoadBalancerKey(hex("fdf726a9893ec05c0632d3956680baf0")).use { k ->
            QuicLbCipher.expand(7, 1, hex("31441a90"), 4, block)
            k.encrypt(block, 0, block, 0)
            assertEquals("a255dd8cdacf01948d3a848c3c7fee23", hexOf(block))
        }
    }

    @Test fun decodeRejectsOtherConfigOrLength() =
        codec(0, "ed793a", 4, b2Key) { c ->
            val out = ByteArray(c.cidLength)
            c.encode(hex("ee080dbf"), out)
            val other = out.copyOf().also { it[0] = (0x20 or 7).toByte() }
            assertNull(c.decodeServerId(other, 0), "another config rotation codepoint")
            val badLength = out.copyOf().also { it[0] = 6 }
            assertNull(c.decodeServerId(badLength, 0), "a self-encoded length that is not ours")
        }

    /** Every pass is a permutation: odd and even lengths from 5 to 19 decode back to the plaintext (four-pass and single-pass). */
    @Test fun everyLengthRoundTrips() {
        KslQuicCrypto.newLoadBalancerKey(null).use { k ->
            for (len in 4..19) {
                val r = kotlin.random.Random(len)
                repeat(50) {
                    val p = ByteArray(len).also { r.nextBytes(it) }
                    val c = p.copyOf()
                    QuicLbCipher.encrypt(k, c, 0, len)
                    if (len != 16) assertFalse(c.contentEquals(p), "length $len: encrypted")
                    QuicLbCipher.decrypt(k, c, 0, len)
                    assertContentEquals(p, c, "length $len")
                }
            }
        }
    }

    private fun nonces(
        length: Int,
        start: Long = 0,
        seed: ByteArray = ByteArray(length),
        key: LoadBalancerKey? = null,
    ) = QuicLbNonces(length, seed, key, start)

    @Test fun nonceCounterNeverRepeats() {
        KslQuicCrypto.newLoadBalancerKey(null).use { k ->
            val seen = HashSet<String>()
            val n = nonces(4, seed = byteArrayOf(-1, -1, -1, -16), key = k) // wraps past 2^32 within the run: still no repeat
            repeat(10_000) { assertTrue(seen.add(hexOf(assertNotNull(n.next()))), "nonce $it repeated") }
            codec(0, "ed793a", 4, b2Key) { c ->
                val cids = HashSet<String>()
                val m = nonces(4, key = k)
                repeat(10_000) {
                    val out = ByteArray(c.cidLength)
                    c.encode(assertNotNull(m.next()), out)
                    assertTrue(cids.add(hexOf(out)), "CID $it repeated")
                }
            }
        }
    }

    /** The counter is permuted with a local key: consecutive nonces show no relation (draft section 5.4: plaintext nonces). */
    @Test fun noncesArePermuted() {
        KslQuicCrypto.newLoadBalancerKey(null).use { k ->
            val n = nonces(6, key = k)
            val a = assertNotNull(n.next())
            val b = assertNotNull(n.next())
            assertFalse(a.contentEquals(ByteArray(6)), "not the counter")
            assertFalse(b.contentEquals(ByteArray(5) + byteArrayOf(1)), "not the counter")
        }
        val plain = nonces(4, seed = byteArrayOf(0, 0, 0, 9))
        assertContentEquals(byteArrayOf(0, 0, 0, 9), plain.next(), "without a key the counter starts at its seed")
        assertContentEquals(byteArrayOf(0, 0, 0, 10), plain.next())
    }

    @Test fun nonceExhaustionReturnsNull() {
        val n = nonces(4, start = (1L shl 32) - 2, seed = byteArrayOf(-1, -1, -1, -1))
        assertContentEquals(byteArrayOf(-1, -1, -1, -3), n.next(), "the last two values of the 2^32 space")
        assertContentEquals(byteArrayOf(-1, -1, -1, -2), n.next())
        assertNull(n.next(), "the next one would be the seed again: exhausted")
        assertNull(n.next(), "and stays exhausted")
        assertTrue(n.exhausted)
    }

    @Test fun negative_configIdSevenRejected() {
        assertFailsWith<IllegalArgumentException> { QuicLbConfig(7, byteArrayOf(1), 4, null) }
        assertFailsWith<IllegalArgumentException> { QuicLbConfig(-1, byteArrayOf(1), 4, null) }
        QuicLbConfig(6, byteArrayOf(1), 4, null)
    }

    @Test fun negative_sidPlusNonceOver19Rejected() {
        assertFailsWith<IllegalArgumentException> { QuicLbConfig(0, ByteArray(15), 5, null) }
        assertFailsWith<IllegalArgumentException> { QuicLbConfig(0, ByteArray(1), 19, null) }
        assertFailsWith<IllegalArgumentException> { QuicLbConfig(0, ByteArray(0), 8, null) }
        assertEquals(20, QuicLbConfig(0, ByteArray(15), 4, null).connectionIdLength)
    }

    @Test fun negative_nonceUnder4Rejected() {
        assertFailsWith<IllegalArgumentException> { QuicLbConfig(0, ByteArray(3), 3, null) }
        assertFailsWith<IllegalArgumentException> { QuicLbConfig(0, ByteArray(3), 4, ByteArray(15)) }
    }

    @Test fun negative_configNeverPrintsTheKey() {
        val c = QuicLbConfig(1, hex("ed793a"), 4, hex(b2Key))
        assertFalse(c.toString().contains("8f95"), c.toString())
        assertFalse(c.toString().contains("ed793a"), c.toString())
    }
}
