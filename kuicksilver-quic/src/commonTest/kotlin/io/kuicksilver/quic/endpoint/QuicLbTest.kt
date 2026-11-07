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

    /** Each test starts with no nonce space of an earlier one (and frees their plaintext keys). */
    @kotlin.test.AfterTest fun forgetNonceSpaces() = QuicLbNonceSpaces.forgetForTest()

    private fun hex(s: String) = ByteArray(s.length / 2) { s.substring(2 * it, 2 * it + 2).toInt(16).toByte() }

    private fun hexOf(b: ByteArray) = b.joinToString("") { (it.toInt() and 0xff).toString(16).padStart(2, '0') }

    private fun <T> codec(
        configId: Int,
        sid: String,
        nonceLength: Int,
        key: String?,
        block: (QuicLbCodec) -> T,
    ): T {
        val k = key?.let { KslQuicCrypto.newLoadBalancerKey(hex(it)) }
        try {
            return block(
                QuicLbCodec(
                    QuicLbConfig(
                        configId,
                        hex(sid),
                        nonceLength,
                        k,
                        if (k ==
                            null
                        ) {
                            QuicLbFixtures.plainReservation
                        } else {
                            null
                        },
                    ),
                ),
            )
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
     * B.1, second line. The draft prints "1 350d28b420 3487d970b 20a350d28b4203487d970b": a nine-digit nonce, and a first octet
     * 0x20 whose config rotation bits are 1 as the line says but whose length bits are 0, not 10. That is what a generator
     * gives that drops leading zeros and prints the first octet as "2" (the codepoint) followed by "0a" (the length). With the
     * leading zeros restored the nonce is 03487d970b (five bytes, as the eleven-byte CID requires) and the CID is
     * 2a | 350d28b420 | 03487d970b: cr_bits 1, length 10.
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
    ) = QuicLbNonceSpace(length, seed, null, null, start)

    @Test fun nonceCounterNeverRepeats() {
        KslQuicCrypto.newLoadBalancerKey(null).use { k ->
            val seen = HashSet<String>()
            val n = nonces(4, seed = byteArrayOf(-1, -1, -1, -16)) // wraps past 2^32 within the run: still no repeat
            repeat(10_000) { assertTrue(seen.add(hexOf(assertNotNull(n.next(k)))), "nonce $it repeated") }
            codec(0, "ed793a", 4, b2Key) { c ->
                val cids = HashSet<String>()
                val m = nonces(4)
                repeat(10_000) {
                    val out = ByteArray(c.cidLength)
                    c.encode(assertNotNull(m.next(k)), out)
                    assertTrue(cids.add(hexOf(out)), "CID $it repeated")
                }
            }
        }
    }

    /** The counter is permuted with a local key: consecutive nonces show no relation (draft section 5.4: plaintext nonces). */
    @Test fun noncesArePermuted() {
        KslQuicCrypto.newLoadBalancerKey(null).use { k ->
            val n = nonces(6)
            val a = assertNotNull(n.next(k))
            val b = assertNotNull(n.next(k))
            assertFalse(a.contentEquals(ByteArray(6)), "not the counter")
            assertFalse(b.contentEquals(ByteArray(5) + byteArrayOf(1)), "not the counter")
        }
        val plain = nonces(4, seed = byteArrayOf(0, 0, 0, 9))
        assertContentEquals(byteArrayOf(0, 0, 0, 9), plain.next(null), "without a permutation the counter starts at its seed")
        assertContentEquals(byteArrayOf(0, 0, 0, 10), plain.next(null))
    }

    @Test fun nonceExhaustionReturnsNull() {
        val n = nonces(4, start = (1L shl 32) - 2, seed = byteArrayOf(-1, -1, -1, -1))
        assertContentEquals(byteArrayOf(-1, -1, -1, -3), n.next(null), "the last two values of the 2^32 space")
        assertContentEquals(byteArrayOf(-1, -1, -1, -2), n.next(null))
        assertNull(n.next(null), "the next one would be the seed again: exhausted")
        assertNull(n.next(null), "and stays exhausted")
        assertTrue(n.exhausted)
    }

    /** The nonce (decrypted) of an ID of [config]. */
    private fun nonceOf(
        config: QuicLbConfig,
        cid: ByteArray,
    ): String {
        val plain = cid.copyOfRange(1, cid.size)
        QuicLbCipher.decrypt(config.key!!, plain, 0, plain.size)
        return hexOf(plain.copyOfRange(config.serverIdLength, plain.size))
    }

    /**
     * Section 9.6 within a process: two endpoints that share a key, with two server IDs, draw from one nonce space: no nonce
     * of one is ever a nonce of the other.
     */
    @Test fun nonceSpaceSharedByKeyAcrossServerIdsAndEndpoints() {
        val keyBytes = "00112233445566778899aabbccddee01"
        KslQuicCrypto.newLoadBalancerKey(hex(keyBytes)).use { k1 ->
            KslQuicCrypto.newLoadBalancerKey(hex(keyBytes)).use { k2 ->
                val a = QuicLbConfig(1, hex("0a0b0c"), 4, k1)
                val b = QuicLbConfig(2, hex("0d0e0f"), 4, k2) // the same key through another handle
                val sa = QuicLbState(LbNullCrypto, kotlin.random.Random(1), a, 1, 8)
                val sb = QuicLbState(LbNullCrypto, kotlin.random.Random(2), b, 1, 8)
                try {
                    val ra = QuicLbRoute(sa, 0)
                    val rb = QuicLbRoute(sb, 0)
                    val na = HashSet<String>()
                    val nb = HashSet<String>()
                    repeat(2000) {
                        na += nonceOf(a, ra.newCid(kotlin.random.Random(it), client = false).toByteArray())
                        nb += nonceOf(b, rb.newCid(kotlin.random.Random(it), client = false).toByteArray())
                    }
                    assertEquals(2000, na.size)
                    assertTrue(na.intersect(nb).isEmpty(), "one key, one nonce space")
                } finally {
                    sa.close()
                    sb.close()
                }
            }
        }
    }

    private class MemoryReservation(
        private val secretBytes: ByteArray = ByteArray(16) { (it * 7 + 1).toByte() },
    ) : io.kuicksilver.quic.QuicLbNonceReservation {
        var mark = 0L
        val stores = ArrayList<Long>()
        var fail = false

        override fun load(): Long = mark

        override fun store(mark: Long) {
            stores += mark
            if (fail) throw kotlinx.io.IOException("disk full")
            this.mark = mark
        }

        override fun secret(): ByteArray = secretBytes.copyOf()
    }

    /** Section 9.6 across processes: with a reservation the nonce sequence is fixed and a new process starts past the stored mark. */
    @Test fun nonceReservationSurvivesARestart() {
        val keyBytes = "00112233445566778899aabbccddee02"
        val store = MemoryReservation()
        val seen = HashSet<String>()
        repeat(2) { process ->
            QuicLbNonceSpaces.forgetForTest() // a new process
            KslQuicCrypto.newLoadBalancerKey(hex(keyBytes)).use { k ->
                val c = QuicLbConfig(1, hex("0a0b0c"), 4, k, store)
                val s = QuicLbState(LbNullCrypto, kotlin.random.Random(process), c, 1, 8)
                try {
                    val r = QuicLbRoute(s, 0)
                    repeat(1000) { assertTrue(seen.add(nonceOf(c, r.newCid(kotlin.random.Random(it), client = false).toByteArray()))) }
                } finally {
                    s.close()
                }
            }
        }
        assertEquals(listOf(65_536L, 131_072L), store.stores, "one block reserved per process, before its first nonce")
    }

    /** A failed store: that request gets an unroutable ID marked temporary, reported apart from exhaustion. */
    @Test fun negative_reservationFailureGoesUnroutable() {
        val keyBytes = "00112233445566778899aabbccddee03"
        KslQuicCrypto.newLoadBalancerKey(hex(keyBytes)).use { k ->
            val failing = MemoryReservation().also { it.fail = true }
            val s = QuicLbState(LbNullCrypto, kotlin.random.Random(1), QuicLbConfig(1, hex("0a0b0c"), 4, k, failing), 1, 8)
            var failures = 0
            var exhausted = 0
            try {
                val r = QuicLbRoute(s, 0, onExhausted = { exhausted++ }, onStoreFailed = { failures++ })
                val i = r.issue(kotlin.random.Random(1), client = false)
                assertEquals(CidIssuance.SingleNoMigration, i.issuance, "no unreserved nonce is ever used")
                assertTrue(i.temporary, "this request only")
                assertEquals(1, failures)
                assertEquals(0, exhausted, "not exhaustion")
                assertFalse(
                    s.routes.current!!
                        .space.exhausted,
                )
            } finally {
                s.close()
            }
        }
    }

    /** A failed store is retried only after a back-off, not on every draw; once stored, nonces flow again. */

    /** A store outage draws nothing: the next try waits for a receive batch (ticks), 1 doubling, at most one per batch. */
    @Test fun reservationStoreBacksOff() {
        val r = MemoryReservation().also { it.fail = true }
        val space = QuicLbNonceSpace(4, ByteArray(4), null, r, 0)
        space.prime()
        assertEquals(1, r.stores.size, "the first block, failed")
        repeat(5) { assertNull(space.next(null)) }
        assertEquals(1, r.stores.size, "requests do not drive the store, batches do")
        assertEquals(0L, space.drawnForTest, "nothing drawn while nothing is reserved")
        space.tick()
        assertEquals(2, r.stores.size, "one try in the batch")
        space.tick()
        assertEquals(2, r.stores.size, "back-off: two batches now")
        r.fail = false
        space.tick()
        assertEquals(3, r.stores.size)
        assertEquals(0L, space.drawnForTest)
        assertNotNull(space.next(null), "stored")
        assertEquals(65_536L, r.stores.last(), "the block after an outage starts at the next draw, not past the stale mark")
    }

    /** The back-off doubles from one batch to 1,024 and stays there; a success resets it, so the next failure waits one batch. */
    @Test fun reservationBackOffDoublesThenHoldsThenResets() {
        val r = MemoryReservation().also { it.fail = true }
        val space = QuicLbNonceSpace(4, ByteArray(4), null, r, 0)
        space.prime() // attempt at tick 0
        val attempts = ArrayList<Int>()
        var tick = 0
        while (attempts.size < 12) {
            val before = r.stores.size
            space.tick()
            tick++
            if (r.stores.size > before) attempts += tick
        }
        val gaps = (listOf(0) + attempts).zipWithNext { a, b -> b - a }
        assertEquals(listOf(1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 1024), gaps)
        r.fail = false
        repeat(1024) { space.tick() }
        assertEquals(14, r.stores.size, "the store after the last 1,024-batch gap succeeds")
        assertNotNull(space.next(null))
        r.fail = true
        space.useUpReservationForTest()
        space.tick()
        assertEquals(15, r.stores.size, "a failure again")
        space.tick()
        assertEquals(16, r.stores.size, "and the gap is back to one batch")
    }

    /** A storm of requests during an outage: the store is tried at most once a batch, however many requests come. */
    @Test fun reservationStormTriesAtMostOnceABatch() {
        val r = MemoryReservation().also { it.fail = true }
        val space = QuicLbNonceSpace(4, ByteArray(4), null, r, 0)
        space.prime()
        val batches = 20
        repeat(batches) {
            repeat(5_000) { assertNull(space.next(null)) }
            space.tick()
        }
        assertTrue(r.stores.size <= batches + 1, "${r.stores.size} store tries for $batches batches of 5,000 requests")
        assertEquals(0L, space.drawnForTest)
    }

    /** A group's back-off is scaled by its loops: about one try a round of their batches. */
    @Test fun reservationBackOffScalesWithTheLoops() {
        val r = MemoryReservation().also { it.fail = true }
        val space = QuicLbNonceSpace(4, ByteArray(4), null, r, 0)
        space.prime() // tick 0, one loop's weight
        repeat(16) { space.tick(loops = 4) }
        assertTrue(r.stores.size <= 4, "about one try a round of four loops: ${r.stores.size}")
    }

    /** The first block is stored when the space is primed: no draw races a store at start. */
    @Test fun reservationStoredBeforeTheFirstDraw() {
        val r = MemoryReservation()
        val space = QuicLbNonceSpace(4, ByteArray(4), null, r, 0)
        space.prime()
        assertEquals(listOf(65_536L), r.stores)
        assertNotNull(space.next(null))
    }

    /** Section 9.6: an instance that lost the registry's insertion never stores, so the stored mark never goes down. */
    @Test fun reservationMarkNeverGoesDown() {
        val r = MemoryReservation()
        val winner = QuicLbNonceSpace(4, ByteArray(4), null, r, 0)
        winner.prime()
        repeat(40_000) { assertNotNull(winner.next(null)) } // past half a block: the next one is stored
        assertEquals(listOf(65_536L, 131_072L), r.stores)
        val loser = QuicLbNonceSpace(4, ByteArray(4), null, r, 0) // made late, dropped by the registry: never primed
        assertEquals(listOf(65_536L, 131_072L), r.stores, "the loser stored nothing")
        assertTrue(loser.reservation === r)
        for (i in 1 until r.stores.size) assertTrue(r.stores[i] > r.stores[i - 1], "monotonic: ${r.stores}")
        KslQuicCrypto.newLoadBalancerKey(hex("00112233445566778899aabbccddee05")).use { k ->
            val shared = MemoryReservation()
            val a = QuicLbNonceSpaces.of(QuicLbConfig(1, hex("0a0b0c"), 4, k, shared), k, LbNullCrypto, kotlin.random.Random(1))
            val b = QuicLbNonceSpaces.of(QuicLbConfig(2, hex("0a0b0d"), 4, k, shared), k, LbNullCrypto, kotlin.random.Random(2))
            assertTrue(a === b, "one space")
            assertEquals(listOf(65_536L), shared.stores, "stored once, by the winner")
        }
    }

    @Test fun negative_reservationMustMatchTheNonceSpace() {
        KslQuicCrypto.newLoadBalancerKey(hex("00112233445566778899aabbccddee04")).use { k ->
            val s = QuicLbState(LbNullCrypto, kotlin.random.Random(1), QuicLbConfig(1, hex("0a0b0c"), 4, k, MemoryReservation()), 1, 8)
            try {
                assertFailsWith<IllegalArgumentException>("no reservation where the space has one") {
                    QuicLbState(LbNullCrypto, kotlin.random.Random(2), QuicLbConfig(2, hex("0a0b0d"), 4, k), 1, 8)
                }
                assertFailsWith<IllegalArgumentException>("another reservation") {
                    s.update(QuicLbConfig(3, hex("0a0b0c"), 4, k, MemoryReservation()))
                }
            } finally {
                s.close()
            }
        }
    }

    /** Section 9.6 in clear across processes: the stored secret keys the permutation, the mark moves the counter on. */
    @Test fun plaintextReservationSurvivesARestart() {
        val store = MemoryReservation()
        val seen = HashSet<String>()
        var sequential = 0
        var previous = -1L
        repeat(2) { process ->
            QuicLbNonceSpaces.forgetForTest() // a new process
            val c = QuicLbConfig(1, hex("0a0b0c"), 6, null, store)
            val s = QuicLbState(LbNullCrypto, kotlin.random.Random(process), c, 1, 10)
            try {
                val r = QuicLbRoute(s, 0)
                repeat(1000) {
                    val n = hexOf(r.newCid(kotlin.random.Random(it), client = false).toByteArray().copyOfRange(4, 10))
                    assertTrue(seen.add(n), "nonce $n repeated")
                    if (n.toLong(16) == previous + 1) sequential++
                    previous = n.toLong(16)
                }
            } finally {
                s.close()
            }
        }
        QuicLbNonceSpaces.forgetForTest()
        assertTrue(sequential < 5, "permuted, not the counter: $sequential sequential pairs")
        assertEquals(listOf(65_536L, 131_072L), store.stores)
    }

    @Test fun negative_configIdSevenRejected() {
        assertFailsWith<IllegalArgumentException> { QuicLbConfig(7, byteArrayOf(1), 4, null, QuicLbFixtures.plainReservation) }
        assertFailsWith<IllegalArgumentException> { QuicLbConfig(-1, byteArrayOf(1), 4, null, QuicLbFixtures.plainReservation) }
        QuicLbConfig(6, byteArrayOf(1), 4, null, QuicLbFixtures.plainReservation)
    }

    @Test fun negative_sidPlusNonceOver19Rejected() {
        assertFailsWith<IllegalArgumentException> { QuicLbConfig(0, ByteArray(15), 5, null, QuicLbFixtures.plainReservation) }
        assertFailsWith<IllegalArgumentException> { QuicLbConfig(0, ByteArray(1), 19, null, QuicLbFixtures.plainReservation) }
        assertFailsWith<IllegalArgumentException> { QuicLbConfig(0, ByteArray(0), 8, null, QuicLbFixtures.plainReservation) }
        assertEquals(20, QuicLbConfig(0, ByteArray(15), 4, null, QuicLbFixtures.plainReservation).connectionIdLength)
    }

    /** Section 9.6 in clear: without a stored counter a restart could repeat nonces, so a plaintext configuration needs one. */
    @Test fun negative_plaintextWithoutReservationRejected() {
        assertFailsWith<IllegalArgumentException> { QuicLbConfig(0, ByteArray(3), 4, null) }
    }

    @Test fun negative_nonceUnder4Rejected() {
        assertFailsWith<IllegalArgumentException> { QuicLbConfig(0, ByteArray(3), 3, null, QuicLbFixtures.plainReservation) }
    }

    @Test fun negative_configNeverPrintsTheKey() {
        KslQuicCrypto.newLoadBalancerKey(hex(b2Key)).use { k ->
            val c = QuicLbConfig(1, hex("ed793a"), 4, k)
            assertFalse(c.toString().contains("8f95"), c.toString())
            assertFalse(c.toString().contains("ed793a"), c.toString())
            assertFalse(assertNotNull(c.keyFingerprint).contains("8f95f092"), "the fingerprint is not the key")
        }
    }
}
