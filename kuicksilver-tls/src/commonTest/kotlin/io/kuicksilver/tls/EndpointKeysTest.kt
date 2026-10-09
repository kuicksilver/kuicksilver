// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.tls

import io.kuicksilver.native.KslLoader
import io.kuicksilver.native.PacketBuffer
import io.kuicksilver.native.of
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull

/** Retry-token and stateless-reset keys live inside ksl (ADR-0003). */
class EndpointKeysTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    private val aad = byteArrayOf(1, 10, 0, 0, 1, 0x1f, 0x90.toByte())

    @Test fun tokenRoundTrip() {
        KslQuicCrypto.newTokenKey().use { k ->
            val sealed = k.seal(nonce = 42L, aad = aad, plaintext = "hello".encodeToByteArray())
            assertEquals(5 + 16, sealed.size)
            assertContentEquals("hello".encodeToByteArray(), k.open(42L, aad, sealed))
        }
    }

    @Test fun tokenTamperedReturnsNull() {
        KslQuicCrypto.newTokenKey().use { k ->
            val sealed = k.seal(1L, aad, ByteArray(20) { it.toByte() })
            val flipped = sealed.copyOf().also { it[3] = (it[3].toInt() xor 1).toByte() }
            assertNull(k.open(1L, aad, flipped))
            assertNull(k.open(2L, aad, sealed), "another nonce")
            assertNull(k.open(1L, aad.copyOf().also { it[0] = 9 }, sealed), "another AAD")
            KslQuicCrypto.newTokenKey().use { other -> assertNull(other.open(1L, aad, sealed), "another key") }
        }
    }

    @Test fun resetTokenDeterministicPerKey() {
        KslQuicCrypto.newResetKey().use { k ->
            val cid = PacketBuffer.of(ByteArray(8) { (it + 1).toByte() })
            try {
                val a = ByteArray(16)
                val b = ByteArray(16)
                k.token(cid, 0, 8, a, 0)
                k.token(cid, 0, 8, b, 0)
                assertContentEquals(a, b)
                assertFalse(a.all { it == 0.toByte() })
            } finally {
                cid.close()
            }
        }
    }

    @Test fun resetTokenDiffersAcrossKeys() {
        KslQuicCrypto.newResetKey().use { k1 ->
            KslQuicCrypto.newResetKey().use { k2 ->
                val cid = PacketBuffer.of(ByteArray(8) { 7 })
                try {
                    val a = ByteArray(20)
                    val b = ByteArray(20)
                    k1.token(cid, 0, 8, a, 4)
                    k2.token(cid, 0, 8, b, 4)
                    assertFalse(a.contentEquals(b))
                    assertEquals(0, a[0].toInt())
                    assertEquals(0, a[3].toInt()) // written at the offset only
                } finally {
                    cid.close()
                }
            }
        }
    }
}
