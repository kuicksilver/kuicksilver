// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.endpoint

import io.kuicksilver.native.KslLoader
import io.kuicksilver.native.PacketBuffer
import io.kuicksilver.native.of
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlin.random.Random
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals

/** [ResetTokenIndex]: the loop of a group whose connection holds a peer's reset token. */
class ResetTokenIndexTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    private fun token(i: Int) = ByteArray(16).also { Random(i + 1).nextBytes(it) }

    private fun resetEndingWith(
        t: ByteArray,
        size: Int = 40,
    ): ByteArray =
        ByteArray(size) { 0x55 }.also {
            it[0] = 0x40
            t.copyInto(it, size - 16)
        }

    private fun ResetTokenIndex.loopOf(bytes: ByteArray): Int = PacketBuffer.of(bytes).use { loopOf(it, bytes.size) }

    @Test fun tokensNameTheirLoopUntilRemoved() {
        val x = ResetTokenIndex(Random(1))
        for (i in 0 until 1000) x.add(token(i), i % 4) // past the first table: rehashed on the way
        assertEquals(1000, x.size)
        for (i in 0 until 1000) assertEquals(i % 4, x.loopOf(resetEndingWith(token(i))), "token $i")
        for (i in 0 until 1000 step 2) x.remove(token(i), i % 4)
        assertEquals(500, x.size)
        for (i in 0 until 1000) assertEquals(if (i % 2 == 0) -1 else i % 4, x.loopOf(resetEndingWith(token(i))), "token $i")
    }

    /** A token two IDs carry stays until both are gone. */
    @Test fun aTokenHeldTwiceStaysUntilBothLeave() {
        val x = ResetTokenIndex(Random(2))
        x.add(token(7), 2)
        x.add(token(7), 2)
        x.remove(token(7), 2)
        assertEquals(2, x.loopOf(resetEndingWith(token(7))))
        x.remove(token(7), 2)
        assertEquals(-1, x.loopOf(resetEndingWith(token(7))))
    }

    /**
     * A token connections on two loops hold (a peer repeating one): when the latest holder leaves, the route follows the loop
     * that still holds it, not the one that left; and the other way round.
     */
    @Test fun aSurvivingHolderKeepsTheRoute() {
        val x = ResetTokenIndex(Random(4))
        x.add(token(9), 1)
        x.add(token(9), 2)
        x.remove(token(9), 2)
        assertEquals(1, x.loopOf(resetEndingWith(token(9))))
        x.add(token(9), 3)
        x.remove(token(9), 1)
        assertEquals(3, x.loopOf(resetEndingWith(token(9))))
        x.remove(token(9), 0) // a loop that never held it changes nothing
        assertEquals(3, x.loopOf(resetEndingWith(token(9))))
        x.remove(token(9), 3)
        assertEquals(-1, x.loopOf(resetEndingWith(token(9))))
        assertEquals(0, x.size)
    }

    /** Loops adding and removing their tokens on their threads while a reader looks them up: every token kept is found. */
    @Test fun concurrentChangesKeepEveryToken() =
        kotlinx.coroutines.runBlocking {
            val x = ResetTokenIndex(Random(5))
            val jobs =
                (0 until 4).map { loop ->
                    launch(Dispatchers.Default) {
                        for (i in 0 until 2000) {
                            val t = token(loop * 10_000 + i)
                            x.add(t, loop)
                            if (i % 2 == 1) x.remove(t, loop)
                        }
                    }
                }
            jobs.forEach { it.join() }
            assertEquals(4 * 1000, x.size)
            for (loop in 0 until 4) {
                for (i in 0 until 2000) {
                    assertEquals(if (i % 2 == 0) loop else -1, x.loopOf(resetEndingWith(token(loop * 10_000 + i))), "loop $loop token $i")
                }
            }
        }

    /** Shorter than a reset can be (RFC 9000 section 10.3: 21 bytes), an all-zero token, an unknown token: no loop. */
    @Test fun negative_shortZeroOrUnknownNamesNoLoop() {
        val x = ResetTokenIndex(Random(3))
        x.add(token(1), 3)
        x.add(ByteArray(16), 1)
        assertEquals(1, x.size, "a zero token is never kept")
        assertEquals(-1, x.loopOf(resetEndingWith(token(1)).copyOfRange(20, 40)), "20 bytes")
        assertEquals(3, x.loopOf(resetEndingWith(token(1), size = 21)))
        assertEquals(-1, x.loopOf(resetEndingWith(ByteArray(16))))
        assertEquals(-1, x.loopOf(resetEndingWith(token(2))))
    }
}
