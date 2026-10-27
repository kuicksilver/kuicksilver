// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.http3

import kotlin.random.Random
import kotlin.random.nextInt
import kotlin.random.nextLong

/**
 * Runs [block] [iterations] times on one [Random] seeded with [seed]; a failure is rethrown with its iteration and the seed,
 * and running the test again draws the same values. Used instead of Kotest's property engine: Android 7.0's ART (API 24)
 * aborted the instrumentation process in its garbage collector on Kotest's proptest frames ("Found invalid root"), a
 * runtime bug no change to a test could avoid. (A copy of kuicksilver-quic's test helper: test sources are not shared.)
 */
internal inline fun forAllSeeded(
    iterations: Int,
    seed: Long,
    block: (rnd: Random, i: Int) -> Unit,
) {
    val rnd = Random(seed)
    for (i in 0 until iterations) {
        try {
            block(rnd, i)
        } catch (e: Throwable) {
            throw AssertionError("iteration $i of $iterations, seed $seed: ${e.message}", e)
        }
    }
}

/** Kotest's edge cases of a range: its ends, and -1, 0 and 1 where they fall inside it. */
internal fun LongRange.edges(): List<Long> = listOf(first, -1L, 0L, 1L, last).filter { it in this }.distinct()

internal fun IntRange.edges(): List<Int> = listOf(first, -1, 0, 1, last).filter { it in this }.distinct()

/** A value of [range]: one draw in 50 is one of its [edges] (as Kotest's default edge-case share), the rest are uniform. */
internal fun Random.long(range: LongRange = Long.MIN_VALUE..Long.MAX_VALUE): Long =
    if (nextInt(50) == 0) range.edges().random(this) else nextLong(range)

internal fun Random.int(range: IntRange = Int.MIN_VALUE..Int.MAX_VALUE): Int =
    if (nextInt(50) == 0) range.edges().random(this) else nextInt(range)

internal fun Random.byte(): Byte = int(Byte.MIN_VALUE..Byte.MAX_VALUE).toByte()

/** [sizes] bytes, each with [byte]'s edge cases. */
internal fun Random.bytes(sizes: IntRange): List<Byte> = List(int(sizes)) { byte() }
