// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic

import io.kuicksilver.native.KslLoader
import io.kuicksilver.native.PacketBuffer
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

/** A batch whose slots cannot all be allocated frees the ones it had: native memory on Kotlin/Native. */
class PacketBatchAllocationTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    @Test fun aFailedSlotAllocationFreesTheSlotsMadeBeforeIt() {
        val made = ArrayList<PacketBuffer>()
        val e =
            assertFailsWith<IllegalStateException> {
                PacketBatch(4, 64) { size ->
                    if (made.size == 2) throw IllegalStateException("out of native memory (test)")
                    PacketBuffer.allocate(size).also { made += it }
                }
            }
        assertEquals("out of native memory (test)", e.message)
        assertEquals(2, made.size)
        for (b in made) assertFailsWith<IllegalStateException>("a slot made before the failure is closed") { b[0] }
    }

    @Test fun closeFreesEverySlot() {
        val made = ArrayList<PacketBuffer>()
        PacketBatch(3, 64) { size -> PacketBuffer.allocate(size).also { made += it } }.close()
        assertEquals(3, made.size)
        for (b in made) assertFailsWith<IllegalStateException> { b[0] }
    }
}
