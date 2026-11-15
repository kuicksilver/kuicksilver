// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.native

private val openHere = ThreadLocal<LongArray>()

/** This thread's count (Android declares ThreadLocal.get nullable: the array is made on the thread's first use). */
private fun here(): LongArray = openHere.get() ?: LongArray(1).also { openHere.set(it) }

internal actual fun packetBuffersOpenHere(): Long = here()[0]

internal actual fun countPacketBuffer(delta: Int) {
    here()[0] += delta
}
