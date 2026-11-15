// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.native

import io.kuicksilver.annotations.InternalKuicksilverApi

/**
 * The [PacketBuffer]s allocated on the calling thread and not closed yet, less those closed on it that another thread
 * allocated: a leak check for code that allocates and frees on one thread (a sans-IO test reads it before and after).
 * Counted per thread, so what other threads do meanwhile never shows here.
 */
@InternalKuicksilverApi
public fun packetBuffersOpenOnThisThread(): Long = packetBuffersOpenHere()

internal expect fun packetBuffersOpenHere(): Long

/** [PacketBuffer.allocate] (+1) and the first [PacketBuffer.close] (-1) on the calling thread. */
internal expect fun countPacketBuffer(delta: Int)
