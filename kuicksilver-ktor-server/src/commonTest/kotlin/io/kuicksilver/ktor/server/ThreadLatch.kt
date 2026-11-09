// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.server

import kotlin.time.Duration

/**
 * A latch that blocks the calling thread itself, not a coroutine: a coroutine that waits on it keeps its thread, and so
 * every task queued behind it in that thread's event loop, until [open] (tests that hold an unconfined event loop).
 */
internal expect class ThreadLatch() {
    /** Releases every [await], now and later. */
    fun open()

    /** Blocks until [open], for [timeout] at most; true when it was opened. */
    fun await(timeout: Duration): Boolean
}
