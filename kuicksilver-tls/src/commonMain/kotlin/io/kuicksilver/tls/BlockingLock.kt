// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.tls

/**
 * A lock that blocks the calling thread (not a coroutine one): for a short critical section in code that cannot suspend, a
 * thread that finds it held waits in the operating system instead of spinning. Not reentrant.
 */
internal expect class BlockingLock() {
    fun lock()

    fun unlock()
}

/** Runs [block] holding the lock. */
internal inline fun <T> BlockingLock.withLock(block: () -> T): T {
    lock()
    try {
        return block()
    } finally {
        unlock()
    }
}
