// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(kotlinx.cinterop.ExperimentalForeignApi::class)

package io.kuicksilver.ktor.server

import kotlinx.cinterop.Arena
import kotlinx.cinterop.alloc
import kotlinx.cinterop.ptr
import platform.posix.pthread_cond_broadcast
import platform.posix.pthread_cond_init
import platform.posix.pthread_cond_tVar
import platform.posix.pthread_cond_wait
import platform.posix.pthread_mutex_init
import platform.posix.pthread_mutex_lock
import platform.posix.pthread_mutex_tVar
import platform.posix.pthread_mutex_unlock
import kotlin.concurrent.Volatile
import kotlin.time.Duration
import kotlin.time.TimeSource

/** A mutex and a condition variable; never freed while a test may wait (one per use, a few bytes). */
internal actual class ThreadLatch actual constructor() {
    private val arena = Arena()
    private val mutex = arena.alloc<pthread_mutex_tVar>().also { pthread_mutex_init(it.ptr, null) }
    private val cond = arena.alloc<pthread_cond_tVar>().also { pthread_cond_init(it.ptr, null) }

    @Volatile private var opened = false

    actual fun open() {
        pthread_mutex_lock(mutex.ptr)
        opened = true
        pthread_cond_broadcast(cond.ptr)
        pthread_mutex_unlock(mutex.ptr)
    }

    actual fun await(timeout: Duration): Boolean {
        val start = TimeSource.Monotonic.markNow()
        pthread_mutex_lock(mutex.ptr)
        try {
            // an untimed wait: [open] always comes in these tests, the bound is checked between wake-ups
            while (!opened && start.elapsedNow() < timeout) pthread_cond_wait(cond.ptr, mutex.ptr)
            return opened
        } finally {
            pthread_mutex_unlock(mutex.ptr)
        }
    }
}
