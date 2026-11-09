// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(kotlinx.cinterop.ExperimentalForeignApi::class)

package io.kuicksilver.ktor.server

import kotlinx.cinterop.Arena
import kotlinx.cinterop.alloc
import kotlinx.cinterop.convert
import kotlinx.cinterop.memScoped
import kotlinx.cinterop.ptr
import platform.posix.CLOCK_REALTIME
import platform.posix.clock_gettime
import platform.posix.pthread_cond_broadcast
import platform.posix.pthread_cond_init
import platform.posix.pthread_cond_t
import platform.posix.pthread_cond_timedwait
import platform.posix.pthread_mutex_init
import platform.posix.pthread_mutex_lock
import platform.posix.pthread_mutex_t
import platform.posix.pthread_mutex_unlock
import platform.posix.timespec
import kotlin.concurrent.Volatile
import kotlin.time.Duration
import kotlin.time.TimeSource

/** A mutex and a condition variable; never freed while a test may wait (one per use, a few bytes). */
internal actual class ThreadLatch actual constructor() {
    private val arena = Arena()
    private val mutex = arena.alloc<pthread_mutex_t>().also { pthread_mutex_init(it.ptr, null) }
    private val cond = arena.alloc<pthread_cond_t>().also { pthread_cond_init(it.ptr, null) }

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
            memScoped {
                // pthread_cond_timedwait takes an absolute CLOCK_REALTIME deadline; the loop also covers spurious wake-ups
                val deadline = alloc<timespec>()
                clock_gettime(CLOCK_REALTIME.convert(), deadline.ptr)
                val nanos = deadline.tv_nsec + timeout.inWholeNanoseconds % 1_000_000_000L
                deadline.tv_sec = (deadline.tv_sec + timeout.inWholeSeconds + nanos / 1_000_000_000L).convert()
                deadline.tv_nsec = (nanos % 1_000_000_000L).convert()
                while (!opened && start.elapsedNow() < timeout) pthread_cond_timedwait(cond.ptr, mutex.ptr, deadline.ptr)
            }
            return opened
        } finally {
            pthread_mutex_unlock(mutex.ptr)
        }
    }
}
