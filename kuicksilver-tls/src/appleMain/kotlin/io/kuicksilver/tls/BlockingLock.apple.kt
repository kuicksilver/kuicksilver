// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(kotlinx.cinterop.ExperimentalForeignApi::class, kotlin.experimental.ExperimentalNativeApi::class)

package io.kuicksilver.tls

import kotlinx.cinterop.alloc
import kotlinx.cinterop.nativeHeap
import kotlinx.cinterop.ptr
import platform.posix.pthread_mutex_destroy
import platform.posix.pthread_mutex_init
import platform.posix.pthread_mutex_lock
import platform.posix.pthread_mutex_t
import platform.posix.pthread_mutex_unlock
import kotlin.native.ref.createCleaner

/** A pthread mutex in native memory, destroyed and freed with the object. */
internal actual class BlockingLock actual constructor() {
    private val mutex = nativeHeap.alloc<pthread_mutex_t>().also { pthread_mutex_init(it.ptr, null) }

    @Suppress("unused") // frees the mutex once the lock is unreachable
    private val cleaner =
        createCleaner(mutex) {
            pthread_mutex_destroy(it.ptr)
            nativeHeap.free(it.rawPtr)
        }

    actual fun lock() {
        pthread_mutex_lock(mutex.ptr)
    }

    actual fun unlock() {
        pthread_mutex_unlock(mutex.ptr)
    }
}
